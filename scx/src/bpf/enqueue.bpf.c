// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task cannot move to another CPU. */
static __always_inline bool flow_task_pinned(
	const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
/* Insert one task with bounded LIFO at K 3 into one queue. */
/* Pinned tasks rest in the overflow tail with no per CPU use. */
/* Migratable tasks keep the per CPU queue with no fallback scan. */
static __always_inline u64 flow_slot_insert(
	struct task_struct *p, s32 cpu, u64 slice, bool pinned)
{
	u64 sdsq;
	bool to_over = pinned;
	u32 lidx;
	u32 seq;
	bool head;
	u64 hflag = 0;
	if (cpu < 0 || !flow_cpu_live((u32)cpu))
		to_over = true;
	if (to_over)
		sdsq = flow_slot_overflow_dsq();
	else
		sdsq = flow_slot_cpu_dsq((u32)cpu);
	/* One atomic add claims one period slot with no scan. */
	if (to_over)
		lidx = flow_lifo_idx(true, 0);
	else
		lidx = flow_lifo_idx(false, (u32)cpu);
	seq = __sync_fetch_and_add(&flow_lifo_seq[lidx], 1);
	head = flow_lifo_take_head(seq);
	if (head)
		hflag = (u64)SCX_ENQ_HEAD;
	scx_bpf_dsq_insert(p, sdsq, slice, hflag);
	if (hflag != 0)
		__sync_fetch_and_add(&flow_stats.lifo_heads, 1);
	else
		__sync_fetch_and_add(&flow_stats.lifo_bound_hits, 1);
	return sdsq;
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	u64 slice = (u64)FLOW_SLICE_NS;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    slice, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst && tst->running_pid == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	if (enq_flags & SCX_ENQ_REENQ)
		__sync_fetch_and_add(&flow_stats.requeues, 1);
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	/* Tasks without state keep the overflow tail with no kick. */
	/* The next dispatch pass collects them with mask wins. */
	if (!tctx) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_slot_insert(p, -1, slice, pinned);
		return;
	}
	/* Pinned tasks stay on the task CPU when the mask allows. */
	if (pinned) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			cpu = here;
		else if (flow_cpu_ok(p, sel))
			cpu = sel;
		else
			cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
	} else if (sel >= 0 && flow_cpu_ok(p, sel)) {
		cpu = sel;
	} else {
		cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
	}
	if (!flow_cpu_ok(p, cpu)) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_slot_insert(p, -1, slice, pinned);
		return;
	}
	if (tctx->vruntime == 0 && tctx->run_at == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	flow_slot_insert(p, cpu, slice, pinned);
	/* Idle targets kick at once with no rate window. */
	/* Busy targets kick at most once per 2ms with soft preempt. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u64 now;
		u64 last;
		if (!st)
			return;
		if (st->running_pid == 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* Pinned tasks never preempt a busy CPU. */
		if (pinned) {
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		now = flow_now();
		last = flow_rate_at[(u32)cpu & 1023U];
		if (last != 0 && now - last < 2000000ULL) {
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		flow_rate_at[(u32)cpu & 1023U] = now;
		/* Shorten the occupant slice to zero so the kick sticks. */
		/* A null or self occupant keeps kick only with no shorten. */
		/* Use the compat helper, it falls back to cpu_rq on old kernels. */
		{
			struct task_struct *occupant =
			    __COMPAT_scx_bpf_cpu_curr(cpu);
			if (occupant && occupant != p)
				scx_bpf_task_set_slice(occupant, 0);
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(
			    &flow_stats.preempt_kicks, 1);
		}
	}
}
