// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Every arrival earns one deadline step past the later of now and
 * its last deadline, with the step shrinking as the effective
 * weight grows. The effective weight folds the task weight with
 * the hierarchy share over depth 8, so a task under a light
 * parent waits longer. The hierarchy share caches by id with
 * generation validation, and a miss uses base share. Throttled
 * hierarchies park in overflow with no kick and lazy refill, and
 * the single timer wakes parks soon. The task joins its target
 * deadline queue, so old kernels keep working. Pinned tasks and
 * foreign policies rest in overflow. A busy target kicks only for
 * a strictly earlier deadline, and pinned arrivals never kick a
 * busy CPU. Slice expiry paces the rest, so no slice write and no
 * stamp run here. See intf.h for the step helper and
 * dispatch.bpf.c for the matching drain order.
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
/* Target CPU for one enqueue with trust in select. */
/* Open tasks keep select when allowed, else the first allowed CPU. */
/* Pinned tasks never reach here, they rest in overflow above. */
static __always_inline s32 flow_pick_target(
	struct task_struct *p, s32 sel)
{
	s32 first;
	if (sel >= 0 && flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
/* Insert one task into the deadline queue with its deadline. */
/* The compat wrapper keeps old kernels working with no new kfunc. */
static __always_inline void flow_vtime_insert(
	struct task_struct *p, s32 cpu, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_vtime_dsq((u32)cpu),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into the shared overflow tail. */
/* Pinned and foreign tasks rest here with mask wins on drain. */
/* Throttled tasks park here too with no kick and lazy refill. */
static __always_inline void flow_over_insert(
	struct task_struct *p)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(),
	    (u64)FLOW_QUANTUM_NS, 0);
}
/* Insert one homeless task into the kernel global queue. */
/* Tasks without state or without a live CPU rest here with */
/* mask wins on drain, and the drain counts the global moves. */
static __always_inline void flow_global_insert(
	struct task_struct *p)
{
	scx_bpf_dsq_insert(p, (u64)SCX_DSQ_GLOBAL,
	    (u64)FLOW_QUANTUM_NS, 0);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	int policy;
	u32 hier;
	u32 eff;
	u64 now;
	u64 deadline;
	struct cgroup *cgrp = NULL;
	u64 cgid = 1;
	(void)enq_flags;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    (u64)FLOW_QUANTUM_NS, enq_flags);
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
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	policy = p->policy;
	now = flow_now();
	/* Tasks without state keep the kernel global queue with no kick. */
	/* Homeless tasks without a route count here too, the name stays */
	/* for the wire with no split. Fail closed, the next kicking */
	/* enqueue or dispatch wakes them with mask wins. */
	if (!tctx) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_global_insert(p);
		return;
	}
	/* Pinned plus non normal, batch, idle tasks rest in overflow. */
	/* Only normal plus batch plus idle policies join the deadline */
	/* queues, and realtime stays ordered with no deadline use. */
	/* Overflow sends no kick. Fail closed, the next kicking enqueue */
	/* or dispatch wakes them with mask wins. Pinned never kicks. */
	if (pinned || (policy != (int)FLOW_POL_NORMAL &&
	    policy != (int)FLOW_POL_BATCH &&
	    policy != (int)FLOW_POL_IDLE)) {
		flow_over_insert(p);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU keeps the kernel global queue with no kick. */
	/* Homeless tasks without a route count here too, the name stays */
	/* for the wire with no split. Fail closed, the next kicking */
	/* enqueue or dispatch wakes them with mask wins. */
	if (!flow_cpu_ok(p, cpu)) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_global_insert(p);
		return;
	}
	if (tctx->deadline == 0 && tctx->wait_at == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	/* Hierarchy share with cache and generation validation. */
	/* A cached id with current generation skips the depth walk. */
	/* A miss walks the nearest 8 ancestors with base on miss. */
	/* The task weight folds at use, so nice changes need no drop. */
	/* The generation compares only the low bits, so 64k bumps wrap. */
	/* Moves clear the cache and share changes bump the generation, */
	/* so a wrap needs 64k bumps with no move to falsely hit. */
	/* The hierarchy carries a reference with a paired release. */
	cgrp = flow_task_cgrp(p);
	cgid = flow_cgrp_id(cgrp);
	if (tctx->cached && tctx->cgid == cgid &&
	    tctx->generation == (u16)flow_load_gen()) {
		hier = tctx->eweight;
	} else {
		hier = flow_hier_weight(cgrp);
		tctx->cgid = cgid;
		tctx->eweight = hier;
		tctx->generation = (u16)flow_load_gen();
		tctx->cached = true;
	}
	/* Throttled hierarchies park in overflow with no kick. */
	/* Lazy refill runs on the walk, and the tightest pool binds. */
	/* Unlimited walks pass at once with no pool use. Fail closed, */
	/* the single timer wakes parks with mask wins on drain. */
	/* Throttled ns counts quanta at 1ms per hit with no wall use, */
	/* and nr throttled plus parked count the same hits. The names */
	/* stay for the wire with the quantum semantic documented. */
	if (flow_load_limited() && flow_bw_throttled(cgrp, now)) {
		tctx->wait_at = now;
		flow_over_insert(p);
		__sync_fetch_and_add(&flow_stats.throttled_ns,
		    (u64)FLOW_QUANTUM_NS);
		__sync_fetch_and_add(&flow_stats.nr_throttled, 1);
		__sync_fetch_and_add(&flow_stats.parked, 1);
		__sync_lock_test_and_set(&flow_bw_pending, 1);
		flow_cgrp_put(cgrp);
		return;
	}
	flow_cgrp_put(cgrp);
	/* One step past the later of now and the last deadline. */
	/* The effective weight folds task plus hierarchy, so a long */
	/* sleep earns no credit and a back to back arrival queues */
	/* behind its own last step. Moves carry the deadline. */
	eff = flow_eff_weight(p->scx.weight, hier);
	deadline = flow_deadline_next(tctx->deadline, now, eff);
	tctx->deadline = deadline;
	tctx->wait_at = now;
	flow_vtime_insert(p, cpu, deadline);
	/* Idle targets kick at once with no rate window. */
	/* The idle flag clears first so the kick sticks. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 occ_pid;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		if (!st)
			return;
		if (st->running_pid == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* Pinned rests in overflow above with no kick, so this busy */
		/* path sees open tasks only with no pinned check. */
		/* The running pid names the occupant with no curr read. */
		/* A trusted lookup carries the occupant deadline, and a */
		/* missing occupant fails closed with no kick. */
		occ_pid = st->running_pid;
		if (occ_pid == 0 || occ_pid == (u32)p->pid) {
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		bpf_rcu_read_lock();
		trusted = bpf_task_from_pid(occ_pid);
		if (!trusted) {
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		octx = flow_lookup(trusted);
		if (!octx) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		/* A strictly earlier deadline kicks at once. */
		/* Equal or later deadlines pace at slice expiry. */
		if (flow_time_before(deadline, octx->deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(
			    &flow_stats.preempt_kicks, 1);
			return;
		}
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		__sync_fetch_and_add(&flow_stats.preempt_skipped, 1);
	}
}
