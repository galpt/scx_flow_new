// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running claims the segment start from zero with no BPF gauge.
 * The snapshot counts live pids for the on CPU gauge. Stopping claims
 * the start once, charges the raw segment to total runtime, advances
 * vruntime by the scaled delta, folds the CPU minimum forward, then
 * feeds the burst predictor average plus deviation from the same delta
 * with shifts, then counts one requeue per runnable stop else one
 * completion. A wall completion past the deadline counts one miss with
 * no wait and no kick, since the task already left the CPU. Enable
 * clears vruntime plus deadline plus stamps plus predictor plus lag
 * plus weight plus slice plus hint plus hint weight plus misses, and
 * disable plus exit charge a leftover segment at most once when stopping never ran with
 * the same advance plus minimum fold. A closed gate still counts one
 * reject with no charge. Release clears a stale running view with no
 * charge. The gate runs first in every op except the exiting paths, so
 * a stale CPU fails closed with one counter. See intf.h for the shared
 * helpers and enqueue.bpf.c for the fair time choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	cpu = scx_bpf_task_cpu(p);
	/* The gate runs first with fail closed and no count on pass. */
	/* Exiting tasks never reach here through the running path. */
	if (unlikely(!flow_entry_ok(cpu, p, 0))) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	if (likely(tctx)) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The claim swaps from zero only, so a second running */
		/* without a stop keeps the first start with no second use. */
		/* The on CPU gauge lives in the snapshot with no BPF count, */
		/* so this path holds no gauge add. */
		stamp = now ? now : 1;
		__sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
	}
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return;
	st = flow_cpu((u32)cpu);
	if (likely(st))
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so stopping versus disable */
	/* or exit charges once. A zero claim means no counted start, */
	/* so this pass drops with no charge. The on CPU gauge lives in */
	/* the snapshot with no BPF drop, so every pass ends here with no */
	/* gauge use. */
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	/* Every segment counts raw time while vruntime counts scaled time. */
	/* The predictor average plus deviation update from the same */
	/* delta with shifts only plus a first deviation floor at average */
	/* quarter, so later deadlines track recent bursts with no extra */
	/* walk. A zero delta keeps the predictor with no train, so a */
	/* backward clock never pulls the average to 1ns. The vruntime */
	/* advance uses the effective share of task times stored hint over */
	/* 128 with no divide and no lookup, so heavy tasks move slowly */
	/* while light tasks move quickly with no neutral cliff. The CPU */
	/* minimum folds forward best effort with no regression past a */
	/* concurrent win. */
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	if (delta) {
		u64 avg = (u64)READ_ONCE(tctx->avg_ns);
		u64 dev = (u64)READ_ONCE(tctx->dev_ns);
		u32 task_w = READ_ONCE(tctx->weight);
		u32 hint_w = READ_ONCE(tctx->hint_w);
		u32 eff_w;
		u64 n_avg = flow_pred_avg(avg, delta);
		u64 n_dev = flow_pred_dev(dev, avg, delta);
		u64 vrun = READ_ONCE(tctx->vruntime);
		u64 n_vrun;
		if (task_w == 0)
			task_w = (u32)FLOW_WEIGHT_BASE;
		eff_w = flow_task_effective_weight(task_w, hint_w);
		n_vrun = flow_vruntime_advance(vrun, delta, eff_w);
		__sync_lock_test_and_set(&tctx->avg_ns, (u32)n_avg);
		__sync_lock_test_and_set(&tctx->dev_ns, (u32)n_dev);
		__sync_lock_test_and_set(&tctx->vruntime, n_vrun);
		flow_min_advance(cpu, n_vrun);
	}
	/* The pid view clears when owned with no gauge use. */
	/* The snapshot counts live pids for the on CPU gauge. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	/* A wall completion past the deadline counts one miss with no */
	/* wait and no kick, since the task already left the CPU. */
	if (!runnable && !flow_deadline_ok(READ_ONCE(tctx->deadline), now))
		flow_count_miss(tctx);
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no vruntime, no deadline, no stamps, no */
	/* predictor, no lag, neutral weight, fixed slice, no hint, neutral */
	/* hint weight, and no misses. The first enqueue clamps vruntime to */
	/* the CPU minimum minus the lag bound with a fallback deadline */
	/* plus a virtual deadline, so sleepers gain no more than one */
	/* boost. The cached hierarchy id clears too, so a reused pid */
	/* never reads a stale hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	tctx->vruntime = 0;
	tctx->deadline = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->hint_w = (u32)FLOW_WEIGHT_BASE;
	tctx->avg_ns = 0;
	tctx->dev_ns = 0;
	tctx->vlag = 0;
	tctx->weight = (u32)FLOW_WEIGHT_BASE;
	tctx->slice_ns = (u32)FLOW_QUANTUM_NS;
	tctx->hint_us = 0;
	tctx->misses = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The advance plus the minimum fold match stopping, so a leftover */
	/* still paces fairness with no double charge. The pid clear stays */
	/* in the caller with no gauge use. */
	flow_charge_leftover(p, tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	/* Exiting tasks stay exempt from the gate with no count. The */
	/* cached hierarchy id clears too, so a later pid reuse never */
	/* reads a stale hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The advance plus the minimum fold match stopping, so a leftover */
	/* still paces fairness with no double charge. The pid clear stays */
	/* in the caller with no gauge use. */
	flow_charge_leftover(p, tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* The gate runs with no task here, so only the CPU checks. */
	/* A stale CPU counts one reject with no clear. */
	if (cpu >= 0 && !flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
