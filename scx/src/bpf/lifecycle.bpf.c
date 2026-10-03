// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running claims the segment start from zero and counts the on CPU
 * gauge once per claim. Stopping claims the start once and charges
 * the raw segment to total runtime, then feeds the burst
 * predictor average plus deviation from the same delta with shifts,
 * then counts one requeue per runnable stop else one completion. A wall
 * completion past release plus deadline counts one miss with one park
 * and no kick, since the task already left the CPU. Enable clears the
 * release plus the period plus the deadline plus the predictor plus
 * the hint plus the miss count, and disable plus exit charge a
 * leftover segment at most once when stopping never ran. A closed gate
 * still counts one reject with no charge. Release clears a stale
 * running view with no charge. The gate runs first in every op except
 * the exiting paths, so a stale CPU fails closed with one counter. See
 * intf.h for the shared helpers and enqueue.bpf.c for the deadline
 * choice.
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
	/* Every segment counts raw time with no weight scaling. */
	/* The predictor average plus deviation update from the same */
	/* delta with shifts only plus a first deviation floor at average */
	/* quarter, so later deadlines track recent bursts with no extra */
	/* walk. A zero delta keeps the predictor with no train, so a */
	/* backward clock never pulls the average to 1ns. */
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	if (delta) {
		u64 avg = READ_ONCE(tctx->avg_ns);
		u64 dev = READ_ONCE(tctx->dev_ns);
		u64 n_avg = flow_pred_avg(avg, delta);
		u64 n_dev = flow_pred_dev(dev, avg, delta);
		__sync_lock_test_and_set(&tctx->avg_ns, n_avg);
		__sync_lock_test_and_set(&tctx->dev_ns, n_dev);
	}
	/* The pid view clears when owned with no gauge use. */
	/* The snapshot counts live pids for the on CPU gauge. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	/* A wall completion past the deadline counts one miss with one */
	/* park and no kick, since the task already left the CPU. */
	if (!runnable && tctx->release &&
	    !flow_deadline_ok(tctx->deadline, now)) {
		flow_count_miss(tctx);
	}
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
	/* Fresh tasks hold no release, no period, no deadline, no */
	/* predictor, no stamps, no hint, and no misses. The first */
	/* enqueue anchors at now with one deadline from the hint period */
	/* with no predictor use. The cached hierarchy id clears too, so */
	/* a reused pid never reads a stale hierarchy. */
	flow_cgrp_cache_invalidate((u32)p->pid);
	tctx->release = 0;
	tctx->period = 0;
	tctx->deadline = 0;
	tctx->avg_ns = 0;
	tctx->dev_ns = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
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
	/* The gauge drop follows the claim with no owner gate. */
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
	/* The gauge drop follows the claim with no owner gate. */
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
