// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running stamps the segment start and pairs the on CPU gauge.
 * Stopping charges the raw segment to total runtime and drains
 * the hierarchy pools, then counts one requeue per runnable stop
 * else one completion. Enable clears the deadline state plus the
 * share cache, and disable plus exit charge a leftover segment
 * at most once when stopping never ran. Release clears a stale
 * running view with no charge. See intf.h for the shared helpers
 * and enqueue.bpf.c for the deadline choice.
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
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (tctx) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The store uses an exchange to pair with the stopping and */
		/* leftover claims with no torn stamp. */
		stamp = now ? now : 1;
		__sync_lock_test_and_set(&tctx->run_at, stamp);
	}
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st)
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
inc:
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
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
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	/* Tasks without state drop the gauge with no charge. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		flow_on_cpu_dec();
		return;
	}
	/* The start claims with an exchange, so stopping versus disable */
	/* or exit charges once. A zero claim means a leftover already */
	/* charged this run. */
	/* The owner clear still runs, so a migrated stop stays clean. */
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
	/* Order already carries weight through the deadline step. */
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	/* Pools drain by raw time with the tightest pool binding. */
	/* Unlimited hierarchies pass with no charge. The lookup */
	/* carries a reference with a paired release, and a null */
	/* lookup skips the charge with no trap. */
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (cgrp) {
			flow_bw_consume(cgrp, delta);
			flow_cgrp_put(cgrp);
		}
	}
	/* The exchange above already zeroed the start, so disable plus */
	/* exit stay once. */
	/* Owner only clears, so a migrated stop never clears a new owner. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	flow_on_cpu_dec();
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no deadline, no stamps, and no cache. */
	/* The first enqueue anchors past now with one step. */
	tctx->deadline = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->cgid = 0;
	tctx->eweight = (u32)FLOW_WEIGHT_BASE;
	tctx->cached = false;
	tctx->generation = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	flow_charge_leftover(cpu, p, tctx, (u32)p->pid);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	flow_charge_leftover(cpu, p, tctx, (u32)p->pid);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
