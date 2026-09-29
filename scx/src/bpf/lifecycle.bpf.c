// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running claims the segment start from zero and counts the on CPU
 * gauge once per claim. Stopping claims the start once and charges
 * the raw segment to total runtime and drains
 * the hierarchy pools, then advances virtual runtime by scaled time
 * with the cached share and bumps the CPU floor, then counts one requeue per runnable stop
 * else one completion. Enable clears the deadline plus the runtime
 * plus the share cache, and disable plus exit charge a leftover segment
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
	u64 prev;
	bool claimed = false;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (tctx) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The claim swaps from zero only, so a second running */
		/* without a stop keeps the first start with no second */
		/* gauge count. The stopping and leftover claims pair */
		/* with no torn stamp. */
		stamp = now ? now : 1;
		prev = __sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
		claimed = prev == 0;
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
	/* Count the on CPU gauge once per claimed start with no second count. */
	/* Tasks without state hold no claim, so they hold no count. */
	if (claimed)
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
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so stopping versus disable */
	/* or exit charges once. A zero claim means no counted start, */
	/* so this pass drops with no charge and no gauge move, and */
	/* every counted start meets exactly one gauge drop. */
	/* The owner check gates the pid clear only, the gauge drop */
	/* follows the claim with no owner gate, so a migrated stop */
	/* still pairs. */
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
	/* Runtime advances by scaled time with the cached share. */
	/* A cold cache uses base share, and a zero share folds to base */
	/* too, so the advance never divides by zero. Two divides per stop */
	/* stay cheap beside one quantum. The floor tracks the largest */
	/* served runtime with no wrap use. */
	{
		u32 share = tctx->cached ? tctx->eweight :
		    (u32)FLOW_WEIGHT_BASE;
		if (!share)
			share = (u32)FLOW_WEIGHT_BASE;
		tctx->vruntime = flow_vruntime_advance(tctx->vruntime,
		    delta, share);
		if (cpu >= 0)
			flow_floor_max((u32)cpu, tctx->vruntime);
	}
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
	/* Owner gates the pid clear only, the gauge drop follows the */
	/* claim with no owner gate. */
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
	/* Fresh tasks hold no deadline, no runtime, no stamps, and no cache. */
	/* The first enqueue anchors past now with one key. */
	tctx->deadline = 0;
	tctx->vruntime = 0;
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
	/* The gauge drop follows the claim with no owner gate. */
	flow_charge_leftover(p, tctx, cpu);
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
	/* The gauge drop follows the claim with no owner gate. */
	flow_charge_leftover(p, tctx, cpu);
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
