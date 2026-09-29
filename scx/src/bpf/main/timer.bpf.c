// SPDX-License-Identifier: GPL-2.0
/*
 * Charge and timer helpers for the core.
 *
 * Holds the leftover charge plus the single backstop timer that wakes
 * parked work on a fixed interval. Each helper stays noinline with
 * scalar inputs, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Charge one leftover run segment at most once with no scaling. */
/* Stopping owns the normal charge and clears the run start. */
/* Disable and exit funnel here only for a running task that */
/* stopping never saw. The start claims with a compare and swap, so */
/* stopping versus disable or exit charges once, and a failed claim */
/* means stopping won, so this pass drops with no double charge. */
/* The gauge drop follows the claim with no owner gate, the owner */
/* check gates the pid clear in the caller only, so a migrated stop */
/* still pairs. A backward clock charges zero time but still pairs */
/* the gauge. Runtime advances by scaled time with the task weight */
/* beside the raw charge. Outlined to keep disable and exit small. */
static __noinline void flow_charge_leftover(struct task_struct *p,
	struct flow_task_ctx *tctx, s32 cpu)
{
	u64 start;
	u64 now;
	u64 delta;
	u64 got;
	if (!tctx)
		return;
	(void)p;
	start = READ_ONCE(tctx->run_at);
	if (start == 0)
		return;
	now = flow_now();
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	got = __sync_val_compare_and_swap(&tctx->run_at,
	    start, 0);
	if (got != start)
		return;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	{
		u32 w = flow_weight_clamp(p->scx.weight);
		tctx->vruntime = flow_vruntime_advance(tctx->vruntime,
		    delta, w);
	}
	flow_on_cpu_dec();
}
/* Count one deadline miss with saturation plus one park. */
/* Misses clamp, so a huge miss count never wraps to zero. Parks */
/* count the same hits, so the wire shows misses plus parks together. */
static __noinline void flow_count_miss(
	struct flow_task_ctx *tctx)
{
	u32 m;
	if (!tctx)
		return;
	m = READ_ONCE(tctx->misses);
	if (m != 0xffffffffU)
		__sync_fetch_and_add(&tctx->misses, 1);
	__sync_fetch_and_add(&flow_stats.misses, 1);
	__sync_fetch_and_add(&flow_stats.parks, 1);
}
/* Single backstop timer for parked work on a fixed interval. */
/* The tick arms pending when parked work waits, then kicks the first */
/* live CPU, so a parked task meets a dispatch pass soon. The kick */
/* targets the first live CPU with mask wins on drain, so a parked */
/* mask mismatch stays best effort with no task scan here. Idle ticks */
/* with no parked work stay quiet with no kick and no storm. Pending */
/* uses an atomic exchange to match the enqueue store with no torn */
/* flag. The live scan stays bound at 8, so the tick never sweeps the */
/* full CPU range. */
static int flow_backstop_cb(void *map, int *key,
	struct bpf_timer *timer)
{
	u32 found = 0xffffffffU;
	u64 was;
	u64 kicks;
	u64 n;
	u32 start = 0;
	u32 off;
	(void)map;
	(void)key;
	if (!READ_ONCE(flow_backstop_pending))
		goto arm;
	was = __sync_lock_test_and_set(&flow_backstop_pending, 0);
	if (!was)
		goto arm;
	n = nr_cpu_ids;
	if (n == 0 || n > (u64)FLOW_MAX_CPUS)
		goto arm;
	kicks = READ_ONCE(flow_stats.kicks);
	start = (u32)(kicks % n);
	bpf_for(off, 0, 8) {
		u32 peer;
		if ((u64)off >= n)
			break;
		peer = (start + off) % (u32)n;
		if (flow_cpu_live(peer)) {
			found = peer;
			break;
		}
	}
	if (found != 0xffffffffU) {
		scx_bpf_kick_cpu((s32)found, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	}
arm:
	bpf_timer_start(timer, (u64)FLOW_BACKSTOP_TIMER_NS, 0);
	return 0;
}
