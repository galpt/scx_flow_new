// SPDX-License-Identifier: GPL-2.0
/*
 * Charge and miss helpers for the core.
 *
 * Holds the leftover charge plus the miss count. Tier waits wake by
 * direct kick on insert with no timer wait, so no timer lives here.
 * Leftover charge matches stopping with scaled vruntime advance plus
 * minimum fold plus predictor train, so disable plus exit still pace
 * fairness with no double charge. Each helper stays noinline with
 * scalar inputs, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Charge one leftover run segment at most once with scaled advance. */
/* Stopping owns the normal charge and clears the run start. Disable */
/* and exit funnel here only for a running task that stopping never */
/* saw. The start claims with a compare and swap, so stopping versus */
/* disable or exit charges once, and a failed claim means stopping won, */
/* so this pass drops with no double charge. The pid clear stays in the */
/* caller with no gauge use, since the on CPU gauge lives in the */
/* snapshot. A backward clock charges zero time with no advance. The */
/* predictor average plus deviation update from the same delta with */
/* shifts plus a first deviation floor at average quarter, so a leftover */
/* segment still trains later deadlines. The vruntime advance uses the */
/* task weight with no divide plus a minimum fold, so leftovers still */
/* pace fairness. Outlined to keep disable and exit small. */
static __noinline void flow_charge_leftover(struct task_struct *p,
	struct flow_task_ctx *tctx)
{
	u64 start;
	u64 now;
	u64 delta;
	u64 got;
	s32 cpu;
	if (!tctx)
		return;
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
	if (delta) {
		u64 avg = (u64)READ_ONCE(tctx->avg_ns);
		u64 dev = (u64)READ_ONCE(tctx->dev_ns);
		u32 weight = READ_ONCE(tctx->weight);
		u64 n_avg = flow_pred_avg(avg, delta);
		u64 n_dev = flow_pred_dev(dev, avg, delta);
		u64 vrun = READ_ONCE(tctx->vruntime);
		u64 n_vrun;
		if (weight == 0)
			weight = (u32)FLOW_WEIGHT_BASE;
		n_vrun = flow_vruntime_advance(vrun, delta, weight);
		__sync_lock_test_and_set(&tctx->avg_ns, (u32)n_avg);
		__sync_lock_test_and_set(&tctx->dev_ns, (u32)n_dev);
		__sync_lock_test_and_set(&tctx->vruntime, n_vrun);
		cpu = scx_bpf_task_cpu(p);
		flow_min_advance(cpu, n_vrun);
	}
}
/* Count one deadline miss with saturation and no park. */
/* Misses clamp, so a huge miss count never wraps to zero. Tier */
/* rejoins carry the fresh deadline with no extra counter. */
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
}
