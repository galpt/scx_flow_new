// SPDX-License-Identifier: GPL-2.0
/*
 * Charge helper for the flow core.
 *
 * Holds the leftover charge used when stopping never ran. Parks wake
 * by direct kick on insert. Outlined to keep disable plus exit small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
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
	flow_on_cpu_dec();
}
