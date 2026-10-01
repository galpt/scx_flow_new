// SPDX-License-Identifier: GPL-2.0
/*
 * Admitted drop plus miss accounting for the flow core.
 *
 * Holds the single exit drop used on stopping, disable, exit, gate
 * fail paths. Drops read the stored share plus CPU plus key then
 * subtract from the per CPU sum then clear task state then delete
 * the order row then clear the head slot. Clearing task state first
 * makes a second drop see zero share so every admit pairs one add
 * with one drop. Misses count when a
 * blocking complete lands past the stored deadline with parks folded
 * in so deadline misses stay visible. Gate fail drops run the same
 * path so stale entries never leak. All helpers stay small so the
 * verifier stays small. Drops live in the core with rings as
 * observability solely.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void flow_admit_drop_one(u32 pid,
	struct flow_task_ctx *tctx, u32 runnable, u64 now)
{
	u64 share = 0;
	u32 cpu = 0;
	u64 deadline = 0;
	u32 key = (u32)FLOW_VEB_EMPTY;
	if (pid == 0)
		return;
	if (tctx) {
		share = READ_ONCE(tctx->admit_share);
		cpu = READ_ONCE(tctx->admit_cpu);
		key = READ_ONCE(tctx->key);
	}
	if (share != 0 && runnable == 0 && now != 0) {
		deadline = flow_order_deadline(pid);
		if (deadline != 0 && now != deadline &&
		    !flow_time_before(now, deadline)) {
			__sync_fetch_and_add(&flow_stats.misses, 1);
			__sync_fetch_and_add(&flow_stats.parks, 1);
		}
	}
	if (share != 0) {
		if ((u64)cpu < (u64)FLOW_MAX_CPUS)
			flow_admitted_sub(cpu, share);
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, 0);
			WRITE_ONCE(tctx->deadline, 0);
			WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
		}
	} else {
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, 0);
			WRITE_ONCE(tctx->deadline, 0);
			WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
		}
	}
	flow_order_delete_one(pid);
	/* Teardown frees the head slot when it still names this pid, */
	/* so a stopped task never lingers as a head. Other slots stay. */
	/* An empty key stays a no op through the clear guard. */
	flow_head_clear(pid, key);
}
static __always_inline void flow_admit_drop(u32 pid,
	struct flow_task_ctx *tctx, u32 runnable, u64 now)
{
	flow_admit_drop_one(pid, tctx, runnable, now);
}
