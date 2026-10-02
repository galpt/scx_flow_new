// SPDX-License-Identifier: GPL-2.0
/*
 * Finish accounting for the dispatch pass.
 *
 * Holds the single per tier account plus the single overflow account
 * in one place, so every moved task lands in exactly one bucket with
 * no missed count. The caller passes the moved count per tier with no
 * shared math, and a zero count skips with no atomic. Runs inline with
 * scalar inputs, so the verifier keeps no extra call.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Count one tier moves with no lock. */
/* A zero count skips with no atomic, so empty tiers stay cheap. */
static __always_inline void flow_account_local(u32 n)
{
	if (!n)
		return;
	__sync_fetch_and_add(&flow_stats.local_moves, (u64)n);
}
/* Count one node tier moves with no lock. */
static __always_inline void flow_account_node(u32 n)
{
	if (!n)
		return;
	__sync_fetch_and_add(&flow_stats.node_moves, (u64)n);
}
/* Count one machine tier moves with no lock. */
static __always_inline void flow_account_machine(u32 n)
{
	if (!n)
		return;
	__sync_fetch_and_add(&flow_stats.machine_moves, (u64)n);
}
/* Count one overflow moves with no lock. */
static __always_inline void flow_account_over(u32 n)
{
	if (!n)
		return;
	__sync_fetch_and_add(&flow_stats.over_moves, (u64)n);
}
