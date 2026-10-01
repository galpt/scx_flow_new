// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open batch drain for the dispatch pass.
 *
 * Calls the single head move up to the exact budget so a stalled
 * pass still drains queue ordered tasks up to sixteen and a moving
 * pass drains the remainder after ordered work within sixteen. The
 * loop carries rejects in queue order up to the bound. Ordered checks
 * run first so admitted tasks stay preferred, while this FIFO step
 * moves the remainder with best effort order there. Each move stays
 * affinity gated with drops at teardown, so no dead task runs.
 * Callers pass sixteen on stall plus the remainder on moving passes,
 * so the budget stays exact with no clamp. Runs inline so the batch
 * wrapper costs no call frame with scalar CPU plus budget and a
 * bounded loop so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open drain with batch progress and FIFO order in one place. */
/* Calls the single head move up to the exact budget so a stalled */
/* pass still drains queue ordered tasks up to sixteen and a moving */
/* pass drains the remainder within sixteen. Ordered checks run first */
/* so admitted tasks stay preferred, while this FIFO step moves the */
/* remainder with best effort order. Inline so the batch wrapper */
/* costs no verifier call frame with the deep dispatch path kept */
/* small through split helpers. */
static __always_inline u32 veb_fail_open_drain(s32 cpu, u32 budget)
{
	u32 moved = 0;
	int i;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	/* Callers pass sixteen or the remainder, so the budget stays exact. */
	bpf_for(i, 0, FLOW_DISPATCH_MAX_BATCH) {
		if ((u64)moved >= (u64)budget)
			break;
		if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
			break;
		if (!veb_fail_open_one(cpu))
			break;
		moved++;
	}
	return moved;
}
