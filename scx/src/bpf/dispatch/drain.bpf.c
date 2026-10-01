// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open batch drain for the dispatch pass.
 *
 * Calls the single head move up to the exact budget so a stalled
 * pass still drains queue ordered tasks up to sixteen and a moving
 * pass under flood still drains up to four within sixteen. Under
 * flood rejects hold no key and ordered probes find little, so this
 * loop carries the backlog instead of one per pass. Ordered checks
 * run first so admitted tasks stay preferred, while this FIFO step
 * may move admitted tasks out of order under flood with best effort
 * order there. Each move stays affinity gated with keyed drop, so
 * order rows never leak and no dead task runs. Callers pass sixteen
 * on stall plus up to four within sixteen on moving flood, so the
 * budget stays exact with no clamp. Runs inline so the batch
 * wrapper costs no call frame with scalar CPU plus budget and a
 * bounded loop so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open drain with batch progress and FIFO order in one place. */
/* Calls the single head move up to the exact budget so a stalled */
/* pass still drains queue ordered tasks up to sixteen and a moving */
/* flood pass still drains up to four within sixteen. Ordered */
/* checks run first so admitted tasks stay preferred, while this */
/* FIFO step may move admitted tasks out of order under flood. */
/* Inline so the batch wrapper costs no verifier call frame: the */
/* flood fix added this layer over the single move and the dispatch */
/* path already nests eight deep through remove plus root refresh */
/* plus scan plus cluster plus bit scan. */
static __always_inline u32 veb_fail_open_drain(s32 cpu, u32 budget)
{
	u32 moved = 0;
	int i;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	/* Callers pass sixteen, so the budget stays exact. */
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
