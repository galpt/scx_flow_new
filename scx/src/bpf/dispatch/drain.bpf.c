// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open batch drain for the dispatch pass.
 *
 * Calls the single head move up to the batch bound so a stalled pass
 * still drains up to sixteen queue ordered tasks. Under flood rejects
 * hold no key and ordered probes find nothing, so this loop carries
 * the backlog instead of one per pass. Each move stays affinity gated
 * with keyed drop, so order rows never leak and no dead task runs.
 * Runs noinline with scalar CPU plus budget and a bounded loop so
 * the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open drain with batch progress and FIFO order in one place. */
/* Calls the single head move up to the batch bound so a stalled pass */
/* still drains up to sixteen queue ordered tasks. Under flood rejects */
/* hold no key and ordered probes find nothing, so this loop carries */
/* the backlog instead of one per pass. Each move stays affinity gated */
/* with keyed drop, so order rows never leak and no dead task runs. */
static __noinline u32 veb_fail_open_drain(s32 cpu, u32 budget)
{
	u32 moved = 0;
	int i;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	if (budget > (u32)FLOW_DISPATCH_MAX_BATCH)
		budget = (u32)FLOW_DISPATCH_MAX_BATCH;
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
