// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with no iterator and no per task
 * lookup. Each priority tier calls once in fixed order, and an empty
 * queue moves nothing with no scan. The kernel keeps each priority
 * queue list in deadline order, so the head holds the earliest deadline
 * with mask wins on drain and no BPF sort. A head that cannot run on
 * the dealing CPU blocks the tier for that pass, so one foreign task
 * can stall its queue behind head blocking. The overflow scan skips
 * such entries instead, so live work still moves there. Homeless parks
 * rest in overflow with all other parks FIFO, so no trip touches the
 * kernel global queue. Fresh parks join the same order at once with
 * no hold. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Move one queued task to local with no gate. */
/* Takes a queue id scalar with no struct pass, so every tier verifies */
/* through this one call. The live check in the caller covers the CPU, */
/* and the kernel holds priority order plus mask wins, so an empty */
/* queue returns zero with no scan and no miss count. An unmatching */
/* head also returns zero with the tier stalled for that pass, unlike */
/* the overflow scan that skips to the next match. */
static __noinline u32 flow_move_one(u64 dsq)
{
	if (scx_bpf_dsq_move_to_local(dsq, 0))
		return 1;
	return 0;
}
