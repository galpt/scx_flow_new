// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with a uniform skip plus a BPF
 * mask gate. Each priority tier calls once in fixed order, and an
 * empty queue moves nothing with no scan. The kernel keeps each
 * priority queue list in deadline order, so the earliest matching
 * deadline moves with mask wins on drain and no BPF sort. A head that
 * cannot run on the dealing CPU skips to the next entry through the
 * shared move, so one foreign task never stalls its tier for that pass.
 * The overflow scan skips the same way through the shared move, so
 * live work still moves there. Visits share the per pass cap at sixty
 * four with leftover work resuming next pass, so one pass never holds
 * RCU across the whole queue while staying work conserving across
 * passes. Homeless parks rest in overflow with all other parks FIFO,
 * so no trip touches the kernel global queue. Fresh parks join the
 * same order at once with no hold. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Move one queued task to local with a uniform skip plus a BPF mask gate. */
/* Takes a queue id plus a CPU scalar plus the per pass visit count with */
/* no struct pass, so every tier verifies through this one call. The gate */
/* runs first for the CPU, then the queue depth leaves at once with no RCU */
/* hold, so idle tiers stay cheap. The length is an opportunistic early */
/* out only with no correctness use, so a join racing the read still meets */
/* the next pass with no loss. The shared move gates affinity with no */
/* kernel error, so an empty queue returns zero with no scan and no miss */
/* count. An unmatching head skips to the next entry through the same */
/* shared gate the overflow scan uses, so one foreign task never stalls */
/* its tier for that pass. Visits cap per pass with resume next pass, so */
/* the loop never holds RCU across the whole queue. Static tier order is */
/* local plus node plus machine plus overflow with no reorder. */
static __noinline u32 flow_move_one(u64 dsq, s32 cpu, u32 *visits)
{
	struct task_struct *p;
	u32 moved = 0;
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!visits))
		return 0;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return 0;
	if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
		return 0;
	if (likely(scx_bpf_dsq_nr_queued(dsq) <= 0))
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (unlikely(moved))
			break;
		if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
			break;
		(*visits)++;
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
