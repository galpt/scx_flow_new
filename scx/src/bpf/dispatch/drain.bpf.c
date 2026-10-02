// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with up to four probes plus a BPF
 * mask gate. Each priority tier calls once in fixed order, and an
 * empty queue moves nothing with no scan. The kernel keeps each
 * priority queue list in deadline order, so the earliest matching
 * deadline moves with mask wins on drain and no BPF sort. A head that
 * cannot run on the dealing CPU skips to the next entry within four
 * probes, so one foreign task never stalls its tier for that pass.
 * The overflow scan skips the same way through the shared move, so
 * live work still moves there with a larger step cap. Homeless parks
 * rest in overflow with all other parks FIFO, so no trip touches the
 * kernel global queue. Fresh parks join the same order at once with
 * no hold. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Move one queued task to local with a bounded skip plus a BPF mask gate. */
/* Takes a queue id plus a CPU scalar with no struct pass, so every */
/* tier verifies through this one call. The live check in the caller */
/* covers the CPU, and the shared move gates affinity with no kernel */
/* error, so an empty queue returns zero with no scan and no miss */
/* count. An unmatching head skips to the next entry within four */
/* probes. The bound shares the step style with the overflow scan */
/* cap at thirty two. */
static __noinline u32 flow_move_one(u64 dsq, s32 cpu)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 probes = 0;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (probes >= (u32)FLOW_DISPATCH_TIER_PROBES)
			break;
		if (moved)
			break;
		probes++;
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
