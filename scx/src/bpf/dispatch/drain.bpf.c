// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with a peek plus a BPF mask gate.
 * Each priority tier calls once in fixed order, and an empty queue
 * moves nothing with no scan. The kernel keeps each priority queue
 * list in deadline order, so the head holds the earliest deadline
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
/* Move one queued task to local with a BPF mask gate. */
/* Takes a queue id plus a CPU scalar with no struct pass, so every */
/* tier verifies through this one call. The live check in the caller */
/* covers the CPU, and the BPF mask test gates the head with no */
/* kernel error, so an empty queue returns zero with no scan and no */
/* miss count. An unmatching head also returns zero with the tier */
/* stalled for that pass, unlike the overflow scan that skips to the */
/* next match. */
static __noinline u32 flow_move_one(u64 dsq, s32 cpu)
{
	struct task_struct *p;
	u32 moved = 0;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (!flow_mask_ok(cpu, p))
			break;
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0))
			moved = 1;
		break;
	}
	bpf_rcu_read_unlock();
	return moved;
}
