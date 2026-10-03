// SPDX-License-Identifier: GPL-2.0
/*
 * Overflow fill for the dispatch pass.
 *
 * Moves matching tasks from the overflow tail in queue order in one
 * scan with no move bound. The overflow tail stays FIFO with plain
 * inserts, so this queue order step moves every match with best effort
 * order there. The queue handle stays hoisted once at entry, so the
 * scan pays no DSQ lookup. Live stays proven once at entry through the
 * dispatch gate, so the scan pays no live branch. The BPF mask test
 * gates affinity on the move, so a mismatched entry skips with no
 * kernel error while mask still wins on drain. Tiers skip the same
 * way through the shared move, so one foreign task never stalls live
 * work. Runs noinline with a scalar CPU plus a bounded scan, so the
 * verifier stays small with no unrolled caller tree and no rescan
 * per move.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Overflow fill with the shared move in one place. */
/* Moves every match in queue order in one scan with no rescan per */
/* move. Noinline with a scalar input so the single scan verifies once */
/* apart from the dispatch entry. */
static __noinline u32 flow_overflow_fill(s32 cpu)
{
	u32 moved = 0;
	u64 ov;
	struct task_struct *p;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	/* Queue handle stays hoisted, so the scan pays no DSQ lookup. */
	ov = flow_overflow_dsq();
	/* Single scan moves every match in queue order with */
	/* no rescan per move, so a deep tail pays one scan. */
	/* The move adds with no success branch and the BPF mask test */
	/* gates affinity, so mask misses skip with no kernel error. */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, ov, 0) {
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
