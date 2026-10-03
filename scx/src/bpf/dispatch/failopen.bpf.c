// SPDX-License-Identifier: GPL-2.0
/*
 * Overflow fill for the dispatch pass.
 *
 * Moves matching tasks from the overflow tail in queue order in one
 * scan with moves uncapped to remaining slots and visits capped per
 * pass. The overflow tail stays FIFO with plain inserts, so this queue
 * order step moves every match within the caps with best effort order
 * there. The queue handle stays hoisted once at entry, so the scan
 * pays no DSQ lookup. Live stays proven once at entry through the
 * dispatch gate, so the scan pays no live branch. The BPF mask test
 * gates affinity on the move, so a mismatched entry skips with no
 * kernel error while mask still wins on drain. Tiers skip the same
 * way through the shared move, so one foreign task never stalls live
 * work. Visits cap at sixty four per pass with resume next pass, so a
 * miss heavy tail never holds RCU across the whole queue while moved
 * progress stays work conserving across passes. Runs noinline with a
 * scalar CPU plus budget plus visit count, so the verifier stays small
 * with no unrolled caller tree and no rescan per move.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Overflow fill with the shared move in one place. */
/* Moves up to budget matches in queue order in one scan with visits */
/* capped per pass, so a deep tail never holds RCU across the whole */
/* queue while leftover work resumes next pass. Noinline with scalar */
/* inputs plus the visit count so the single scan verifies once apart */
/* from the dispatch entry. */
static __noinline u32 flow_overflow_fill(s32 cpu, u32 budget, u32 *visits)
{
	u32 moved = 0;
	u64 ov;
	u64 qlen;
	struct task_struct *p;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	if (!visits)
		return 0;
	if (*visits >= (u32)FLOW_DISPATCH_MAX_VISIT)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	/* Queue handle stays hoisted, so the scan pays no DSQ lookup. */
	ov = flow_overflow_dsq();
	/* Length is an opportunistic early out only with no correctness */
	/* use, so a join racing the read still meets the scan below. */
	qlen = (u64)scx_bpf_dsq_nr_queued(ov);
	if (qlen == 0)
		return 0;
	/* Single scan moves up to remaining slots in queue order with */
	/* no rescan per move, so a deep tail pays one scan. Visits cap */
	/* per pass with resume next pass, so a miss heavy tail never */
	/* holds RCU across the whole queue while moved progress stays. */
	/* The move adds with no success branch and the BPF mask test */
	/* gates affinity, so mask misses skip with no kernel error. */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, ov, 0) {
		if (moved >= budget)
			break;
		if (*visits >= (u32)FLOW_DISPATCH_MAX_VISIT)
			break;
		(*visits)++;
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
