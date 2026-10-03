// SPDX-License-Identifier: GPL-2.0
/*
 * Shared move plus overflow fill for the dispatch pass.
 *
 * Holds the single affinity probe plus the single task move plus the
 * overflow scan in one place, so tiers plus overflow share one gate
 * with no per tier copy. Live stays proven once at entry, so the per
 * element cost stays one mask test with no live branch. The overflow
 * scan plus the uniform tier skip gate affinity through this one BPF
 * test, so a miss skips with no kernel error while mask still wins on
 * drain. Moves match in queue order for overflow and in deadline order
 * for tiers through the same move, so one foreign task never stalls
 * live work. Visits cap at sixty four per pass with resume next pass,
 * so a miss heavy tail never holds RCU across the whole queue while
 * moved progress stays work conserving across passes. Runs inline for
 * the probe plus move with the scans noinline on scalar inputs, so the
 * verifier stays small with no unrolled caller tree and no rescan per
 * move. No fair.c helper is used and the queue order stays in kernel
 * priority queues for tiers plus FIFO for overflow.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one CPU may run one task through its mask. */
/* Live proven at entry, so mask alone gates here with no live branch. */
static __always_inline bool flow_mask_ok(s32 cpu,
	const struct task_struct *p)
{
	if (cpu < 0)
		return false;
	if (!p)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* One candidate with the shared mask gate plus move in one place. */
/* Gives one on move else zero with no state and one mask test. */
/* The shared probe gates the move with live proven by the caller, so a */
/* mismatched entry skips with no kernel error while mask still wins */
/* on drain. Tiers plus overflow share this one gate, so every skip is */
/* uniform. Callers add the result with no success branch, so the */
/* verifier keeps the loop small. Callers pass the loop iterator so */
/* the move stays in iterator context. */
static __always_inline u32 flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	if (cpu < 0)
		return 0;
	if (!p)
		return 0;
	if (!flow_mask_ok(cpu, p))
		return 0;
	return (u32)scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
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
	/* use, so a join racing the read still meets the next pass. */
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
