// SPDX-License-Identifier: GPL-2.0
/*
 * Overflow fill for the dispatch pass.
 *
 * Moves up to budget tasks from the overflow tail in queue order in one
 * scan, so a deep tail pays one scan for sixteen moves with no rescan
 * per move. The overflow tail stays FIFO with plain inserts, so this
 * queue order step moves the remainder with best effort order there.
 * Past deep backlog the fill stops after four moves, and every pass
 * stops after thirty two visited entries regardless of moves, so one
 * pass never burns sixteen scans on a deep tail and never walks the
 * whole queue on mask misses while still draining with fail open
 * progress. The queue handle plus the flood bound stay hoisted once
 * at entry, so the scan pays no DSQ lookup and no per step depth test
 * beyond the two breaks. Live stays proven once at entry through the
 * dispatch gate, so the scan pays no live branch. The kernel gates
 * affinity on the move with no BPF mask test, so a mismatched entry
 * skips with no extra branch while mask still wins on drain. Unlike
 * the priority tiers that block on an unmatching head, this scan
 * skips unmatching entries, so one foreign task never stalls live
 * work. Runs noinline with scalar CPU plus budget and a bounded scan,
 * so the verifier stays small with no unrolled caller tree and no
 * rescan per move.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Overflow fill with flood cap plus step cap plus move in one place. */
/* Gives the moved count up to budget with four past deep backlog and */
/* thirty two visited entries at most, so a deep tail never burns */
/* sixteen scans in one pass and a miss heavy tail never walks the */
/* whole queue under RCU. Noinline with scalar inputs so the single */
/* scan verifies once apart from the dispatch entry. */
static __noinline u32 flow_overflow_fill(s32 cpu, u32 budget)
{
	u32 moved = 0;
	u32 steps = 0;
	u32 limit;
	u64 ov;
	u64 qlen;
	struct task_struct *p;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	/* Queue handle stays hoisted, so the scan pays no DSQ lookup. */
	ov = flow_overflow_dsq();
	qlen = (u64)scx_bpf_dsq_nr_queued(ov);
	if (qlen == 0)
		return 0;
	/* Flood bound hoists out of the scan, so the loop holds two */
	/* breaks only with no per step queue depth test. Past deep */
	/* backlog the move bound drops to four, else it stays at budget. */
	limit = budget;
	if (qlen > (u64)FLOW_DISPATCH_FLOOD_QUEUED &&
	    limit > (u32)FLOW_DISPATCH_FLOOD_PROBES)
		limit = (u32)FLOW_DISPATCH_FLOOD_PROBES;
	/* Single scan moves up to budget in queue order with no rescan */
	/* per move, so a deep tail pays one scan for sixteen moves. */
	/* The move adds with no success branch and the kernel gates */
	/* affinity, so mask misses skip with no extra verifier state. */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, ov, 0) {
		/* Every pass stops after thirty two visited entries */
		/* regardless of moves, so a mask miss walk never holds */
		/* RCU across the whole queue while moved progress stays. */
		if (steps >= (u32)FLOW_DISPATCH_SCAN_STEPS)
			break;
		steps++;
		if (moved >= limit)
			break;
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
