// SPDX-License-Identifier: GPL-2.0
/*
 * Priority fill for the dispatch pass.
 *
 * Moves up to budget tasks from the overflow tail in queue order in one
 * scan, so a deep tail pays one scan for sixteen moves with no rescan
 * per move. The overflow tail stays FIFO with plain inserts, so this
 * queue order step moves the remainder with best effort order there.
 * Past deep backlog the fill stops after four moves, so one pass never
 * burns sixteen scans on a deep tail while still draining with fail
 * open progress. The queue handle stays hoisted once at entry, so the
 * scan pays no DSQ lookup per step beyond the depth call. The budget
 * hoists the remaining dispatch slots once at entry through the caller,
 * so the fill shares one exact bound with no overfill. Live stays
 * proven once at entry through the dispatch gate, so the scan pays one
 * mask test per entry with no live branch. Runs noinline with scalar
 * CPU plus budget and a bounded scan, so the verifier stays small with
 * no unrolled caller tree and no rescan per move.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Priority fill with flood cap plus mask in one place. */
/* Gives the moved count up to budget with four past deep backlog, so */
/* a deep tail never burns sixteen scans in one pass. Noinline with */
/* scalar inputs so the single scan verifies once apart from the */
/* dispatch entry. */
static __noinline u32 flow_priq_fill(s32 cpu, u32 budget)
{
	u32 moved = 0;
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
	/* Single scan moves up to budget in queue order with no rescan */
	/* per move, so a deep tail pays one scan for sixteen moves. */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, ov, 0) {
		if ((u64)moved >= (u64)budget)
			break;
		/* Past deep backlog the fill stops after four moves, so */
		/* one pass never burns sixteen scans on a deep tail. */
		if ((u64)moved >= (u64)FLOW_DISPATCH_FLOOD_PROBES &&
		    qlen > (u64)FLOW_DISPATCH_FLOOD_QUEUED)
			break;
		if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p))
			moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}
