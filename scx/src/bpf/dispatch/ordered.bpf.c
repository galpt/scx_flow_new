// SPDX-License-Identifier: GPL-2.0
/*
 * Ordered fill for the dispatch pass.
 *
 * Moves admitted tasks in global deadline order up to sixteen per
 * pass with no sequence gate and no CPU gate. Each move picks the
 * least key then deadline then owned then pid among entries the
 * dispatch CPU may run. The queue handle stays hoisted once at
 * entry, so the loop pays no dsq lookup per step beyond the depth
 * call. Past one hundred twenty eight queued ordered stops after
 * four moves with FIFO covering the remainder to sixteen, so a deep
 * tail never burns sixteen double scans in one pass. A recheck miss
 * ends ordered and falls to FIFO below, so one stale pick never
 * burns extra scans. Drops run at teardown, so the hot path keeps
 * no deletes. Runs noinline with scalar CPU and a bounded loop so
 * the verifier stays small with no unrolled caller tree.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Ordered moves with flood gate plus miss exit in one place. */
/* Gives the ordered count up to sixteen with four past deep backlog, */
/* so the caller drains the remainder FIFO within sixteen. Noinline */
/* with scalar input so the sixteen step loop verifies once apart */
/* from the dispatch entry. */
static __noinline u32 flow_ordered_fill(s32 cpu)
{
	u32 moved = 0;
	u64 ov;
	int i;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	/* Queue handle stays hoisted, so each step reads depth with no */
	/* dsq lookup. Flood plus miss break early with no nested takes, */
	/* so the verifier walks one flat chain per step. */
	ov = flow_overflow_dsq();
	bpf_for(i, 0, FLOW_DISPATCH_MAX_BATCH) {
		u64 qlen;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		qlen = scx_bpf_dsq_nr_queued(ov);
		if (qlen == 0)
			break;
		/* Past deep backlog ordered stops after four moves with */
		/* FIFO covering the remainder below, so one pass never */
		/* burns sixteen double scans on a deep tail while still */
		/* draining sixteen with ordered first. */
		if (flow_flood_stop(moved, qlen))
			break;
		/* A recheck miss ends ordered and falls to FIFO below, */
		/* so one stale pick never burns extra scans. */
		if (!veb_consume_best(cpu))
			break;
		moved++;
	}
	return moved;
}
