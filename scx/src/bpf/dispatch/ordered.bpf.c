// SPDX-License-Identifier: GPL-2.0
/*
 * Ordered fill for the dispatch pass.
 *
 * Moves every parked task in global deadline order up to sixteen per
 * pass with no sequence gate and no CPU gate. Each move picks the
 * least key then deadline then owned then pid among entries the
 * dispatch CPU may run, so admits sort before top key rejects while
 * rejects still drain ordered last. The queue handle stays hoisted
 * once at entry, so the loop pays no dsq lookup per step beyond the
 * depth call. A recheck miss ends ordered and falls to the empty or
 * corrupt fallback below, so one stale pick never burns extra scans.
 * Drops run at teardown, so the hot path keeps no deletes. Runs
 * noinline with scalar CPU and a bounded loop so the verifier stays
 * small with no unrolled caller tree.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Ordered moves to the batch bound in one place. */
/* Gives the ordered count up to sixteen, so the caller keeps the */
/* remainder solely for the empty or corrupt fallback within sixteen. */
/* Noinline with scalar input so the sixteen step loop verifies once */
/* apart from the dispatch entry. */
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
	/* dsq lookup. A miss breaks early with no nested takes, so the */
	/* verifier walks one flat chain per step. */
	ov = flow_overflow_dsq();
	bpf_for(i, 0, FLOW_DISPATCH_MAX_BATCH) {
		u64 qlen;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		qlen = scx_bpf_dsq_nr_queued(ov);
		if (qlen == 0)
			break;
		/* A recheck miss ends ordered and falls to the fallback */
		/* below, so one stale pick never burns extra scans while */
		/* still draining sixteen ordered when live work remains. */
		if (!veb_consume_best(cpu))
			break;
		moved++;
	}
	return moved;
}
