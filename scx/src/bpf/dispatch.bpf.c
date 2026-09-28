// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains in fixed order. The deadline tree moves first
 * in key order, then the park ring recycles in arrival order, then
 * the kernel global queue drains homeless tasks. One batch bounds
 * the whole pass with no per queue caps, so a deep tree cannot
 * starve parks and a deep park cannot starve homeless tasks. Empty
 * trips pay one head read with no scan. Throttled pops park with
 * the timer re-armed, and the park phase rotates blocked heads with
 * the phase stopped, so drained pools hold tasks back with no
 * bypass and no head spin. Rotation cycles depth across passes, so
 * one blocked head paces one pass only with the next pass serving
 * past it. See intf.h for the batch and
 * enqueue.bpf.c for the key choice.
 *
 * The pass splits across dispatch/tree, park, and global files
 * with one RCU section here. Each helper stays noinline with
 * scalar inputs and no duplicate walks, so the verifier stays
 * small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/tree.bpf.c"
#include "dispatch/park.bpf.c"
#include "dispatch/global.bpf.c"

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	/* Batch 16 bounds one pass with no stall. */
	/* One RCU read section covers every phase, so the lock */
	/* pairs collapse to one with no nesting. Phases take */
	/* scalars only and verify once with no cross inline. */
	u32 budget = (u32)FLOW_DISPATCH_BATCH;
	u32 moved = 0;
	u32 got;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	bpf_rcu_read_lock();
	got = flow_phase_tree(cpu, budget, moved);
	moved += got;
	if (moved != 0)
		__sync_fetch_and_add(&flow_stats.tree_moves,
		    (u64)got);
	got = flow_phase_park(cpu, budget, moved);
	moved += got;
	if (got != 0)
		__sync_fetch_and_add(&flow_stats.park_moves,
		    (u64)got);
	got = flow_phase_global(cpu, budget, moved);
	moved += got;
	if (got != 0)
		__sync_fetch_and_add(&flow_stats.global_moves,
		    (u64)got);
	bpf_rcu_read_unlock();
}
