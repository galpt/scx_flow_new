// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains in fixed order under one shared budget of 32
 * across five phases. The own deadline queue moves
 * first with the header cap, then one peer steal moves a single task,
 * then the kernel global plus the shared overflow tail with a
 * shared cap at 4, and last a gated starvation pass over overflow
 * when throttling. Visits plus moves plus skips share the budget
 * with a miss cap at 4 per trip and a steal bound at 8 peers, and
 * each phase adds its moves once with no lock. Throttled parks share the overflow tail with
 * mask wins on drain and a throttle recheck, so drained pools hold
 * tasks back with no bypass. Empty trips pay one queued read with no scan.
 * Steal never visits a peer deadline queue unless the local queue
 * drained empty, so a busy CPU keeps its own order. The SMT
 * sibling wins first, then the same cache domain, then a gated
 * cross domain move of a head that waited past 2ms. Donors hold
 * at least two, and stolen tasks pay no extra charge. See intf.h
 * for the caps and enqueue.bpf.c for the deadline choice.
 *
 * The pass splits across dispatch/drain, gated, steal, tail, and perf
 * files with one RCU section here. Each helper stays noinline
 * with scalar inputs and no duplicate walks, so the verifier
 * stays small. Level follows after the lock from queue depth
 * with no call on steady.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/drain.bpf.c"
#include "dispatch/gated.bpf.c"
#include "dispatch/steal.bpf.c"
#include "dispatch/tail.bpf.c"
#include "dispatch/perf.bpf.c"

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	/* Budget 32 bounds one pass with no stall. */
	/* One RCU read section covers every phase, so the lock */
	/* pairs collapse to one with no nesting. Phases take */
	/* scalars only and verify once with no cross inline. */
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 global_moved = 0;
	u64 own_vtime;
	u64 over;
	u64 limited;
	u32 tail_lim;
	u32 got;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	own_vtime = flow_vtime_dsq((u32)cpu);
	over = flow_overflow_dsq();
	limited = flow_load_limited();
	bpf_rcu_read_lock();
	got = flow_phase_own(cpu, own_vtime, budget, moved);
	moved += got;
	got = flow_phase_steal(cpu, own_vtime, budget, moved);
	moved += got;
	tail_lim = moved + flow_tail_cap(budget);
	if (tail_lim > budget)
		tail_lim = budget;
	got = flow_phase_global(cpu, tail_lim, moved);
	moved += got;
	global_moved += got;
	got = flow_phase_overflow(cpu, over, tail_lim, moved,
	    limited);
	moved += got;
	over_moved += got;
	got = flow_phase_gated(cpu, over, budget, moved, limited);
	moved += got;
	over_moved += got;
	bpf_rcu_read_unlock();
	/* Level follows after the lock with the same CPU only. */
	flow_perf_update(cpu);
	if (moved != 0)
		__sync_fetch_and_add(&flow_stats.slot_moves,
		    (u64)moved);
	if (over_moved != 0)
		__sync_fetch_and_add(&flow_stats.park_moves,
		    (u64)over_moved);
	if (global_moved != 0)
		__sync_fetch_and_add(&flow_stats.global_moves,
		    (u64)global_moved);
}
