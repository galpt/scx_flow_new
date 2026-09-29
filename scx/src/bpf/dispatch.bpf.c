// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains in two tiers under one shared budget of 16. The
 * local queue moves first with the local cap, then one shared queue
 * moves with its own cap under the same budget. The shared pick
 * rotates across node plus machine plus overflow plus global from a
 * cursor and takes the first queued member, so every pass serves
 * local plus one shared queue with no five loop pileup. Visits plus
 * moves plus skips share the budget with a miss cap at 3 per trip,
 * and each tier adds its moves once with no lock. Overflow parks move
 * only past the backstop interval, so fresh parks keep order while
 * old parks surface. Homeless tasks move fail open with mask wins on
 * the global turn only. Empty trips pay one queued read with no scan.
 * One RCU read section covers both tiers, so the lock pairs collapse
 * to one with no nesting. See intf.h for the caps and enqueue.bpf.c
 * for admission plus the deadline choice.
 *
 * The pass splits the tier drains into dispatch/drain.bpf.c with one
 * RCU section here. Each drain stays noinline with scalar inputs, so
 * the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/drain.bpf.c"

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	/* Budget 16 bounds one pass with no stall. */
	/* One RCU read section covers both tiers, so the lock */
	/* pairs collapse to one with no nesting. Tiers take */
	/* scalars only and verify once with no cross inline. */
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 local_moved = 0;
	u32 node_moved = 0;
	u32 machine_moved = 0;
	u32 over_moved = 0;
	u32 global_moved = 0;
	u64 own_local;
	u32 node;
	u32 lim;
	u32 got;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	own_local = flow_local_dsq((u32)cpu);
	node = flow_cpu_node((u32)cpu);
	if (node >= (u32)FLOW_MAX_NODES)
		node = 0;
	bpf_rcu_read_lock();
	/* Local tier first with the local cap. */
	/* An empty queue exits the loop at once with no scan. */
	lim = moved + flow_local_cap(budget);
	if (lim > budget)
		lim = budget;
	got = flow_drain_gated(cpu, own_local, lim, moved, false);
	moved += got;
	local_moved += got;
	/* Shared tier next with one rotating queued member. */
	/* The rotor walks node plus machine plus overflow plus global */
	/* from the cursor and takes the first queued member with its */
	/* own cap, so every pass pairs local with one shared queue. */
	/* The cursor advances on a hit only, so an empty round keeps */
	/* the same start with no hotspot move. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 rotor = st ? READ_ONCE(st->cursor) % 4U : 0;
		u32 i;
		u32 hit = 0xffffffffU;
		u64 dsq = 0;
		u32 cap = 0;
		bool backstop = false;
		bool homeless = false;
		bpf_for(i, 0, 4) {
			u32 turn = (rotor + i) % 4U;
			u64 cand = 0;
			u32 ccap = 0;
			bool cback = false;
			bool chome = false;
			if (turn == 0) {
				cand = flow_node_dsq(node);
				ccap = flow_node_cap(budget);
			} else if (turn == 1) {
				cand = flow_machine_dsq();
				ccap = flow_machine_cap(budget);
			} else if (turn == 2) {
				cand = flow_overflow_dsq();
				ccap = flow_over_cap(budget);
				cback = true;
			} else {
				cand = (u64)SCX_DSQ_GLOBAL;
				ccap = budget;
				chome = true;
			}
			if (scx_bpf_dsq_nr_queued(cand) == 0)
				continue;
			hit = turn;
			dsq = cand;
			cap = ccap;
			backstop = cback;
			homeless = chome;
			break;
		}
		if (hit != 0xffffffffU) {
			if (st)
				__sync_lock_test_and_set(&st->cursor,
				    (rotor + 1U) % 4U);
			lim = moved + cap;
			if (lim > budget)
				lim = budget;
			if (homeless) {
				got = flow_drain_global(cpu, lim,
				    moved);
				moved += got;
				global_moved += got;
			} else {
				got = flow_drain_gated(cpu, dsq, lim,
				    moved, backstop);
				moved += got;
				if (hit == 0)
					node_moved += got;
				else if (hit == 1)
					machine_moved += got;
				else
					over_moved += got;
			}
		}
	}
	bpf_rcu_read_unlock();
	if (local_moved != 0)
		__sync_fetch_and_add(&flow_stats.local_moves,
		    (u64)local_moved);
	if (node_moved != 0)
		__sync_fetch_and_add(&flow_stats.node_moves,
		    (u64)node_moved);
	if (machine_moved != 0)
		__sync_fetch_and_add(&flow_stats.machine_moves,
		    (u64)machine_moved);
	if (over_moved != 0)
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)over_moved);
	if (global_moved != 0)
		__sync_fetch_and_add(&flow_stats.global_moves,
		    (u64)global_moved);
}
