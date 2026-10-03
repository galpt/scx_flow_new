// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains local plus node plus machine in priority order
 * plus overflow in queue order with moves uncapped to remaining
 * dispatch slots and visits capped at sixty four per pass. The kernel
 * keeps each priority queue list in deadline order, so each tier takes
 * the earliest matching deadline with mask wins on drain and no BPF
 * sort. EDF order via kernel priority queue: the vtime key holds the
 * absolute deadline, so the earliest deadline wins with no lag
 * compensation. Each tier skips unmatching heads uniformly through
 * the shared move, so one foreign task never stalls its tier for that
 * pass. The overflow tail stays FIFO with one single scan and mask
 * wins on drain, so stale work never stalls live work since the scan
 * skips unmatching entries through the shared BPF mask gate. Visits
 * cap at sixty four per pass regardless of moves with leftover work
 * resuming next pass, so one pass never holds RCU across the whole
 * queue on mask misses while staying work conserving across passes.
 * The gate runs first for the CPU, then the remaining dispatch slots
 * bound the moves with no clamp, so every tier shares one exact move
 * bound with no overfill. The queue depth leaves at once per tier with
 * no RCU hold through the shared move, so idle tiers stay cheap. Static
 * tier order is local plus node plus machine plus overflow with no
 * reorder, so the pass follows one fixed path. Per tier moves count
 * once with no lock through one exit, and the level follows after all
 * moves with the same CPU only, so idle cannot be skipped. No
 * consumable slots leaves at once with no scan, so idle stays cheap.
 * See intf.h for the visit cap plus the deadline helpers and
 * enqueue.bpf.c for the deadline choice with no admission bound.
 *
 * The pass splits across dispatch/probes, drain, failopen, perf plus
 * helpers/move plus helpers/finish with one RCU section per tier scan
 * plus the single overflow scan. Each scan stays noinline with scalar
 * inputs plus a visit capped loop, so the verifier stays small with no
 * unrolled caller tree, while the single task move plus the account
 * stay inline so the deepest path keeps its call frames small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/probes.bpf.c"
#include "helpers/move.bpf.c"
#include "dispatch/drain.bpf.c"
#include "dispatch/failopen.bpf.c"
#include "helpers/finish.bpf.c"
#include "dispatch/perf.bpf.c"

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget;
	u32 left;
	u32 visits = 0;
	u32 local_moved = 0;
	u32 node_moved = 0;
	u32 machine_moved = 0;
	u32 over_moved = 0;
	u64 own_local;
	u32 node;
	u64 node_dsq;
	u64 machine_dsq;
	(void)prev;
	/* A negative CPU is a core idle call with no queue work, so it */
	/* returns with no gate count. A stale live CPU fails closed with */
	/* one count below, so only real rejects count. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	/* Moves hoist the remaining dispatch slots once at entry with no */
	/* clamp, so every tier shares one exact move bound with no */
	/* overfill. No consumable slots leaves at once with no scan, so */
	/* idle stays cheap. */
	budget = scx_bpf_dispatch_nr_slots();
	if (budget == 0)
		goto out;
	/* Handles stay hoisted once at entry, so pops pay no extra lookup. */
	own_local = flow_local_dsq((u32)cpu);
	node = flow_cpu_node((u32)cpu);
	/* Fold past the derived count to zero like enqueue, so the node */
	/* turn always names a created queue with no stale id. */
	if (node >= (u32)FLOW_MAX_NODES ||
	    (u64)node >= nr_node_ids)
		node = 0;
	node_dsq = flow_node_dsq(node);
	machine_dsq = flow_machine_dsq();
	left = budget;
	/* Local tier first with no scan on empty. The kernel holds */
	/* deadline order plus mask wins, so the earliest matching */
	/* deadline moves at once within the per pass visit cap. */
	if (left && visits < (u32)FLOW_DISPATCH_MAX_VISIT) {
		local_moved = flow_move_one(own_local, cpu, &visits);
		if (local_moved > left)
			local_moved = left;
		left -= local_moved;
	}
	/* Node tier next with no scan on empty. */
	if (left && visits < (u32)FLOW_DISPATCH_MAX_VISIT) {
		node_moved = flow_move_one(node_dsq, cpu, &visits);
		if (node_moved > left)
			node_moved = left;
		left -= node_moved;
	}
	/* Machine tier next with no scan on empty. */
	if (left && visits < (u32)FLOW_DISPATCH_MAX_VISIT) {
		machine_moved = flow_move_one(machine_dsq, cpu, &visits);
		if (machine_moved > left)
			machine_moved = left;
		left -= machine_moved;
	}
	/* Overflow tail last with one single scan and no scan on empty. */
	/* Homeless parks move here with all other parks FIFO, so the */
	/* kernel global queue stays out of the pass. Moves stay uncapped */
	/* to remaining slots with visits capped per pass, so a deep tail */
	/* never holds RCU across the whole queue while leftover work */
	/* resumes next pass. Tiers plus overflow share the mask gate */
	/* through the shared move. */
	if (left && visits < (u32)FLOW_DISPATCH_MAX_VISIT)
		over_moved = flow_overflow_fill(cpu, left, &visits);
	flow_account_local(local_moved);
	flow_account_node(node_moved);
	flow_account_machine(machine_moved);
	flow_account_over(over_moved);
out:
	/* Level follows after all moves with the same CPU only through */
	/* one exit, so idle cannot be skipped and a steady level makes */
	/* no call. */
	flow_perf_update(cpu);
}
