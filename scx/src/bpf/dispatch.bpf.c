// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains local plus node plus machine in priority order
 * with moves uncapped to remaining dispatch slots and visits capped
 * at sixty four per pass. The kernel keeps each priority queue list
 * in deadline order, so each tier takes the earliest matching
 * deadline with mask wins on drain and no BPF sort. EDF order via
 * kernel priority queue: the vtime key holds the fair time,
 * so the earliest deadline wins with no lag compensation. Each tier
 * skips unmatching heads uniformly through the shared move, so one
 * foreign task never stalls its tier for that pass. Visits cap at
 * sixty four per pass regardless of moves with leftover work resuming
 * next pass, so one pass never holds RCU across the whole queue on
 * mask misses while staying work conserving across passes.
 * The gate runs first for the CPU, then the remaining dispatch slots
 * bound the moves with no clamp, so every tier shares one exact move
 * bound with no overfill. The queue depth leaves at once per tier with
 * no RCU hold through the shared move, so idle tiers stay cheap. Static
 * tier order is local plus node plus machine with no reorder, so the
 * pass follows one fixed path. Per tier moves count once with no lock
 * through one exit, and the level follows after all moves with the
 * same CPU only, so idle cannot be skipped. No consumable slots leaves
 * at once with no scan, so idle stays cheap.
 * See intf.h for the visit cap plus the deadline helpers and
 * enqueue.bpf.c for the deadline choice with no admission bound.
 *
 * The pass splits across dispatch/failopen, drain, perf plus
 * helpers/finish with one RCU section per tier scan. The probe plus
 * move live in failopen, so tiers share one gate with no per tier
 * copy. Each scan stays noinline with scalar inputs plus a visit
 * capped loop, so the verifier stays small with no unrolled caller
 * tree, while the single task move plus the account stay inline so
 * the deepest path keeps its call frames small. No fair.c helper is
 * used and the queue order stays in kernel priority queues.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/failopen.bpf.c"
#include "dispatch/drain.bpf.c"
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
	u64 own_local;
	u32 node;
	u64 node_dsq;
	u64 machine_dsq;
	(void)prev;
	/* The gate runs first with no queue cost, so a stale CPU fails */
	/* closed at once. A negative CPU is an idle call with no work, so */
	/* it leaves with no count while only live rejects count. */
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu))) {
		flow_gate_reject();
		return;
	}
	/* Moves hoist the remaining dispatch slots once at entry with no */
	/* clamp, so every tier shares one exact move bound with no */
	/* overfill. No consumable slots leaves at once with no scan, so */
	/* idle stays cheap. */
	budget = scx_bpf_dispatch_nr_slots();
	if (unlikely(budget == 0))
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
	/* deadline moves at once within the per pass visit cap. The likely */
	/* busy tiers run first in static order with no reorder. */
	if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
		local_moved = flow_move_one(own_local, cpu, &visits);
		if (local_moved > left)
			local_moved = left;
		left -= local_moved;
	}
	/* Node tier next with no scan on empty. */
	if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
		node_moved = flow_move_one(node_dsq, cpu, &visits);
		if (node_moved > left)
			node_moved = left;
		left -= node_moved;
	}
	/* Machine tier next with no scan on empty. */
	if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
		machine_moved = flow_move_one(machine_dsq, cpu, &visits);
		if (machine_moved > left)
			machine_moved = left;
		left -= machine_moved;
	}
	flow_account_local(local_moved);
	flow_account_node(node_moved);
	flow_account_machine(machine_moved);
out:
	/* Level follows after all moves with the same CPU only through */
	/* one exit, so idle cannot be skipped and a steady level makes */
	/* no call through the cached compare. */
	flow_perf_update(cpu);
}
