// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains local plus node plus machine with one pop each in
 * priority order plus overflow with one single scan in queue order up
 * to sixteen with no shared math. The kernel keeps each priority queue
 * list in deadline order, so each pop takes the earliest deadline with
 * mask wins on drain and no BPF sort. A pop blocks on an unmatching
 * head, so one foreign task can stall its tier for that pass. The
 * overflow tail stays FIFO with one single scan and mask wins on
 * drain, so stale work never stalls live work since the scan skips
 * unmatching entries through the BPF mask gate. Past deep backlog
 * the single scan stops after four moves and after thirty two visited
 * entries regardless of moves, so one pass never burns sixteen scans
 * on a deep tail and never walks the whole queue on mask misses. The budget
 * hoists the remaining dispatch slots once at entry, so every tier
 * shares one exact bound with no overfill. Per tier moves count once
 * with no lock through one exit, and the level follows after all moves
 * with the same CPU only, so idle cannot be skipped. An empty queue
 * leaves at once with no scan, so idle stays cheap. See intf.h for the
 * batch plus flood plus step cap and enqueue.bpf.c for admission plus
 * the deadline choice.
 *
 * The pass splits across dispatch/probes, drain, failopen, perf plus
 * helpers/move plus helpers/finish with one RCU section in the single
 * scan. The single scan stays noinline with scalar inputs and a bounded
 * loop, so the verifier stays small with no unrolled caller tree, while
 * the single task move plus the account stay inline so the deepest path
 * keeps its call frames small.
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
	/* Budget hoists the remaining dispatch slots once at entry, so */
	/* every tier shares one exact bound with no overfill. */
	budget = scx_bpf_dispatch_nr_slots();
	if (budget == 0)
		goto out;
	if (budget > (u32)FLOW_DISPATCH_MAX_BATCH)
		budget = (u32)FLOW_DISPATCH_MAX_BATCH;
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
	/* Local tier first with one pop and no scan on empty. The kernel */
	/* holds deadline order plus mask wins, so the head moves at once. */
	if (left) {
		local_moved = flow_move_one(own_local, cpu);
		if (local_moved > left)
			local_moved = left;
		left -= local_moved;
	}
	/* Node tier next with one pop and no scan on empty. */
	if (left) {
		node_moved = flow_move_one(node_dsq, cpu);
		if (node_moved > left)
			node_moved = left;
		left -= node_moved;
	}
	/* Machine tier next with one pop and no scan on empty. */
	if (left) {
		machine_moved = flow_move_one(machine_dsq, cpu);
		if (machine_moved > left)
			machine_moved = left;
		left -= machine_moved;
	}
	/* Overflow tail last with one single scan and no scan on empty. */
	/* Homeless parks move here with all other parks FIFO, so the */
	/* kernel global queue stays out of the pass. Past deep backlog */
	/* the scan stops after four moves and after thirty two visited */
	/* entries regardless of moves, so a deep tail never burns */
	/* sixteen scans at once and a miss heavy tail never walks the */
	/* whole queue under RCU. Unlike the priority pops that block on */
	/* an unmatching head, this scan skips unmatching entries through */
	/* the BPF mask gate. */
	if (left)
		over_moved = flow_overflow_fill(cpu, left);
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
