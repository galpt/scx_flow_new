// SPDX-License-Identifier: GPL-2.0
/*
 * Tree drain for the dispatch pass.
 *
 * Pops head nodes first in deadline order up to the batch bound.
 * Each pop resolves its owner past the unlock with no cgroup walk,
 * then lands local, parks, or reaps. Mask mismatches park in the
 * ring for a later pass, and a set throttle flag parks too with
 * the timer re-armed, so drained pools hold tasks back with no
 * bypass. A cold cache or a missing leaf moves fail open, so a
 * move while parked costs one slice at most. Gone tasks, cleared
 * queue flags, and sequence mismatches from pid reuse reap with
 * the entry dropped only when the slot sits empty, so a live
 * replacement node never frees. A full ring re-trees the node
 * with the same key and stops the phase, so no pass spins. Runs
 * under the caller RCU read lock with the tree lock taken per
 * pop only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one popped task still gates on its leaf flag. */
/* Takes cached plus id scalars with no struct pass, so the caller */
/* stays small and the check verifies once. A flagged hit re-arms */
/* the timer flag for the next tick. */
static __noinline bool flow_tree_throttled_scalar(bool cached,
	u64 cgid)
{
	struct flow_cgrp_ctx *e;

	if (!cached)
		return false;
	e = flow_cgrp(cgid);
	if (!e)
		return false;
	if (!(flow_load_flags(e) & (u32)FLOW_CGRP_THROTTLED))
		return false;
	__sync_lock_test_and_set(&flow_bw_pending, 1);
	return true;
}

/* Reap one popped node with entry drop when the slot sits empty. */
/* A non null slot means a fresher node arrived for the pid, so the */
/* popped node drops with the live one kept. Runs with no lock. */
static __noinline void flow_tree_reap(u32 pid,
	struct flow_node *node)
{
	struct flow_stash *stash;
	bool drop_entry = true;
	if (!node)
		return;
	stash = flow_stash_lookup(pid);
	if (stash && READ_ONCE(stash->node) != NULL)
		drop_entry = false;
	if (drop_entry)
		bpf_map_delete_elem(&node_stor, &pid);
	bpf_obj_drop(node);
}

/* Tree phase with narrow inputs. Returns the tree moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
/* Pops one head per pass with no loop, so the jump chains stay */
/* short enough to load. A dead head reaps with the pass spent, */
/* and the next pass pops the next head with monotonic progress. */
/* A live head lands local, parks, or re-trees with the pass */
/* spent. CPUs re-dispatch as they consume, so order holds */
/* globally with the tree staying the single source. */
static __noinline u32 flow_phase_tree(s32 cpu, u32 budget,
	u32 base)
{
	struct flow_node *node;
	struct task_struct *task;
	struct flow_task_ctx *tctx;
	u32 pid;
	bool cached;
	u64 cgid;
	if (base >= budget)
		return 0;
	node = flow_tree_pop();
	if (!node)
		return 0;
	pid = node->pid;
	task = bpf_task_from_pid((s32)pid);
	if (!task) {
		flow_tree_reap(pid, node);
		return 0;
	}
	tctx = flow_lookup(task);
	if (!tctx || READ_ONCE(tctx->queued) != 1 ||
	    READ_ONCE(tctx->seq) != node->seq) {
		bpf_task_release(task);
		flow_tree_reap(pid, node);
		return 0;
	}
	cached = tctx->cached;
	cgid = tctx->cgid;
	if (!bpf_cpumask_test_cpu((u32)cpu,
	    task->cpus_ptr) ||
	    flow_tree_throttled_scalar(cached, cgid)) {
		/* A full ring re-trees with the same key, so */
		/* order holds with no spin and the node never */
		/* touches the stash mid flight. */
		WRITE_ONCE(tctx->queued, (u8)0);
		if (!flow_park_push(pid)) {
			bpf_spin_lock(&edf_lock);
			bpf_rbtree_add(&edf_tree, &node->rb,
			    flow_edf_less_cb);
			WRITE_ONCE(tctx->queued, (u8)1);
			bpf_spin_unlock(&edf_lock);
			bpf_task_release(task);
			return 0;
		}
		flow_tree_give(pid, node);
		WRITE_ONCE(tctx->queued, (u8)2);
		__sync_fetch_and_add(&flow_stats.parked,
		    1);
		bpf_task_release(task);
		return 0;
	}
	WRITE_ONCE(tctx->queued, (u8)0);
	flow_tree_give(pid, node);
	flow_local_insert(task, cpu, 0);
	bpf_task_release(task);
	return 1;
}
