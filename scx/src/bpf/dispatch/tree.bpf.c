// SPDX-License-Identifier: GPL-2.0
/*
 * Tree drain for the dispatch pass.
 *
 * Visits at most 4 heads in deadline order with a short loop, so the
 * jump chains stay small enough to load. Each visit pops a fresh
 * head with no reexamine, then resolves its owner past the unlock
 * with no cgroup walk, then lands local, parks, or reaps. The floor
 * advances only for a live pop past validation with a monotonic
 * max, so dead reaps never inflate later clamps. Mask mismatches
 * park in the ring for a later pass with one mismatch count each,
 * and mask only parks kick one idle allowed CPU, while a set
 * throttle flag parks too with the timer re-armed, so drained pools
 * hold tasks back with no bypass. A cold cache or a missing leaf
 * moves fail open, so a move while parked costs one slice at most.
 * Gone tasks, cleared queue flags, and sequence mismatches from pid
 * reuse reap with the entry dropped only when the slot sits empty,
 * so a live replacement node never frees. A full ring fails open to
 * global with the node reaped, so no pass spins with mask wins on
 * the global drain. Visits plus moves plus skips share the batch,
 * so the pass ends early once the sum meets the bound. CPUs
 * re-dispatch as they consume, so order holds globally with the
 * tree staying the single source despite four heads per pass. Runs
 * under the caller RCU read lock with the tree lock taken per pop
 * only.
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
/* Visits at most 4 heads per pass with no reexamine, so the jump */
/* chains stay short enough to load. The floor moves only for live */
/* heads past validation with a monotonic max, so live order sets */
/* later clamps. A dead head reaps and the visit moves to the next */
/* head, and a live head lands local or parks with the visit spent. */
/* Mask parks count one mismatch each with one idle kick for mask */
/* only parks, and a full ring fails open to global. Visits plus */
/* moves plus skips share the batch with an early exit, so 4 plus */
/* 4 plus 4 stays under 16 across all phases. */
static __noinline u32 flow_phase_tree(s32 cpu, u32 budget,
	u32 base)
{
	u32 moved = 0;
	u32 seen = 0;
	u32 skips = 0;
	u32 i;
	if (base >= budget)
		return 0;
	bpf_for(i, 0, FLOW_SKIP_BOUND) {
		struct flow_node *node;
		struct task_struct *task;
		struct flow_task_ctx *tctx;
		u32 pid;
		bool cached;
		u64 cgid;
		bool throttled;
		bool allowed;
		u64 floor;
		if (base + moved + seen + skips >= budget)
			break;
		node = flow_tree_pop();
		if (!node)
			break;
		seen++;
		pid = node->pid;
		task = bpf_task_from_pid((s32)pid);
		if (!task) {
			flow_tree_reap(pid, node);
			skips++;
			continue;
		}
		tctx = flow_lookup(task);
		if (!tctx || READ_ONCE(tctx->queued) != 1 ||
		    READ_ONCE(tctx->seq) != node->seq) {
			bpf_task_release(task);
			flow_tree_reap(pid, node);
			skips++;
			continue;
		}
		floor = READ_ONCE(flow_floor);
		if (flow_time_before(floor, node->deadline))
			WRITE_ONCE(flow_floor, node->deadline);
		cached = tctx->cached;
		cgid = tctx->cgid;
		throttled = flow_tree_throttled_scalar(cached, cgid);
		allowed = bpf_cpumask_test_cpu((u32)cpu,
		    task->cpus_ptr);
		if (!allowed || throttled) {
			/* A full ring fails open to global with the node reaped, */
			/* so no pass spins and no task stalls. The ring holds */
			/* 4096 parks, so full is exceptional with mask wins on */
			/* the global drain for the overflow. */
			WRITE_ONCE(tctx->queued, (u8)0);
			if (!allowed)
				__sync_fetch_and_add(
				    &flow_stats.mask_mismatch, 1);
			if (!flow_park_push(pid)) {
				flow_tree_reap(pid, node);
				flow_global_insert(task);
				bpf_task_release(task);
				skips++;
				continue;
			}
			flow_tree_give(pid, node);
			WRITE_ONCE(tctx->queued, (u8)2);
			__sync_fetch_and_add(&flow_stats.parked,
			    1);
			/* Mask only parks kick one idle allowed CPU with */
			/* no preempt, so a compatible pass wakes at once. */
			/* Throttled parks wait on the timer refill instead. */
			if (!throttled && !allowed) {
				s32 sel = task->scx.selected_cpu;
				flow_kick_idle_allowed(task, sel);
			}
			bpf_task_release(task);
			skips++;
			continue;
		}
		WRITE_ONCE(tctx->queued, (u8)0);
		flow_tree_give(pid, node);
		flow_local_insert(task, cpu, 0);
		bpf_task_release(task);
		moved++;
	}
	return moved;
}
