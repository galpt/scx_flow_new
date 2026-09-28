// SPDX-License-Identifier: GPL-2.0
/*
 * Park recycle for the dispatch pass.
 *
 * Pops one ring head in arrival order per pass. The pop resolves
 * its owner with no cgroup walk, then lands local or rotates. A
 * parked mark gates the serve, so a stale ring pid from an earlier
 * park drops with the live tree node left alone. A blocked head
 * rotates to the tail with the pass spent, so one unservable head
 * never spins the pass and the rotation keeps depth cycling
 * across dispatches. Throttled heads wait on the timer refill,
 * and masked heads wait on a compatible pass with the arrival kick
 * aimed at allowed idle CPUs. Gone tasks drop their ring slot with
 * no node touch, since exit already freed the node. One head keeps
 * the jump sequences small enough to load. Each phase takes scalars
 * only and verifies once. Runs under the caller RCU read lock with
 * no tree lock held here.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Park phase with narrow inputs. Returns the park moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
/* Serves one head per pass with no loop, so the jump chains stay */
/* short enough to load. A blocked head rotates with the pass */
/* spent, and the next pass serves past it with monotonic progress. */
static __noinline u32 flow_phase_park(s32 cpu, u32 budget,
	u32 base)
{
	u32 pid;
	struct task_struct *task;
	struct flow_task_ctx *tctx;
	bool cached;
	u64 cgid;
	if (base >= budget)
		return 0;
	if (!flow_park_pop(&pid))
		return 0;
	task = bpf_task_from_pid((s32)pid);
	if (!task)
		return 0;
	tctx = flow_lookup(task);
	if (!tctx) {
		bpf_task_release(task);
		return 0;
	}
	/* Only parked members serve here. A stale ring pid */
	/* from an earlier park drops with no insert, since */
	/* the live tree node owns the task. */
	if (READ_ONCE(tctx->queued) != 2) {
		bpf_task_release(task);
		return 0;
	}
	cached = tctx->cached;
	cgid = tctx->cgid;
	/* A blocked head rotates with the pass spent. */
	/* The pop freed exactly one slot, so the push finds room */
	/* with no fail open past it. */
	if (flow_tree_throttled_scalar(cached, cgid) ||
	    !bpf_cpumask_test_cpu((u32)cpu,
	    task->cpus_ptr)) {
		flow_park_push(pid);
		bpf_task_release(task);
		return 0;
	}
	WRITE_ONCE(tctx->queued, (u8)0);
	flow_local_insert(task, cpu, 0);
	bpf_task_release(task);
	return 1;
}
