// SPDX-License-Identifier: GPL-2.0
/*
 * Park recycle for the dispatch pass.
 *
 * Pops ring heads in arrival order up to the batch bound. Each pop
 * resolves its owner with no cgroup walk, then lands local or
 * rotates. A throttled head or a masked out head rotates to the
 * tail with the phase stopped, so one unservable head never stalls
 * the ring and order churns only while blocked. The timer refill
 * plus kick retries throttled heads soon, and a compatible CPU
 * serves masked heads on its own pass with the arrival kick aimed
 * at allowed idle CPUs. Gone tasks drop their ring slot with no
 * node touch, since exit already freed the node. A queued task
 * means a stale ring pid from an earlier park, so the slot drops
 * with the live tree node left alone. Each phase takes scalars
 * only and verifies once. Runs under the caller RCU read lock
 * with no tree lock held here.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Park phase with narrow inputs. Returns the park moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
static __noinline u32 flow_phase_park(s32 cpu, u32 budget,
	u32 base)
{
	u32 moved = 0;
	u32 i;
	bpf_for(i, 0, FLOW_DISPATCH_BATCH) {
		u32 pid;
		struct task_struct *task;
		struct flow_task_ctx *tctx;
		bool cached;
		u64 cgid;
		if (moved + base >= budget)
			break;
		if (!flow_park_pop(&pid))
			break;
		task = bpf_task_from_pid((s32)pid);
		if (!task)
			continue;
		tctx = flow_lookup(task);
		if (!tctx) {
			bpf_task_release(task);
			continue;
		}
		/* A queued task means a stale ring pid from an earlier */
		/* park, since parks clear the flag at park time. */
		/* The live tree node serves the task, so the stale slot */
		/* drops with no insert and no stall. */
		if (READ_ONCE(tctx->queued) != 0) {
			bpf_task_release(task);
			continue;
		}
		cached = tctx->cached;
		cgid = tctx->cgid;
		/* A blocked head rotates with the phase stopped. */
		/* Throttled heads wait on the timer refill, and masked */
		/* heads wait on a compatible pass, so the rotation */
		/* never stalls servable tails for long. */
		if (flow_tree_throttled_scalar(cached, cgid) ||
		    !bpf_cpumask_test_cpu((u32)cpu,
		    task->cpus_ptr)) {
			flow_park_push(pid);
			bpf_task_release(task);
			break;
		}
		flow_local_insert(task, cpu, 0);
		bpf_task_release(task);
		moved++;
	}
	return moved;
}
