// SPDX-License-Identifier: GPL-2.0
/*
 * Park recycle for the dispatch pass.
 *
 * Pops at most 4 ring heads in arrival order per pass. Each pop
 * resolves its owner with no cgroup walk, then lands local or
 * rotates. A parked mark gates the serve, so a stale ring pid from
 * an earlier park drops with the live tree node left alone. Each
 * visit pops a fresh head with no reexamine, and a blocked head
 * rotates to the tail with the visit spent, so one unservable head
 * never spins the pass and the rotation keeps depth cycling
 * across dispatches. Mask only rotates kick one idle allowed CPU
 * with no preempt, so a compatible pass wakes at once, while
 * throttled heads wait on the timer refill. Pinned heads kick too
 * when their single CPU idles. Gone tasks drop their ring slot with
 * no node touch, since exit already freed the node. Visits plus
 * moves plus skips share the batch with an early exit. Each phase
 * takes scalars only and verifies once. Runs under the caller RCU
 * read lock with no tree lock held here.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Park phase with narrow inputs. Returns the park moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
/* Serves at most 4 heads per pass with a short loop, so the jump */
/* chains stay short enough to load. A blocked head rotates with */
/* the visit spent, and the next visit serves past it with */
/* monotonic progress. Mask only rotates kick one idle allowed CPU */
/* with no preempt, and throttled heads wait on the timer. */
static __noinline u32 flow_phase_park(s32 cpu, u32 budget,
	u32 base)
{
	u32 moved = 0;
	u32 seen = 0;
	u32 skips = 0;
	u32 i;
	if (base >= budget)
		return 0;
	bpf_for(i, 0, FLOW_PARK_BATCH) {
		u32 pid;
		struct task_struct *task;
		struct flow_task_ctx *tctx;
		bool cached;
		u64 cgid;
		bool throttled;
		bool allowed;
		if (base + moved + seen + skips >= budget)
			break;
		if (!flow_park_pop(&pid))
			break;
		seen++;
		task = bpf_task_from_pid((s32)pid);
		if (!task) {
			skips++;
			__sync_fetch_and_add(&flow_stats.park_skipped,
			    1);
			continue;
		}
		tctx = flow_lookup(task);
		if (!tctx) {
			bpf_task_release(task);
			skips++;
			__sync_fetch_and_add(&flow_stats.park_skipped,
			    1);
			continue;
		}
		/* Only parked members serve here. A stale ring pid */
		/* from an earlier park drops with no insert, since */
		/* the live tree node owns the task. */
		if (READ_ONCE(tctx->queued) != 2) {
			bpf_task_release(task);
			skips++;
			__sync_fetch_and_add(&flow_stats.park_skipped,
			    1);
			continue;
		}
		cached = tctx->cached;
		cgid = tctx->cgid;
		throttled = flow_tree_throttled_scalar(cached, cgid);
		allowed = bpf_cpumask_test_cpu((u32)cpu,
		    task->cpus_ptr);
		/* A blocked head rotates with the visit spent. */
		/* The pop freed one slot but a concurrent push can fill */
		/* it first, so a full ring fails open to global with the */
		/* flag cleared and no task left without a queue. Mask only */
		/* rotates kick one idle allowed CPU with no preempt, and */
		/* throttled heads wait on the timer refill instead. */
		if (throttled || !allowed) {
			if (!flow_park_push(pid)) {
				WRITE_ONCE(tctx->queued, (u8)0);
				flow_global_insert(task);
				bpf_task_release(task);
				skips++;
				__sync_fetch_and_add(&flow_stats.park_skipped,
				    1);
				continue;
			}
			if (!throttled && !allowed) {
				s32 sel = task->scx.selected_cpu;
				flow_kick_idle_allowed(task, sel);
			}
			__sync_fetch_and_add(&flow_stats.park_skipped,
			    1);
			bpf_task_release(task);
			skips++;
			continue;
		}
		WRITE_ONCE(tctx->queued, (u8)0);
		flow_local_insert(task, cpu, 0);
		bpf_task_release(task);
		moved++;
	}
	return moved;
}
