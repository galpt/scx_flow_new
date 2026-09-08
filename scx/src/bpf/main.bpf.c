/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. Three feedback levels with
 * per cpu queues served top down. Tasks start at the
 * top and move down one level on each full slice.
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per task state. Created on first use and kept for
 * the life of the task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per cpu state. Keyed by cpu id. Holds the running
 * task view and the steal scan rotation.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");

/* Number of possible cpus. Written once at init. */
volatile u64 nr_cpu_ids;

/* Per level queued count for the live means. */
volatile u64 flow_nr[FLOW_NR_LEVELS];

/* Per level estimate sum for the live means. */
volatile u64 flow_sum[FLOW_NR_LEVELS];

/* Global per level mean quanta. Seeded at init. */
volatile u64 flow_mean_ns[FLOW_NR_LEVELS];

/* Scheduler wide counters. Updated with atomics. */
volatile struct flow_sched_stats flow_stats;

/*
 * Current time source. New kernels provide the
 * scheduler clock helper. Older kernels fall back
 * to the plain kernel time helper.
 */
static __always_inline u64 flow_now(void)
{
#if LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 12, 0)
	return scx_bpf_now();
#else
	return bpf_ktime_get_ns();
#endif
}

/*
 * Look up the task state without creating it. Returns
 * null when the task has no state yet.
 */
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}

/*
 * Look up or create the task state. Returns null on
 * allocation failure.
 */
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Look up the cpu state for one cpu. Returns null for
 * out of range ids.
 */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;

	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}

/*
 * Check that a cpu may run a task. The id must be in
 * range and present in the task mask.
 */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}

/*
 * Check that a steal candidate may run here. The peek
 * gives an untrusted view, so a trusted reference is
 * used for the mask test. A missing peek fails closed
 * and skips the steal.
 */
static __always_inline bool flow_steal_ok(s32 cpu,
    u64 dsq)
{
	struct task_struct *cand;
	struct task_struct *ref;
	bool ok;

	if (cpu < 0)
		return false;
	if (!bpf_ksym_exists(scx_bpf_dsq_peek))
		return false;
	cand = scx_bpf_dsq_peek(dsq);
	if (!cand)
		return false;
	ref = bpf_task_from_pid(cand->pid);
	if (!ref)
		return false;
	ok = bpf_cpumask_test_cpu((u32)cpu,
	    ref->cpus_ptr);
	bpf_task_release(ref);
	return ok;
}

/*
 * Count one placement at a level. Keeps the per level
 * insert shares visible to userspace.
 */
static __always_inline void flow_count_place(u32 level)
{
	if (level == 0)
		__sync_fetch_and_add(&flow_stats.l0_placements,
		    1);
	else if (level == 1)
		__sync_fetch_and_add(&flow_stats.l1_placements,
		    1);
	else
		__sync_fetch_and_add(&flow_stats.l2_placements,
		    1);
}

/*
 * Recompute one level mean. An empty level keeps the
 * last value, so the quantum is never zero.
 */
static __always_inline void flow_recompute(u32 level)
{
	u64 nr;
	u64 sum;
	u64 last;
	u64 mean;

	if (!flow_level_ok(level))
		return;
	nr = flow_nr[level];
	sum = flow_sum[level];
	last = flow_mean_ns[level];
	mean = flow_mean_quantum(level, sum, nr, last);
	flow_mean_ns[level] = mean;
}

/*
 * Add one estimate to a level. The sum saturates at
 * the top, so a burst cannot wrap the value.
 */
static __always_inline void flow_level_add(u32 level,
    u64 est)
{
	u64 old;

	if (!flow_level_ok(level))
		return;
	est = flow_clamp_est(est);
	__sync_fetch_and_add(&flow_nr[level], 1);
	old = __sync_fetch_and_add(&flow_sum[level], est);
	if (old > (u64)-1 - est)
		__sync_lock_test_and_set(&flow_sum[level],
		    (u64)-1);
	flow_recompute(level);
}

/*
 * Remove one estimate from a level. Counts and sums use
 * compare and swap loops with saturation, so concurrent
 * releases never wrap below zero. An empty level keeps
 * the last quantum.
 */
static __always_inline void flow_level_remove(u32 level,
    u64 est)
{
	s32 i;

	if (!flow_level_ok(level))
		return;
	est = flow_clamp_est(est);
	bpf_for(i, 0, 4) {
		u64 cur;
		u64 nxt;
		u64 old;

		cur = flow_nr[level];
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_nr[level], cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_nr[level], 0);
	}
	bpf_for(i, 0, 4) {
		u64 cur;
		u64 nxt;
		u64 old;

		cur = flow_sum[level];
		if (cur == 0)
			break;
		if (cur >= est)
			nxt = cur - est;
		else
			nxt = 0;
		old = __sync_val_compare_and_swap(
		    &flow_sum[level], cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_sum[level], 0);
	}
	flow_recompute(level);
}

/*
 * Release one accounted entry exactly once. A missing
 * entry is a no op, so double release is safe.
 */
static __always_inline void flow_release(
    struct flow_task_ctx *tctx)
{
	if (!tctx)
		return;
	if (!tctx->acct_valid)
		return;
	if (!flow_level_ok(tctx->acct_level)) {
		tctx->acct_valid = 0;
		return;
	}
	flow_level_remove(tctx->acct_level, tctx->acct_est);
	tctx->acct_valid = 0;
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
    s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;

	this_cpu = (s32)bpf_get_smp_processor_id();
	/* Pinned tasks stay where they are. */
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		return here;
	}
	/* Prefer an idle cpu inside the mask. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, picked))
			return picked;
	}
	/* Fall back to the previous cpu when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* Fall back to the current cpu when allowed. */
	if (flow_cpu_ok(p, this_cpu))
		return this_cpu;
	/* Try the first allowed cpu when allowed. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	/* No allowed cpu found, kernel checks the hint. */
	return prev_cpu;
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
    u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu;
	u32 level;
	u64 dsq;
	u64 slice;
	u64 est;

	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	if (!tctx) {
		u64 live;

		__sync_fetch_and_add(&flow_stats.enq_no_tctx,
		    1);
		live = flow_quantum_for_level(0, flow_mean_ns);
		live = flow_clamp_quantum(live);
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, live, 0);
		return;
	}
	/* Runnable requeue keeps the mean entry, refresh only. */
	if (tctx->acct_valid) {
		level = tctx->level;
		if (!flow_level_ok(level))
			level = 0;
		est = flow_clamp_est(tctx->est_ns);
		if (flow_level_ok(tctx->acct_level)) {
			if (tctx->acct_level != level) {
				/* Level changed, shift the entry. */
				flow_level_remove(tctx->acct_level,
				    tctx->acct_est);
				flow_level_add(level, est);
				tctx->acct_level = level;
				tctx->acct_est = est;
			} else if (tctx->acct_est != est) {
				/* Same level, refresh the sum. */
				/* Remove then add keeps the count. */
				flow_level_remove(tctx->acct_level,
				    tctx->acct_est);
				flow_level_add(level, est);
				tctx->acct_est = est;
			}
		} else {
			/* Bad stored level, add a fresh entry. */
			flow_level_add(level, est);
			tctx->acct_level = level;
			tctx->acct_est = est;
			tctx->acct_valid = 1;
		}
		tctx->level = level;
		/* Key the target off the selected cpu. */
		/* Fallback is first allowed, then global park. */
		if (flow_cpu_ok(p, sel)) {
			cpu = sel;
		} else {
			cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
			if (!flow_cpu_ok(p, cpu)) {
				u64 live;

				/* No allowed cpu, use global queue. */
				live = flow_quantum_for_level(level,
				    flow_mean_ns);
				live = flow_clamp_quantum(live);
				tctx->slice_ns = live;
				scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL,
				    live, 0);
				return;
			}
		}
		/* Cpu is checked above, cast is safe. */
		dsq = flow_dsq_id((u32)cpu, level);
		slice = flow_quantum_for_level(level, flow_mean_ns);
		slice = flow_clamp_quantum(slice);
		tctx->slice_ns = slice;
		/* Plain tail insert. No head insert is used. */
		scx_bpf_dsq_insert(p, dsq, slice, 0);
		return;
	}
	/* Pick a level from the estimate, top on unknown. */
	level = flow_pick_level(tctx->est_ns, flow_mean_ns);
	tctx->level = level;
	/* Key the target off the selected cpu. */
	/* Fallback is first allowed, then global park. */
	if (flow_cpu_ok(p, sel)) {
		cpu = sel;
	} else {
		cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (!flow_cpu_ok(p, cpu)) {
			u64 live;

			/* No allowed cpu found, use the global */
			/* queue, kernel places the task safely. */
			live = flow_quantum_for_level(0,
			    flow_mean_ns);
			live = flow_clamp_quantum(live);
			scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL,
			    live, 0);
			return;
		}
	}
	/* Cpu is checked above, cast is safe. */
	dsq = flow_dsq_id((u32)cpu, level);
	slice = flow_quantum_for_level(level, flow_mean_ns);
	slice = flow_clamp_quantum(slice);
	tctx->slice_ns = slice;
	tctx->acct_level = level;
	tctx->acct_est = flow_clamp_est(tctx->est_ns);
	tctx->acct_valid = 1;
	flow_level_add(level, tctx->acct_est);
	flow_count_place(level);
	/* Plain tail insert. No head insert is used. */
	scx_bpf_dsq_insert(p, dsq, slice, 0);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 start = 0;
	u32 n = 0;
	u32 moved = 0;
	struct flow_cpu_state *st;
	s32 k;
	s32 off;

	if (cpu < 0)
		return;
	st = flow_cpu((u32)cpu);
	if (st)
		start = st->scan_off;
	if (nr_cpu_ids) {
		n = (u32)nr_cpu_ids;
		if (n > 1024)
			n = 1024;
	}
	/* Serve local queues, bottom gets every sixteenth move. */
	/* Paper order is batch static, online arrivals need guard. */
	/* Normal moves drain top down, guard moves drain bottom up. */
	bpf_for(k, 0, 32) {
		u64 q0;
		u64 q1;
		u64 q2;
		s32 lvl;
		u64 local;

		__sink(moved);
		if (moved >= 32)
			break;
		q0 = scx_bpf_dsq_nr_queued(flow_dsq_id((u32)cpu, 0));
		q1 = scx_bpf_dsq_nr_queued(flow_dsq_id((u32)cpu, 1));
		q2 = scx_bpf_dsq_nr_queued(flow_dsq_id((u32)cpu, 2));
		if (!q0 && !q1 && !q2)
			break;
		/* Every sixteenth move takes lowest nonempty level. */
		if ((u64)(moved + 1) %
		    (u64)FLOW_GUARANTEE_EVERY == 0) {
			if (q2)
				lvl = 2;
			else if (q1)
				lvl = 1;
			else
				lvl = 0;
		} else {
			if (q0)
				lvl = 0;
			else if (q1)
				lvl = 1;
			else
				lvl = 2;
		}
		local = flow_dsq_id((u32)cpu, (u32)lvl);
		if (!scx_bpf_dsq_move_to_local(local, 0))
			break;
		__sync_fetch_and_add(&flow_stats.dispatches, 1);
		moved++;
		__sink(moved);
	}
	if (moved >= 32)
		goto out;
	if (n == 0)
		goto out;
	/* Steal remote work level major in batch. */
	/* The scan uses sixty four checks in total. */
	/* Top uses twenty two, others use twenty one. */
	bpf_for(off, 0, 22) {
		u32 peer;
		u64 peer_dsq;

		__sink(moved);
		if (moved >= 32)
			break;
		peer = (start + (u32)off + 1) & 1023;
		if (peer >= n)
			continue;
		if ((s32)peer == cpu)
			continue;
		peer_dsq = flow_dsq_id(peer, 0);
		if (!scx_bpf_dsq_nr_queued(peer_dsq))
			continue;
		/* Move only when the head may run here. */
		if (!flow_steal_ok(cpu, peer_dsq))
			continue;
		if (!scx_bpf_dsq_move_to_local(peer_dsq,
		    0))
			continue;
		__sync_fetch_and_add(&flow_stats.steals,
		    1);
		__sync_fetch_and_add(&flow_stats.dispatches,
		    1);
		moved++;
		__sink(moved);
	}
	if (moved >= 32)
		goto out;
	bpf_for(off, 0, 21) {
		u32 peer;
		u64 peer_dsq;

		__sink(moved);
		if (moved >= 32)
			break;
		peer = (start + (u32)off + 1) & 1023;
		if (peer >= n)
			continue;
		if ((s32)peer == cpu)
			continue;
		peer_dsq = flow_dsq_id(peer, 1);
		if (!scx_bpf_dsq_nr_queued(peer_dsq))
			continue;
		/* Move only when the head may run here. */
		if (!flow_steal_ok(cpu, peer_dsq))
			continue;
		if (!scx_bpf_dsq_move_to_local(peer_dsq,
		    0))
			continue;
		__sync_fetch_and_add(&flow_stats.steals,
		    1);
		__sync_fetch_and_add(&flow_stats.dispatches,
		    1);
		moved++;
		__sink(moved);
	}
	if (moved >= 32)
		goto out;
	bpf_for(off, 0, 21) {
		u32 peer;
		u64 peer_dsq;

		__sink(moved);
		if (moved >= 32)
			break;
		peer = (start + (u32)off + 1) & 1023;
		if (peer >= n)
			continue;
		if ((s32)peer == cpu)
			continue;
		peer_dsq = flow_dsq_id(peer, 2);
		if (!scx_bpf_dsq_nr_queued(peer_dsq))
			continue;
		/* Move only when the head may run here. */
		if (!flow_steal_ok(cpu, peer_dsq))
			continue;
		if (!scx_bpf_dsq_move_to_local(peer_dsq,
		    0))
			continue;
		__sync_fetch_and_add(&flow_stats.steals,
		    1);
		__sync_fetch_and_add(&flow_stats.dispatches,
		    1);
		moved++;
		__sink(moved);
	}
out:
	if (st)
		st->scan_off = start + 1;
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;

	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	if (tctx)
		tctx->run_at = flow_now();
	/* Keep the mean entry while running. */
	/* Paper ready set covers all unfinished tasks. */
	/* Negative ids fall back to zero, use needs a check. */
	st = flow_cpu((u32)(cpu < 0 ? 0 : cpu));
	if (st && cpu >= 0) {
		st->running_level = tctx ? (s32)tctx->level : -1;
		st->running_pid = (u32)p->pid;
	}
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}

/*
 * Drop the mean entry when the task leaves a queue
 * without running. The valid flag keeps the release
 * idempotent with the stopping path.
 */
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
    u64 deq_flags)
{
	struct flow_task_ctx *tctx;

	(void)deq_flags;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	flow_release(tctx);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
    bool runnable)
{
	struct flow_task_ctx *tctx;
	u64 now;
	u64 delta;
	u64 est;

	tctx = flow_lookup(p);
	now = flow_now();
	if (!tctx || !tctx->run_at) {
		__sync_fetch_and_sub(&flow_stats.on_cpu, 1);
		return;
	}
	delta = now >= tctx->run_at ? now - tctx->run_at : 0;
	est = flow_clamp_est(delta);
	tctx->est_ns = est;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	__sync_fetch_and_sub(&flow_stats.on_cpu, 1);
	tctx->run_at = 0;
	/* Blocked tasks leave the paper ready set at once. */
	if (!runnable) {
		flow_release(tctx);
		return;
	}
	/* Demote one level on a consumed slice. No move up. */
	/* The move shifts the mean entry between levels. */
	if (delta >= tctx->slice_ns &&
	    tctx->slice_ns > 0) {
		u32 old = tctx->level;
		u32 next = flow_next_level(old);

		if (next != old) {
			u64 live;

			if (tctx->acct_valid) {
				flow_level_remove(
				    tctx->acct_level,
				    tctx->acct_est);
				tctx->acct_valid = 0;
			}
			flow_level_add(next, est);
			tctx->acct_level = next;
			tctx->acct_est = est;
			tctx->acct_valid = 1;
			tctx->level = next;
			__sync_fetch_and_add(
			    &flow_stats.demotions, 1);
			live = flow_quantum_for_level(next,
			    flow_mean_ns);
			tctx->slice_ns =
			    flow_clamp_quantum(live);
		}
	}
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	u64 live;

	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->level = flow_initial_level();
	live = flow_quantum_for_level(0, flow_mean_ns);
	live = flow_clamp_quantum(live);
	tctx->est_ns = live;
	tctx->run_at = 0;
	tctx->slice_ns = live;
	tctx->acct_level = 0;
	tctx->acct_est = 0;
	tctx->acct_valid = 0;
}

/*
 * Release the mean entry when a task leaves the
 * scheduler. The valid flag keeps the release to a
 * single decrement.
 */
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;

	tctx = flow_lookup(p);
	if (!tctx)
		return;
	flow_release(tctx);
}

/*
 * Release the mean entry at task exit. The valid flag
 * keeps the release to a single decrement with the
 * disable path.
 */
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
    struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;

	(void)args;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	flow_release(tctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 cpu;
	u32 level;
	u64 n;
	s32 ret;

	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("cpu count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no cpus found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	/* Seed the per level means. */
	flow_mean_ns[0] = (u64)FLOW_L0_QUANTUM_NS;
	flow_mean_ns[1] = (u64)FLOW_L1_QUANTUM_NS;
	flow_mean_ns[2] = (u64)FLOW_L2_QUANTUM_NS;
	/* Create one queue per cpu per level. */
	bpf_for(cpu, 0, n) {
		for (level = 0; level < (u32)FLOW_NR_LEVELS;
		    level++) {
			u64 id = flow_dsq_id((u32)cpu, level);

			if (id >= SCX_DSQ_LOCAL_ON) {
				scx_bpf_error("dsq id over bound");
				return -EINVAL;
			}
			ret = scx_bpf_create_dsq(id, -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("dsq create failed");
				return ret;
			}
		}
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .enable			= (void *)flow_enable,
	       .disable			= (void *)flow_disable,
	       .exit_task		= (void *)flow_exit_task,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .dispatch_max_batch	= 32,
	       .timeout_ms		= 30000,
	       .name			= "flow");
