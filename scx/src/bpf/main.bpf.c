/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. One ordered queue per cpu
 * with a global park. Tasks order by estimate with
 * unknown tasks at the front. A global mean sets the
 * slice.
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

/* Accounted task count for the global mean. */
volatile u64 flow_nr;

/* Estimate sum for the global mean. */
volatile u64 flow_sum;

/* Global mean quantum. Seeded at init. */
volatile u64 flow_mean_ns;

/* First arrival time of the busy period. */
volatile u64 flow_head_at;

/* Most recent arrival time. */
volatile u64 flow_tail_at;

/* Accounted tasks per cpu. Index is the cpu id. */
volatile u64 flow_depth[FLOW_MAX_CPUS];

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
 * Check that a depth slot names a real cpu. Used to
 * guard per cpu depth updates.
 */
static __always_inline bool flow_depth_ok(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
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
 * Recompute the global mean. An empty set keeps the
 * last value, so the quantum is never zero.
 */
static __always_inline void flow_recompute(void)
{
	u64 nr = flow_nr;
	u64 sum = flow_sum;
	u64 last = flow_mean_ns;
	u64 mean = flow_mean_quantum(sum, nr, last);

	flow_mean_ns = mean;
}

/*
 * Add one estimate to the global set. The sum saturates
 * at the top, so a burst cannot wrap the value. The
 * per cpu depth grows when the cpu is known. The tail
 * always moves forward. An empty set starts a new busy
 * period at the head.
 */
static __always_inline void flow_add(u64 est, u32 cpu,
    bool cpu_valid)
{
	u64 now = flow_now();
	bool was_empty;

	est = flow_clamp_est(est);
	was_empty = flow_nr == 0;
	__sync_fetch_and_add(&flow_nr, 1);
	if (true) {
		u64 old = __sync_fetch_and_add(&flow_sum,
		    est);

		if (old > (u64)-1 - est)
			__sync_lock_test_and_set(&flow_sum,
			    (u64)-1);
	}
	if (cpu_valid && flow_depth_ok(cpu))
		__sync_fetch_and_add(&flow_depth[cpu], 1);
	if (was_empty)
		flow_head_at = now;
	flow_tail_at = now;
	flow_recompute();
}

/*
 * Remove one estimate from the global set. Counts and
 * sums use compare and swap loops with saturation, so
 * concurrent releases never wrap below zero. An empty
 * set keeps the last quantum and clears the busy
 * period. The per cpu depth falls when the cpu is
 * known.
 */
static __always_inline void flow_remove(u64 est, u32 cpu,
    bool cpu_valid)
{
	s32 i;

	est = flow_clamp_est(est);
	bpf_for(i, 0, 4) {
		u64 cur = flow_nr;
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_nr, cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(&flow_nr, 0);
	}
	bpf_for(i, 0, 4) {
		u64 cur = flow_sum;
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		if (cur >= est)
			nxt = cur - est;
		else
			nxt = 0;
		old = __sync_val_compare_and_swap(
		    &flow_sum, cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(&flow_sum, 0);
	}
	if (cpu_valid && flow_depth_ok(cpu)) {
		bpf_for(i, 0, 4) {
			u64 cur = flow_depth[cpu];
			u64 nxt;
			u64 old;

			if (cur == 0)
				break;
			nxt = cur - 1;
			old = __sync_val_compare_and_swap(
			    &flow_depth[cpu], cur, nxt);
			if (old == cur)
				break;
			if (i == 3)
				__sync_lock_test_and_set(
				    &flow_depth[cpu], 0);
		}
	}
	flow_recompute();
	if (flow_nr == 0) {
		flow_head_at = 0;
		flow_tail_at = 0;
	}
}

/*
 * Refresh one estimate in place. The count stays fixed
 * and the sum swaps the old estimate for the new one.
 * The per cpu depth moves when the queue changes. The
 * tail moves forward on every refresh.
 */
static __always_inline void flow_refresh(u64 old_est,
    u64 new_est, u32 old_cpu, u32 new_cpu, bool old_ok,
    bool new_ok)
{
	u64 now;
	s32 i;

	old_est = flow_clamp_est(old_est);
	new_est = flow_clamp_est(new_est);
	if (old_est != new_est) {
		bpf_for(i, 0, 4) {
			u64 cur = flow_sum;
			u64 tmp;
			u64 nxt;
			u64 old;

			if (cur >= old_est)
				tmp = cur - old_est;
			else
				tmp = 0;
			if (tmp > (u64)-1 - new_est)
				nxt = (u64)-1;
			else
				nxt = tmp + new_est;
			old = __sync_val_compare_and_swap(
			    &flow_sum, cur, nxt);
			if (old == cur)
				break;
			if (i == 3)
				__sync_lock_test_and_set(
				    &flow_sum, nxt);
		}
		flow_recompute();
	}
	if (old_ok && new_ok && old_cpu != new_cpu) {
		if (flow_depth_ok(old_cpu)) {
			bpf_for(i, 0, 4) {
				u64 cur =
				    flow_depth[old_cpu];
				u64 nxt;
				u64 old;

				if (cur == 0)
					break;
				nxt = cur - 1;
				old =
				    __sync_val_compare_and_swap(
				    &flow_depth[old_cpu],
				    cur, nxt);
				if (old == cur)
					break;
				if (i == 3)
					__sync_lock_test_and_set(
					    &flow_depth[old_cpu],
					    0);
			}
		}
		if (flow_depth_ok(new_cpu))
			__sync_fetch_and_add(
			    &flow_depth[new_cpu], 1);
	} else if (!old_ok && new_ok) {
		if (flow_depth_ok(new_cpu))
			__sync_fetch_and_add(
			    &flow_depth[new_cpu], 1);
	} else if (old_ok && !new_ok) {
		if (flow_depth_ok(old_cpu)) {
			bpf_for(i, 0, 4) {
				u64 cur =
				    flow_depth[old_cpu];
				u64 nxt;
				u64 old;

				if (cur == 0)
					break;
				nxt = cur - 1;
				old =
				    __sync_val_compare_and_swap(
				    &flow_depth[old_cpu],
				    cur, nxt);
				if (old == cur)
					break;
				if (i == 3)
					__sync_lock_test_and_set(
					    &flow_depth[old_cpu],
					    0);
			}
		}
	}
	now = flow_now();
	flow_tail_at = now;
	if (flow_nr == 0)
		flow_head_at = now;
}

/*
 * Release one accounted entry exactly once. A missing
 * entry is a no op, so double release is safe.
 */
static __always_inline void flow_release(
    struct flow_task_ctx *tctx)
{
	bool cpu_ok;
	u32 cpu;

	if (!tctx)
		return;
	if (!tctx->acct_valid)
		return;
	cpu = tctx->acct_cpu;
	cpu_ok = flow_depth_ok(cpu);
	flow_remove(tctx->acct_est, cpu, cpu_ok);
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
	u64 dsq;
	u64 slice;
	u64 key;
	u64 live;

	(void)enq_flags;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	live = flow_live_quantum(flow_mean_ns);
	if (!tctx) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx,
		    1);
		scx_bpf_dsq_insert_vtime(p, SCX_DSQ_GLOBAL,
		    live, 0, 0);
		return;
	}
	/* Runnable requeue keeps the mean entry, refresh only. */
	if (tctx->acct_valid) {
		u64 old_est = tctx->acct_est;
		u32 old_cpu = tctx->acct_cpu;
		bool old_ok = flow_depth_ok(old_cpu);
		u64 new_est;
		u32 new_cpu;
		bool new_ok;

		if (tctx->est_ns == 0)
			new_est = flow_clamp_est(1);
		else
			new_est = flow_clamp_est(tctx->est_ns);
		/* Key the target off the selected cpu. */
		/* Fallback is first allowed, then global park. */
		if (flow_cpu_ok(p, sel)) {
			cpu = sel;
		} else {
			cpu = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (!flow_cpu_ok(p, cpu)) {
				/* No allowed cpu, use global queue. */
				key = flow_insert_key(
				    tctx->est_ns);
				flow_refresh(old_est, new_est,
				    old_cpu, 0, old_ok, false);
				tctx->acct_est = new_est;
				tctx->acct_cpu = 0;
				scx_bpf_dsq_insert_vtime(p,
				    SCX_DSQ_GLOBAL, live, key, 0);
				__sync_fetch_and_add(
				    &flow_stats.requeues, 1);
				return;
			}
		}
		new_cpu = (u32)cpu;
		new_ok = true;
		key = flow_insert_key(tctx->est_ns);
		flow_refresh(old_est, new_est, old_cpu,
		    new_cpu, old_ok, new_ok);
		tctx->acct_est = new_est;
		tctx->acct_cpu = new_cpu;
		/* Cpu is checked above, cast is safe. */
		dsq = flow_dsq_id((u32)cpu);
		slice = live;
		scx_bpf_dsq_insert_vtime(p, dsq, slice, key,
		    0);
		__sync_fetch_and_add(&flow_stats.requeues,
		    1);
		return;
	}
	/* First insert adds a fresh mean entry. */
	/* Key the target off the selected cpu. */
	/* Fallback is first allowed, then global park. */
	if (flow_cpu_ok(p, sel)) {
		cpu = sel;
	} else {
		cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (!flow_cpu_ok(p, cpu)) {
			u64 est;

			/* No allowed cpu, use global queue. */
			if (tctx->est_ns == 0)
				est = flow_clamp_est(1);
			else
				est = flow_clamp_est(
				    tctx->est_ns);
			key = flow_insert_key(tctx->est_ns);
			flow_add(est, 0, false);
			tctx->acct_est = est;
			tctx->acct_cpu = 0;
			tctx->acct_valid = 1;
			scx_bpf_dsq_insert_vtime(p,
			    SCX_DSQ_GLOBAL, live, key, 0);
			__sync_fetch_and_add(
			    &flow_stats.placements, 1);
			return;
		}
	}
	{
		u64 est;

		if (tctx->est_ns == 0)
			est = flow_clamp_est(1);
		else
			est = flow_clamp_est(tctx->est_ns);
		key = flow_insert_key(tctx->est_ns);
		flow_add(est, (u32)cpu, true);
		tctx->acct_est = est;
		tctx->acct_cpu = (u32)cpu;
		tctx->acct_valid = 1;
		/* Cpu is checked above, cast is safe. */
		dsq = flow_dsq_id((u32)cpu);
		slice = live;
		scx_bpf_dsq_insert_vtime(p, dsq, slice, key,
		    0);
		__sync_fetch_and_add(&flow_stats.placements,
		    1);
	}
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 start = 0;
	u32 n = 0;
	u32 moved = 0;
	struct flow_cpu_state *st;
	s32 k;
	s32 off;

	(void)prev;
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
	/* Serve the local queue in one drain. */
	bpf_for(k, 0, 32) {
		u64 local;

		__sink(moved);
		if (moved >= 32)
			break;
		local = flow_dsq_id((u32)cpu);
		if (!scx_bpf_dsq_nr_queued(local))
			break;
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
	/* Steal remote work in one scan of sixty four checks. */
	/* The scan rotates forward each pass and honors the mask. */
	bpf_for(off, 0, 64) {
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
		peer_dsq = flow_dsq_id(peer);
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
	/* Negative ids fall back to zero, use needs a check. */
	st = flow_cpu((u32)(cpu < 0 ? 0 : cpu));
	if (st && cpu >= 0) {
		st->running_est = tctx ? tctx->est_ns : 0;
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
	/* Blocked tasks leave the ready set at once. */
	/* Runnable tasks keep the entry for ordered requeue. */
	if (!runnable)
		flow_release(tctx);
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;

	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->est_ns = 0;
	tctx->run_at = 0;
	tctx->acct_est = 0;
	tctx->acct_cpu = 0;
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
	u64 n;
	s32 ret;
	u32 i;

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
	/* Seed the global mean. */
	flow_mean_ns = flow_seed_quantum();
	flow_nr = 0;
	flow_sum = 0;
	flow_head_at = 0;
	flow_tail_at = 0;
	bpf_for(i, 0, 1024) {
		if ((u64)i >= (u64)FLOW_MAX_CPUS)
			break;
		flow_depth[i] = 0;
	}
	/* Create one ordered queue per cpu. */
	bpf_for(cpu, 0, n) {
		u64 id = flow_dsq_id((u32)cpu);

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
