/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. Three queues per cpu with
 * one park queue per queue. New tasks start at the
 * first queue. Full burns move down one queue. Aged
 * heads move up one queue. Each queue keeps FIFO order
 * with its own live mean for the slice.
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

/* Accounted task count per queue for the mean. */
volatile u64 flow_nr[3];

/* Estimate sum per queue for the mean. */
volatile u64 flow_sum[3];

/* Live mean quantum per queue. Seeded at init. */
volatile u64 flow_mean_ns[3];

/* First arrival time per queue of the busy period. */
volatile u64 flow_head_at[3];

/* Accounted tasks per cpu. Index is the cpu id. */
volatile u64 flow_depth[FLOW_MAX_CPUS];

/* Scheduler wide counters. Updated with atomics. */
volatile struct flow_sched_stats flow_stats;

/*
 * Current time source. The plain kernel time is used
 * on all kernels, so the stamps share one boot clock
 * with the userspace age reads from uptime. Ages use
 * saturation, so small skew stays harmless.
 */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
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
 * Head age of one queue. A zero stamp means the queue
 * is empty, so the age is zero.
 */
static __always_inline u64 flow_queue_age(u32 q,
    u64 now)
{
	u64 head;

	if (!flow_queue_ok(q))
		return 0;
	head = flow_head_at[q];
	if (head == 0)
		return 0;
	if (now >= head)
		return now - head;
	return 0;
}

/*
 * Drop the on cpu count without wrap. Zero stays at
 * zero, so a double stop never wraps the gauge.
 */
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;

	bpf_for(i, 0, 4) {
		u64 cur = flow_stats.on_cpu;
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_stats.on_cpu, 0);
	}
}

/*
 * Clear the running view of one cpu. Zero pid means
 * idle, so the dashboard sees idle at once.
 */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;

	if (cpu < 0)
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_est = 0;
	st->running_pid = 0;
	st->running_queue = 0;
}

/*
 * Pick the next queue to serve. Aged non empty queues
 * come first by oldest age. Other queues follow strict
 * order. Empty queues never win. No queued task yields
 * a negative pick.
 */
static __always_inline s32 flow_pick(bool q0, bool q1,
    bool q2, u64 a0, u64 a1, u64 a2)
{
	bool aged0 = q0 && flow_should_promote(a0);
	bool aged1 = q1 && flow_should_promote(a1);
	bool aged2 = q2 && flow_should_promote(a2);
	s32 best = -1;
	u64 best_age = 0;

	if (aged0) {
		best = 0;
		best_age = a0;
	}
	if (aged1) {
		if (best < 0 || a1 > best_age) {
			best = 1;
			best_age = a1;
		}
	}
	if (aged2) {
		if (best < 0 || a2 > best_age) {
			best = 2;
			best_age = a2;
		}
	}
	if (best >= 0)
		return best;
	if (q0)
		return 0;
	if (q1)
		return 1;
	if (q2)
		return 2;
	return -1;
}

/*
 * Recompute one queue mean. An empty set keeps the
 * last value, so the quantum is never zero.
 */
static __always_inline void flow_recompute(u32 q)
{
	u64 nr;
	u64 sum;
	u64 last;
	u64 mean;

	if (!flow_queue_ok(q))
		return;
	nr = flow_nr[q];
	sum = flow_sum[q];
	last = flow_mean_ns[q];
	mean = flow_mean_quantum(q, sum, nr, last);
	flow_mean_ns[q] = mean;
}

/*
 * Add one estimate to one queue. The sum saturates at
 * the top, so a burst cannot wrap the value. The per
 * cpu depth grows when the cpu is known. An empty queue
 * starts a new busy period at the head with an atomic
 * stamp, so concurrent starts keep the first stamp.
 */
static __always_inline void flow_add(u32 q, u64 est,
    u32 cpu, bool cpu_valid)
{
	u64 now = flow_now();
	u64 stamp;
	bool was_empty;

	if (!flow_queue_ok(q))
		return;
	est = flow_clamp_est(est);
	was_empty = flow_nr[q] == 0;
	__sync_fetch_and_add(&flow_nr[q], 1);
	if (true) {
		u64 old = __sync_fetch_and_add(&flow_sum[q],
		    est);

		if (old > (u64)-1 - est)
			__sync_lock_test_and_set(&flow_sum[q],
			    (u64)-1);
	}
	if (cpu_valid && flow_depth_ok(cpu))
		__sync_fetch_and_add(&flow_depth[cpu], 1);
	if (was_empty) {
		if (now == 0)
			stamp = 1;
		else
			stamp = now;
		__sync_val_compare_and_swap(
		    &flow_head_at[q], 0, stamp);
	}
	flow_recompute(q);
}

/*
 * Remove one estimate from one queue. Counts and sums
 * use compare and swap loops with saturation, so
 * concurrent releases never wrap below zero. An empty
 * queue keeps the last quantum and clears the busy
 * period with an atomic swap, so a late clear only
 * delays one promotion and stays harmless. The per
 * cpu depth falls when the cpu is known.
 */
static __always_inline void flow_remove(u32 q, u64 est,
    u32 cpu, bool cpu_valid)
{
	s32 i;

	if (!flow_queue_ok(q))
		return;
	est = flow_clamp_est(est);
	bpf_for(i, 0, 4) {
		u64 cur = flow_nr[q];
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_nr[q], cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(&flow_nr[q], 0);
	}
	bpf_for(i, 0, 4) {
		u64 cur = flow_sum[q];
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		if (cur >= est)
			nxt = cur - est;
		else
			nxt = 0;
		old = __sync_val_compare_and_swap(
		    &flow_sum[q], cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(&flow_sum[q], 0);
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
	flow_recompute(q);
	if (flow_nr[q] == 0) {
		u64 cur = flow_head_at[q];

		__sync_val_compare_and_swap(
		    &flow_head_at[q], cur, 0);
	}
}

/*
 * Refresh one estimate in place in the same queue. The
 * count stays fixed and the sum swaps the old estimate
 * for the new one. The per cpu depth moves when the
 * cpu changes.
 */
static __always_inline void flow_refresh_same(u32 q,
    u64 old_est, u64 new_est, u32 old_cpu, u32 new_cpu,
    bool old_ok, bool new_ok)
{
	s32 i;

	if (!flow_queue_ok(q))
		return;
	old_est = flow_clamp_est(old_est);
	new_est = flow_clamp_est(new_est);
	if (old_est != new_est) {
		bpf_for(i, 0, 4) {
			u64 cur = flow_sum[q];
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
			    &flow_sum[q], cur, nxt);
			if (old == cur)
				break;
			if (i == 3)
				__sync_lock_test_and_set(
				    &flow_sum[q], nxt);
		}
		flow_recompute(q);
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
	u32 q;

	if (!tctx)
		return;
	if (!tctx->acct_valid)
		return;
	cpu = tctx->acct_cpu;
	q = tctx->acct_queue;
	if (!flow_queue_ok(q))
		q = 0;
	cpu_ok = flow_depth_ok(cpu);
	flow_remove(q, tctx->acct_est, cpu, cpu_ok);
	tctx->acct_valid = 0;
}

/*
 * Move one accounted entry between queues. A same queue
 * move refreshes in place. A cross queue move removes
 * from the old queue and adds to the new one.
 */
static __always_inline void flow_move(u32 old_q,
    u32 new_q, u64 old_est, u64 new_est, u32 old_cpu,
    u32 new_cpu, bool old_ok, bool new_ok)
{
	if (!flow_queue_ok(old_q))
		old_q = 0;
	if (!flow_queue_ok(new_q))
		new_q = old_q;
	if (old_q == new_q) {
		flow_refresh_same(old_q, old_est, new_est,
		    old_cpu, new_cpu, old_ok, new_ok);
		return;
	}
	flow_remove(old_q, old_est, old_cpu, old_ok);
	flow_add(new_q, new_est, new_cpu, new_ok);
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
		s32 allow;

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		/* The single allowed cpu is the valid hint. */
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		return allow;
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
	s32 cpu = -1;
	bool cpu_valid = false;
	u64 now;

	(void)enq_flags;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	now = flow_now();
	if (!tctx) {
		u64 live;

		live = flow_live_quantum(0, flow_mean_ns[0]);
		__sync_fetch_and_add(&flow_stats.enq_no_tctx,
		    1);
		scx_bpf_dsq_insert(p, flow_park_id(0), live,
		    0);
		return;
	}
	if (flow_cpu_ok(p, sel)) {
		cpu = sel;
		cpu_valid = true;
	} else {
		s32 first;

		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first)) {
			cpu = first;
			cpu_valid = true;
		}
	}
	/* Runnable requeue keeps the entry and may move. */
	if (tctx->acct_valid) {
		u64 old_est = tctx->acct_est;
		u32 old_cpu = tctx->acct_cpu;
		u32 old_q = tctx->acct_queue;
		bool old_ok = flow_depth_ok(old_cpu);
		u64 new_est;
		u32 cur;
		u32 new_q;
		u64 age;
		bool is_burned;
		bool promoted = false;
		bool demoted = false;
		u64 live;
		u64 dsq;

		if (!flow_queue_ok(old_q))
			old_q = 0;
		cur = tctx->queue;
		if (!flow_queue_ok(cur))
			cur = old_q;
		if (tctx->est_ns == 0)
			new_est = flow_clamp_est(1);
		else
			new_est = flow_clamp_est(tctx->est_ns);
		age = flow_queue_age(cur, now);
		is_burned = flow_burned(tctx->slice_ns,
		    new_est);
		if (flow_should_promote(age) && cur > 0) {
			new_q = cur - 1;
			promoted = true;
		} else {
			new_q = flow_next_on_burn(cur, true,
			    is_burned);
			if (new_q > cur)
				demoted = true;
		}
		if (!flow_queue_ok(new_q))
			new_q = cur;
		if (new_q == old_q) {
			u32 new_cpu = cpu_valid ? (u32)cpu : 0;
			bool new_ok = cpu_valid;

			flow_refresh_same(old_q, old_est,
			    new_est, old_cpu, new_cpu, old_ok,
			    new_ok);
			tctx->acct_est = new_est;
			tctx->acct_cpu = new_cpu;
			tctx->acct_queue = old_q;
			tctx->queue = old_q;
		} else {
			u32 new_cpu = cpu_valid ? (u32)cpu : 0;
			bool new_ok = cpu_valid;

			flow_move(old_q, new_q, old_est,
			    new_est, old_cpu, new_cpu, old_ok,
			    new_ok);
			tctx->acct_est = new_est;
			tctx->acct_cpu = new_cpu;
			tctx->acct_queue = new_q;
			tctx->queue = new_q;
			if (promoted)
				__sync_fetch_and_add(
				    &flow_stats.promotions[cur],
				    1);
			if (demoted)
				__sync_fetch_and_add(
				    &flow_stats.demotions[cur],
				    1);
		}
		live = flow_live_quantum(new_q,
		    flow_mean_ns[new_q]);
		tctx->slice_ns = live;
		if (cpu_valid)
			dsq = flow_dsq_id((u32)cpu, new_q);
		else
			dsq = flow_park_id(new_q);
		scx_bpf_dsq_insert(p, dsq, live, 0);
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		/* Kick an idle target to collect now. */
		if (cpu_valid) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
		return;
	}
	/* First insert holds the queue or starts anew. */
	{
		u64 est;
		u32 cur;
		u32 new_q;
		u64 age;
		u64 live;
		u64 dsq;

		if (tctx->est_ns == 0) {
			est = flow_clamp_est(1);
			cur = 0;
			new_q = 0;
		} else {
			est = flow_clamp_est(tctx->est_ns);
			cur = tctx->queue;
			if (!flow_queue_ok(cur))
				cur = 0;
			age = flow_queue_age(cur, now);
			new_q = flow_promote_if_aged(cur, age);
			if (!flow_queue_ok(new_q))
				new_q = cur;
			if (new_q != cur)
				__sync_fetch_and_add(
				    &flow_stats.promotions[cur],
				    1);
		}
		if (cpu_valid) {
			flow_add(new_q, est, (u32)cpu, true);
		} else {
			flow_add(new_q, est, 0, false);
		}
		tctx->acct_est = est;
		tctx->acct_cpu = cpu_valid ? (u32)cpu : 0;
		tctx->acct_queue = new_q;
		tctx->acct_valid = 1;
		tctx->queue = new_q;
		live = flow_live_quantum(new_q,
		    flow_mean_ns[new_q]);
		tctx->slice_ns = live;
		if (cpu_valid)
			dsq = flow_dsq_id((u32)cpu, new_q);
		else
			dsq = flow_park_id(new_q);
		scx_bpf_dsq_insert(p, dsq, live, 0);
		__sync_fetch_and_add(
		    &flow_stats.placements[new_q], 1);
		/* Kick an idle target to collect now. */
		if (cpu_valid) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
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
	u64 now;

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
	now = flow_now();
	/* Serve the local queues in strict order with age. */
	bpf_for(k, 0, 32) {
		u64 a0;
		u64 a1;
		u64 a2;
		bool has0;
		bool has1;
		bool has2;
		s32 pick;
		u64 local;

		__sink(moved);
		if (moved >= 32)
			break;
		a0 = flow_queue_age(0, now);
		a1 = flow_queue_age(1, now);
		a2 = flow_queue_age(2, now);
		has0 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id((u32)cpu, 0)) > 0;
		has1 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id((u32)cpu, 1)) > 0;
		has2 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id((u32)cpu, 2)) > 0;
		if (!has0 && !has1 && !has2)
			break;
		pick = flow_pick(has0, has1, has2, a0, a1,
		    a2);
		if (pick < 0)
			break;
		local = flow_dsq_id((u32)cpu, (u32)pick);
		if (!scx_bpf_dsq_move_to_local(local, 0))
			continue;
		__sync_fetch_and_add(&flow_stats.dispatches, 1);
		moved++;
		__sink(moved);
	}
	if (moved >= 32)
		goto out;
	/* Serve the park queues with the same order. */
	bpf_for(k, 0, 32) {
		u64 a0;
		u64 a1;
		u64 a2;
		bool has0;
		bool has1;
		bool has2;
		s32 pick;
		u64 park;

		__sink(moved);
		if (moved >= 32)
			break;
		a0 = flow_queue_age(0, now);
		a1 = flow_queue_age(1, now);
		a2 = flow_queue_age(2, now);
		has0 = scx_bpf_dsq_nr_queued(
		    flow_park_id(0)) > 0;
		has1 = scx_bpf_dsq_nr_queued(
		    flow_park_id(1)) > 0;
		has2 = scx_bpf_dsq_nr_queued(
		    flow_park_id(2)) > 0;
		if (!has0 && !has1 && !has2)
			break;
		pick = flow_pick(has0, has1, has2, a0, a1,
		    a2);
		if (pick < 0)
			break;
		park = flow_park_id((u32)pick);
		if (!flow_steal_ok(cpu, park))
			continue;
		if (!scx_bpf_dsq_move_to_local(park, 0))
			continue;
		__sync_fetch_and_add(&flow_stats.steals, 1);
		__sync_fetch_and_add(&flow_stats.dispatches, 1);
		moved++;
		__sink(moved);
	}
	if (moved >= 32)
		goto out;
	if (n == 0)
		goto out;
	/* Steal remote work in one scan of sixty four. */
	/* The scan rotates forward and honors the mask. */
	/* Each peer is tried in queue order with age. */
	bpf_for(off, 0, 64) {
		u32 peer;
		u64 a0;
		u64 a1;
		u64 a2;
		bool has0;
		bool has1;
		bool has2;
		s32 pick;
		u64 peer_dsq;
		s32 qi;

		__sink(moved);
		if (moved >= 32)
			break;
		peer = (start + (u32)off + 1) & 1023;
		if (peer >= n)
			continue;
		if ((s32)peer == cpu)
			continue;
		a0 = flow_queue_age(0, now);
		a1 = flow_queue_age(1, now);
		a2 = flow_queue_age(2, now);
		has0 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id(peer, 0)) > 0;
		has1 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id(peer, 1)) > 0;
		has2 = scx_bpf_dsq_nr_queued(
		    flow_dsq_id(peer, 2)) > 0;
		if (!has0 && !has1 && !has2)
			continue;
		pick = flow_pick(has0, has1, has2, a0, a1,
		    a2);
		if (pick < 0)
			continue;
		/* Try the picked queue first, then the rest. */
		for (qi = 0; qi < 3; qi++) {
			s32 q;

			if (qi == 0)
				q = pick;
			else if (qi == 1)
				q = (pick + 1) % 3;
			else
				q = (pick + 2) % 3;
			if (q == 0 && !has0)
				continue;
			if (q == 1 && !has1)
				continue;
			if (q == 2 && !has2)
				continue;
			peer_dsq = flow_dsq_id(peer, (u32)q);
			if (!flow_steal_ok(cpu, peer_dsq))
				continue;
			if (!scx_bpf_dsq_move_to_local(
			    peer_dsq, 0))
				continue;
			__sync_fetch_and_add(&flow_stats.steals,
			    1);
			__sync_fetch_and_add(
			    &flow_stats.dispatches, 1);
			moved++;
			__sink(moved);
			break;
		}
		if (moved >= 32)
			break;
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
		if (tctx && flow_queue_ok(tctx->queue))
			st->running_queue = tctx->queue;
		else
			st->running_queue = 0;
	}
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}

/*
 * Keep the mean entry across dispatch to run. The
 * move to the local queue leaves custody but the
 * entry stays for the ordered requeue. The block
 * path and the exit paths release once through the
 * valid flag.
 */
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
    u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
    bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 est;

	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (!tctx || !tctx->run_at) {
		flow_clear_running(cpu);
		flow_on_cpu_dec();
		return;
	}
	delta = now >= tctx->run_at ? now - tctx->run_at : 0;
	est = flow_clamp_est(delta);
	tctx->est_ns = est;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
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
	tctx->slice_ns = 0;
	tctx->queue = 0;
	tctx->acct_est = 0;
	tctx->acct_cpu = 0;
	tctx->acct_queue = 0;
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
	u32 q;

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
	/* Seed each queue mean. */
	bpf_for(q, 0, 3) {
		if (!flow_queue_ok(q))
			continue;
		flow_mean_ns[q] = flow_seed_quantum(q);
		flow_nr[q] = 0;
		flow_sum[q] = 0;
		flow_head_at[q] = 0;
	}
	bpf_for(i, 0, 1024) {
		if ((u64)i >= (u64)FLOW_MAX_CPUS)
			break;
		flow_depth[i] = 0;
	}
	/* Create three ordered queues per cpu. */
	bpf_for(cpu, 0, n) {
		bpf_for(q, 0, 3) {
			u64 id;

			if (!flow_queue_ok(q))
				continue;
			id = flow_dsq_id((u32)cpu, q);
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
	/* Create one park queue per queue. */
	bpf_for(q, 0, 3) {
		u64 id;

		if (!flow_queue_ok(q))
			continue;
		id = flow_park_id(q);
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
