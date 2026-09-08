/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. Two tiers share the work.
 * The interactive tier serves short bursts with a small
 * fixed slice and direct placement to the target DSQ.
 * The batch tier serves long bursts with a large fixed
 * slice through one shared DSQ ordered by vruntime. New
 * tasks start in the interactive tier. Full burns move
 * down one tier. Short voluntary blocks build a streak
 * that moves up one tier. A deficit guard keeps the
 * batch tier from waiting too long.
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
 * view plus the deficit count and the preempt stamp.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");

/* Number of possible cpus. Written once at init. */
volatile u64 nr_cpu_ids;

/* Floor of batch vruntime. New batch tasks join here. */
volatile u64 flow_min_vtime;

/* Accounted tasks per tier. Index is the tier. */
volatile u64 flow_tier_nr[2];

/* Scheduler wide counters. Updated with atomics. */
volatile struct flow_sched_stats flow_stats;

/*
 * Current time source. The plain kernel time is used
 * on all kernels, so stamps share one boot clock with
 * userspace reads from uptime.
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
 * Check that a cpu id names a real cpu. Used to guard
 * per cpu state access.
 */
static __always_inline bool flow_cpu_id_ok(u32 cpu)
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
 * Check that a parked task may run here. The peek
 * gives an untrusted view, so a trusted reference is
 * used for the mask test. A missing peek fails closed
 * and skips the move.
 */
static __always_inline bool flow_park_ok(s32 cpu,
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
	ok = bpf_cpumask_test_cpu((u32)cpu, ref->cpus_ptr);
	bpf_task_release(ref);
	return ok;
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
 * Drop one tier count without wrap. Zero stays at
 * zero, so a double release never wraps the gauge.
 */
static __always_inline void flow_tier_dec(u32 tier)
{
	s32 i;

	if (!flow_tier_ok(tier))
		return;
	bpf_for(i, 0, 4) {
		u64 cur = flow_tier_nr[tier];
		u64 nxt;
		u64 old;

		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_tier_nr[tier], cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_tier_nr[tier], 0);
	}
}

/*
 * Raise the vruntime floor to the smallest waiting
 * value. The floor only moves forward, so later joins
 * never pass waiting work.
 */
static __always_inline void flow_floor_advance(u64 vtime)
{
	s32 i;

	bpf_for(i, 0, 4) {
		u64 cur = flow_min_vtime;
		u64 old;

		if (!flow_vruntime_before(cur, vtime))
			break;
		old = __sync_val_compare_and_swap(
		    &flow_min_vtime, cur, vtime);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_min_vtime, vtime);
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
	if (!flow_cpu_id_ok((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_est = 0;
	st->running_pid = 0;
	st->running_tier = 0;
}

/*
 * Set the cpu hint of one tier. Interactive asks
 * for the max level. Batch restores the default,
 * so the hint tracks the task now on the cpu.
 */
static __always_inline void flow_cpuperf_set(s32 cpu,
	u32 tier)
{
	u32 perf;

	if (cpu < 0)
		return;
	if (!flow_cpu_id_ok((u32)cpu))
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	perf = flow_cpuperf_tier(tier);
	scx_bpf_cpuperf_set(cpu, perf);
}

/*
 * Release one accounted entry exactly once. A missing
 * entry is a no op, so double release stays safe.
 */
static __always_inline void flow_release(
	struct flow_task_ctx *tctx)
{
	u32 tier;

	if (!tctx)
		return;
	if (tctx->grant_ns == (u64)-1)
		return;
	tier = tctx->tier;
	if (!flow_tier_ok(tier))
		return;
	flow_tier_dec(tier);
	tctx->grant_ns = (u64)-1;
}

/*
 * Mark one accounted entry as joined. A joined entry
 * is counted once until release. The tier is stored
 * for the later release.
 */
static __always_inline void flow_acquire(
	struct flow_task_ctx *tctx, u32 tier)
{
	if (!tctx)
		return;
	if (!flow_tier_ok(tier))
		tier = 0;
	__sync_fetch_and_add(&flow_tier_nr[tier], 1);
	tctx->tier = tier;
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
	bool is_requeue = false;
	u32 tier = 0;
	u64 grant;
	u64 now;
	bool is_fresh = false;
	bool need_join = false;

	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	now = flow_now();
	if (!tctx) {
		grant = flow_quantum_tier(0);
		__sync_fetch_and_add(&flow_stats.enq_no_tctx,
		    1);
		scx_bpf_dsq_insert(p, (u64)FLOW_DSQ_PARK,
		    grant, 0);
		return;
	}
	if (tctx->grant_ns == 0 && tctx->run_at == 0 &&
	    tctx->est_ns == 0 && tctx->vruntime == 0 &&
	    tctx->streak == 0)
		is_fresh = true;
	if (tctx->grant_ns == (u64)-1 || is_fresh)
		need_join = true;
	/* Joining tasks start in the interactive tier. */
	if (tctx->grant_ns == (u64)-1) {
		/* Released state, tier holds the next tier. */
		tier = tctx->tier;
		if (!flow_tier_ok(tier))
			tier = 0;
	} else if (is_fresh) {
		/* Fresh task with no history starts interactive. */
		tier = 0;
		tctx->tier = 0;
	} else {
		tier = tctx->tier;
		if (!flow_tier_ok(tier))
			tier = 0;
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
	if (!cpu_valid) {
		/* No target, park for a later move. */
		if (need_join)
			flow_acquire(tctx, tier);
		grant = flow_quantum_tier(tier);
		tctx->grant_ns = grant;
		if (tier == (u32)FLOW_TIER_BATCH) {
			u64 floor = flow_min_vtime;

			if (tctx->vruntime == 0)
				tctx->vruntime = floor;
			scx_bpf_dsq_insert_vtime(p,
			    (u64)FLOW_DSQ_PARK, grant,
			    tctx->vruntime, 0);
		} else {
			scx_bpf_dsq_insert(p,
			    (u64)FLOW_DSQ_PARK, grant, 0);
		}
		if (tier == 0)
			__sync_fetch_and_add(
			    &flow_stats.enq_tier0, 1);
		else
			__sync_fetch_and_add(
			    &flow_stats.enq_tier1, 1);
		return;
	}
	if (tier == (u32)FLOW_TIER_BATCH) {
		u64 floor = flow_min_vtime;
		u64 vtime;

		if (need_join)
			flow_acquire(tctx, tier);
		grant = flow_quantum_tier(tier);
		tctx->grant_ns = grant;
		if (tctx->vruntime == 0)
			tctx->vruntime = floor;
		vtime = tctx->vruntime;
		scx_bpf_dsq_insert_vtime(p,
		    (u64)FLOW_DSQ_BATCH, grant, vtime, 0);
		__sync_fetch_and_add(&flow_stats.enq_tier1, 1);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
		return;
	}
	/* Interactive tasks place direct to the target. */
	if (need_join)
		flow_acquire(tctx, tier);
	grant = flow_quantum_tier(tier);
	tctx->grant_ns = grant;
	if (is_requeue) {
		scx_bpf_dsq_insert(p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, grant,
		    0);
	} else {
		scx_bpf_dsq_insert(p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, grant,
		    SCX_ENQ_HEAD);
	}
	__sync_fetch_and_add(&flow_stats.enq_tier0, 1);
	scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	__sync_fetch_and_add(&flow_stats.kicks, 1);
	/* Busy preemption stays narrow by design. */
	if (!is_requeue) {
		struct flow_cpu_state *st;

		st = flow_cpu((u32)cpu);
		if (st) {
			bool busy_batch = false;

			if (st->running_pid != 0 &&
			    st->running_tier ==
			    (u32)FLOW_TIER_BATCH)
				busy_batch = true;
			if (busy_batch &&
			    flow_preempt_gap_ok(now,
			    st->last_preempt_at)) {
				scx_bpf_kick_cpu(cpu,
				    SCX_KICK_PREEMPT);
				__sync_lock_test_and_set(
				    &st->last_preempt_at, now);
				__sync_fetch_and_add(
				    &flow_stats.preempts, 1);
			}
		}
	}
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	struct flow_cpu_state *st;
	u64 served0 = 0;
	bool tier0_wait = false;
	bool tier1_wait = false;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_id_ok((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (st)
		served0 = st->served0;
	if (scx_bpf_dsq_nr_queued(
	    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu) > 0)
		tier0_wait = true;
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_BATCH) > 0)
		tier1_wait = true;
	/* Gated batch serve keeps long waits bounded. */
	if (flow_deficit_should_serve(served0, tier0_wait,
	    tier1_wait)) {
		struct task_struct *cand = NULL;
		u64 vtime = 0;
		bool have = false;

		if (bpf_ksym_exists(scx_bpf_dsq_peek)) {
			cand = scx_bpf_dsq_peek(
			    (u64)FLOW_DSQ_BATCH);
			if (cand) {
				vtime = cand->scx.dsq_vtime;
				have = true;
			}
		}
		if (have)
			flow_floor_advance(vtime);
		if (scx_bpf_dsq_move_to_local(
		    (u64)FLOW_DSQ_BATCH, 0)) {
			__sync_fetch_and_add(
			    &flow_stats.deficit_serves, 1);
			/* Batch runs restore the default hint. */
			flow_cpuperf_set(cpu,
			    (u32)FLOW_TIER_BATCH);
			return;
		}
	}
	/* Parked tasks move when the mask allows. */
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_PARK) > 0) {
		if (!flow_park_ok(cpu, (u64)FLOW_DSQ_PARK)) {
			/* Blocked park keeps the local hint. */
			if (tier0_wait)
				flow_cpuperf_set(cpu,
				    (u32)FLOW_TIER_INTERACTIVE);
			return;
		}
		scx_bpf_dsq_move_to_local((u64)FLOW_DSQ_PARK,
		    0);
		/* Park moves leave the hint alone. */
		return;
	}
	/* Interactive backlog asks for the max hint. */
	if (tier0_wait)
		flow_cpuperf_set(cpu,
		    (u32)FLOW_TIER_INTERACTIVE);
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
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_id_ok((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st) {
		u32 tier = 0;

		if (tctx && flow_tier_ok(tctx->tier))
			tier = tctx->tier;
		st->running_est = tctx ? tctx->est_ns : 0;
		st->running_pid = (u32)p->pid;
		st->running_tier = tier;
		st->served0 = flow_deficit_next(st->served0,
		    tier);
		if (tier == (u32)FLOW_TIER_BATCH)
			__sync_fetch_and_add(
			    &flow_stats.serves_tier1, 1);
		else
			__sync_fetch_and_add(
			    &flow_stats.serves_tier0, 1);
		/* The hint tracks the task now on the cpu. */
		flow_cpuperf_set(cpu, tier);
	}
inc:
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}

/*
 * Keep the accounted entry across dispatch to run. The
 * move to the local DSQ leaves custody but the entry
 * stays for the ordered insert. The block path and the
 * exit paths release once through the grant sentinel.
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
	u64 grant;
	bool is_burned;

	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (!tctx || !tctx->run_at ||
	    tctx->run_at == (u64)-1) {
		flow_clear_running(cpu);
		flow_on_cpu_dec();
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	est = flow_clamp_est(delta);
	tctx->est_ns = est;
	grant = tctx->grant_ns;
	if (grant == (u64)-1)
		grant = 0;
	is_burned = flow_burned(grant, delta);
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
	tctx->run_at = 0;
	if (runnable) {
		u32 tier = tctx->tier;
		u32 next;

		if (!flow_tier_ok(tier))
			tier = 0;
		next = flow_next_on_burn(tier, true,
		    is_burned);
		if (next != tier && flow_tier_ok(next)) {
			/* Burns move down at once. */
			flow_tier_dec(tier);
			__sync_fetch_and_add(
			    &flow_tier_nr[next], 1);
			tctx->tier = next;
			tctx->streak = 0;
			if (next ==
			    (u32)FLOW_TIER_BATCH) {
				u64 floor = flow_min_vtime;

				if (tctx->vruntime == 0 ||
				    flow_vruntime_before(
				    tctx->vruntime, floor))
					tctx->vruntime = floor;
			}
			__sync_fetch_and_add(
			    &flow_stats.demotions, 1);
		} else {
			if (tier ==
			    (u32)FLOW_TIER_BATCH)
				tctx->vruntime =
				    flow_vruntime_advance(
				    tctx->vruntime, delta);
		}
		return;
	}
	/* Blocked tasks build the streak for promotion. */
	{
		u32 tier = tctx->tier;
		u32 streak = tctx->streak;
		u32 next_streak;
		u32 next_tier;

		if (!flow_tier_ok(tier))
			tier = 0;
		next_streak = flow_streak_next(streak, delta);
		tctx->streak = next_streak;
		if (tier == (u32)FLOW_TIER_BATCH)
			tctx->vruntime = flow_vruntime_advance(
			    tctx->vruntime, delta);
		next_tier = tier;
		if (tier == (u32)FLOW_TIER_BATCH &&
		    flow_should_promote(next_streak)) {
			next_tier = (u32)FLOW_TIER_INTERACTIVE;
			__sync_fetch_and_add(
			    &flow_stats.promotions, 1);
		}
		flow_release(tctx);
		tctx->tier = next_tier;
	}
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;

	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->est_ns = 0;
	tctx->run_at = 0;
	tctx->grant_ns = (u64)-1;
	tctx->vruntime = 0;
	tctx->tier = 0;
	tctx->streak = 0;
}

/*
 * Release the accounted entry when a task leaves the
 * scheduler. The grant sentinel keeps the release to
 * a single decrement.
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
 * Release the accounted entry at task exit. The grant
 * sentinel keeps the release to a single decrement
 * with the disable path.
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
	s32 ret;
	u64 n;

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
	flow_min_vtime = 0;
	flow_tier_nr[0] = 0;
	flow_tier_nr[1] = 0;
	/* Create the shared batch DSQ. */
	if ((u64)FLOW_DSQ_BATCH >= SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq((u64)FLOW_DSQ_BATCH, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Create the park DSQ for tasks with no target. */
	if ((u64)FLOW_DSQ_PARK >= SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq((u64)FLOW_DSQ_PARK, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
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
