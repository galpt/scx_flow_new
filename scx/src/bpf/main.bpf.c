/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. Each CPU keeps an ordered
 * queue with a mean slice. Short estimates run first
 * with arrival order for ties. The mean tracks the
 * unfinished work on the CPU with the running task
 * included. Fresh tasks join with the current mean so
 * the mean stays neutral. Blocked tasks complete and
 * release. Runnable tasks requeue ordered with a fresh
 * estimate. Idle CPUs steal from peers with a bounded
 * rotating scan. Kicks wake idle targets only.
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
 * Per CPU state. Keyed by CPU id. Holds the mean with
 * the sum and the count plus the steal cursor and the
 * running view.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");

/* Number of possible CPUs. Written once at init. */
volatile u64 nr_cpu_ids;

/* Scheduler wide counters. Updated with atomics. */
volatile struct flow_sched_stats flow_stats;

/*
 * Per CPU LLC ids. Seeded once by userspace from
 * host topology. Unknown entries hold the unknown
 * value. The count holds distinct domains. Zero or
 * one means plain behavior with no LLC step.
 */
volatile u32 flow_cpu_llc[FLOW_MAX_CPUS];

/* Count of distinct LLC domains. Zero is unknown. */
volatile u64 flow_llc_nr;

/* Owner value for tasks with no accounting. */
#define FLOW_OWNER_NONE 0xFFFFFFFFU

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
 * Look up the CPU state for one CPU. Returns null for
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
 * Check that a CPU id names a live CPU. Used to guard
 * queue and state access.
 */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}

/*
 * Check that a CPU may run a task. The id must be in
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
 * Idle CPU in the same LLC as the previous CPU.
 * Skips the second thread of a busy core when the
 * idle set marks fully idle cores. Returns minus
 * one when no LLC idle CPU is found. Single and
 * unknown hosts return at once with no scan.
 */
static s32 flow_llc_idle(const struct task_struct *p,
	s32 prev_cpu)
{
	u32 want;
	const struct cpumask *idle_smt;
	s32 cpu;
	s32 found = -1;

	if (!flow_llc_ok(flow_llc_nr))
		return -1;
	if (prev_cpu < 0)
		return -1;
	if ((u32)prev_cpu >= (u32)FLOW_MAX_CPUS)
		return -1;
	if ((u64)prev_cpu >= nr_cpu_ids)
		return -1;
	want = flow_cpu_llc[(u32)prev_cpu];
	if (!flow_llc_known(want))
		return -1;
	idle_smt = scx_bpf_get_idle_smtmask();
	bpf_for(cpu, 0, 1024) {
		u32 id;

		if (cpu < 0)
			continue;
		if ((u32)cpu >= (u32)FLOW_MAX_CPUS)
			break;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		id = flow_cpu_llc[(u32)cpu];
		if (id != want)
			continue;
		if (!flow_cpu_ok(p, cpu))
			continue;
		if (idle_smt) {
			if (!bpf_cpumask_test_cpu((u32)cpu,
			    idle_smt))
				continue;
		}
		if (scx_bpf_test_and_clear_cpu_idle(cpu)) {
			found = cpu;
			break;
		}
	}
	if (idle_smt)
		scx_bpf_put_idle_cpumask(idle_smt);
	return found;
}

/*
 * Join one estimate to a CPU mean. The sum and the
 * count grow by the estimate. The mean is refreshed
 * from the new sum and count.
 */
static __always_inline void flow_join_cpu(u32 cpu,
	u64 est)
{
	struct flow_cpu_state *st;

	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	__sync_fetch_and_add(&st->sum_est, est);
	__sync_fetch_and_add(&st->nr, 1);
	__sync_lock_test_and_set(&st->tq_ns,
	    flow_mean_tq(st->sum_est, st->nr));
}

/*
 * Leave one estimate from a CPU mean. A missing entry
 * is a no op, so a double leave stays safe. The mean
 * is refreshed from the new sum and count.
 */
static __always_inline void flow_leave_cpu(u32 cpu,
	u64 est)
{
	struct flow_cpu_state *st;
	s32 i;

	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	bpf_for(i, 0, 4) {
		u64 cur_n = st->nr;
		u64 cur_s = st->sum_est;
		u64 nxt_n;
		u64 nxt_s;
		u64 old_n;
		u64 old_s;

		if (cur_n == 0)
			break;
		if (cur_s < est)
			nxt_s = 0;
		else
			nxt_s = cur_s - est;
		nxt_n = cur_n - 1;
		old_n = __sync_val_compare_and_swap(&st->nr,
		    cur_n, nxt_n);
		if (old_n != cur_n)
			continue;
		old_s = __sync_val_compare_and_swap(
		    &st->sum_est, cur_s, nxt_s);
		if (old_s != cur_s) {
			__sync_fetch_and_add(&st->nr, 1);
			__sync_lock_test_and_set(&st->sum_est,
			    cur_s);
			break;
		}
		__sync_lock_test_and_set(&st->tq_ns,
		    flow_mean_tq(nxt_s, nxt_n));
		break;
	}
}

/*
 * Replace one estimate in a CPU mean. The count stays
 * fixed while the sum tracks the change. The mean is
 * refreshed from the new sum.
 */
static __always_inline void flow_replace_cpu(u32 cpu,
	u64 old, u64 next)
{
	struct flow_cpu_state *st;

	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	if (old != next) {
		if (st->sum_est >= old)
			__sync_fetch_and_sub(&st->sum_est, old);
		else
			__sync_lock_test_and_set(&st->sum_est, 0);
		__sync_fetch_and_add(&st->sum_est, next);
	}
	__sync_lock_test_and_set(&st->tq_ns,
	    flow_mean_tq(st->sum_est, st->nr));
}

/*
 * Drop the on CPU count without wrap. Zero stays at
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
 * Clear the running view of one CPU. Zero pid means
 * idle, so the dashboard sees idle at once.
 */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;

	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_est = 0;
	st->running_pid = 0;
}

/*
 * Set the CPU hint from estimate against mean. Short
 * estimates ask for the high hint. Long estimates
 * restore the low hint. Unknown helpers stay safe
 * with no hint change.
 */
static __always_inline void flow_cpuperf_set(s32 cpu,
	u64 est, u64 tq)
{
	u32 perf;

	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	perf = flow_cpuperf_for_est(est, tq);
	scx_bpf_cpuperf_set(cpu, perf);
}

/*
 * Restore the low hint when a stop leaves the CPU
 * idle. Runnable stops keep their work, so they
 * never restore. Queued work also keeps the hint,
 * so restore runs once per idle change.
 */
static __always_inline void flow_cpuperf_restore(s32 cpu,
	bool runnable)
{
	u64 dsq;

	if (runnable)
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	dsq = flow_dsq_for_cpu((u32)cpu);
	if (scx_bpf_dsq_nr_queued(dsq) != 0)
		return;
	if (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)cpu) != 0)
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	scx_bpf_cpuperf_set(cpu, (u32)FLOW_CPUPERF_LONG);
}

/*
 * Release one accounted entry exactly once. A missing
 * entry is a no op, so double release stays safe.
 */
static __always_inline void flow_release(
	struct flow_task_ctx *tctx)
{
	u32 owner;
	u64 est;

	if (!tctx)
		return;
	if (tctx->grant_ns == (u64)-1)
		return;
	owner = tctx->owner;
	est = tctx->est_ns;
	if (owner != FLOW_OWNER_NONE && flow_cpu_live(owner))
		flow_leave_cpu(owner, flow_clamp_est(est));
	tctx->grant_ns = (u64)-1;
	tctx->owner = FLOW_OWNER_NONE;
}

/*
 * Drain one per CPU queue with skip past bad heads.
 * The iterator visits every queued task in order, so
 * one foreign, exiting, or unresolvable head never
 * blocks later work. Each eligible task moves to the
 * local DSQ of the asking CPU. Returns the count
 * moved, capped at the given budget.
 */
static __always_inline u32 flow_drain_own(s32 cpu,
	u32 budget)
{
	struct task_struct *p;
	u64 dsq;
	u32 moved = 0;

	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	if (budget == 0)
		return 0;
	dsq = flow_dsq_for_cpu((u32)cpu);
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved >= budget)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (p->flags & PF_EXITING) {
			bpf_task_release(p);
			continue;
		}
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			continue;
		}
		bpf_task_release(p);
		moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}

/*
 * Drain the park queue with skip past bad heads. The
 * iterator visits every parked task in order, so one
 * foreign, exiting, or unresolvable head never blocks
 * later work. Each eligible task moves to the local
 * DSQ of the asking CPU. Returns the count moved,
 * capped at the given budget.
 */
static __always_inline u32 flow_drain_park(s32 cpu,
	u32 budget)
{
	struct task_struct *p;
	u32 moved = 0;

	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	if (budget == 0)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, FLOW_DSQ_PARK, 0) {
		if (moved >= budget)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (p->flags & PF_EXITING) {
			bpf_task_release(p);
			continue;
		}
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			continue;
		}
		bpf_task_release(p);
		__sync_fetch_and_add(&flow_stats.park_moves, 1);
		moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}

/*
 * Steal one task from a peer queue for an idle thief.
 * Peeks the head only, so a foreign head stays for
 * its owner while the scan moves to the next peer.
 * The mask check mirrors the own and park drains, so
 * only allowed heads reach the move helper. Returns
 * one when a task moved and zero otherwise.
 */
static __always_inline u32 flow_drain_peer(s32 thief,
	u32 peer)
{
	struct task_struct *p;
	u64 dsq;
	bool stole = false;

	if (thief < 0)
		return 0;
	if (!flow_cpu_live((u32)thief))
		return 0;
	if (!flow_cpu_live(peer))
		return 0;
	if (thief == (s32)peer)
		return 0;
	dsq = flow_dsq_for_cpu(peer);
	if (scx_bpf_dsq_nr_queued(dsq) == 0)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		p = bpf_task_from_pid(p->pid);
		if (!p)
			break;
		if (p->flags & PF_EXITING) {
			bpf_task_release(p);
			break;
		}
		if (!bpf_cpumask_test_cpu((u32)thief,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			break;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)thief, 0)) {
			bpf_task_release(p);
			break;
		}
		bpf_task_release(p);
		stole = true;
		break;
	}
	bpf_rcu_read_unlock();
	if (stole) {
		__sync_fetch_and_add(&flow_stats.steal_moves, 1);
		return 1;
	}
	return 0;
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;
	s32 llc_pick;

	this_cpu = (s32)bpf_get_smp_processor_id();
	/* Single CPU ends at the first allowed CPU. */
	/* Tasks that cannot move stay on the current CPU. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		/* No allowed CPU, park hint for enqueue. */
		return prev_cpu;
	}
	/* Pinned tasks stay where they are. */
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		/* The single allowed CPU is the valid hint. */
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		/* No allowed CPU, park hint for enqueue. */
		return prev_cpu;
	}
	/* Prefer an idle CPU in the previous LLC domain. */
	/* Single and unknown hosts skip the LLC step. */
	llc_pick = flow_llc_idle(p, prev_cpu);
	if (llc_pick >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, llc_pick))
			return llc_pick;
	}
	/* Prefer an idle CPU inside the mask. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, picked))
			return picked;
	}
	/* Fall back to the previous CPU when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* Fall back to the current CPU when allowed. */
	if (flow_cpu_ok(p, this_cpu))
		return this_cpu;
	/* Try the first allowed CPU when allowed. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	/* No allowed CPU, park hint for enqueue. */
	return prev_cpu;
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 sel;
	s32 cpu = -1;
	bool cpu_valid = false;
	bool is_requeue = false;
	bool is_fresh = false;
	bool need_join = false;
	u64 est = 0;
	u64 tq = (u64)FLOW_TQ_SEED_NS;

	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	if (!tctx) {
		tq = (u64)FLOW_TQ_SEED_NS;
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		/* Park holds the task for a later move. */
		scx_bpf_dsq_insert(p, (u64)FLOW_DSQ_PARK,
		    tq, 0);
		return;
	}
	if (tctx->est_ns == 0)
		is_fresh = true;
	if (tctx->grant_ns == (u64)-1)
		need_join = true;
	/* Tasks that cannot move stay on the current CPU. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here)) {
			cpu = here;
			cpu_valid = true;
		}
	}
	if (!cpu_valid) {
		if (flow_cpu_ok(p, sel)) {
			cpu = sel;
			cpu_valid = true;
		} else {
			s32 first;

			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first)) {
				cpu = first;
				cpu_valid = true;
			}
		}
	}
	if (!cpu_valid) {
		/* No target, park for a later move. */
		tq = (u64)FLOW_TQ_SEED_NS;
		if (is_fresh) {
			tctx->est_ns = tq;
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		} else if (is_requeue) {
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		} else if (need_join) {
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		}
		tctx->grant_ns = tq;
		tctx->owner = FLOW_OWNER_NONE;
		scx_bpf_dsq_insert(p, (u64)FLOW_DSQ_PARK,
		    tq, 0);
		return;
	}
	st = flow_cpu((u32)cpu);
	tq = st ? st->tq_ns : (u64)FLOW_TQ_SEED_NS;
	if (tq == 0)
		tq = (u64)FLOW_TQ_SEED_NS;
	if (is_fresh)
		est = tq;
	else
		est = flow_clamp_est(tctx->est_ns);
	tctx->est_ns = est;
	if (need_join) {
		flow_join_cpu((u32)cpu, est);
		tctx->owner = (u32)cpu;
		if (is_fresh)
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		else
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		st = flow_cpu((u32)cpu);
		tq = st ? st->tq_ns : tq;
		if (tq == 0)
			tq = (u64)FLOW_TQ_SEED_NS;
	} else {
		tctx->owner = (u32)cpu;
		if (is_requeue)
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
	}
	tctx->grant_ns = tq;
	/* Ordered queue keeps short estimates first. */
	scx_bpf_dsq_insert_vtime(p, flow_dsq_for_cpu((u32)cpu),
	    tq, est, 0);
	/* Kick only a CPU in the mask. */
	if (flow_cpu_ok(p, cpu)) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	}
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_DISPATCH_MAX_BATCH;
	u32 moved = 0;
	u32 own_left = 0;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* Own queue drains first with skip past bad heads. */
	moved += flow_drain_own(cpu, budget - moved);
	if (moved >= budget)
		return;
	/* Parked tasks move when the mask allows. */
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_PARK) > 0)
		moved += flow_drain_park(cpu, budget - moved);
	if (moved >= budget)
		return;
	own_left = scx_bpf_dsq_nr_queued(
	    flow_dsq_for_cpu((u32)cpu));
	if (own_left > 0)
		return;
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_PARK) > 0)
		return;
	/* Idle thieves scan peers with a rotating cursor. */
	{
		struct flow_cpu_state *st;
		u32 cur;
		u32 i;

		st = flow_cpu((u32)cpu);
		cur = st ? (u32)st->cursor : 0;
		bpf_for(i, 0, 8) {
			u32 peer;

			if (moved >= budget)
				break;
			if (i >= (u32)FLOW_STEAL_BOUND)
				break;
			peer = flow_steal_next(cur,
			    (u32)nr_cpu_ids);
			cur = peer;
			if (!flow_cpu_live(peer))
				continue;
			if ((s32)peer == cpu)
				continue;
			moved += flow_drain_peer(cpu, peer);
		}
		if (st)
			__sync_lock_test_and_set(&st->cursor, cur);
	}
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
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st) {
		u64 est = tctx ?
		    flow_clamp_est(tctx->est_ns) : 0;
		u64 tq = st->tq_ns;

		if (tq == 0)
			tq = (u64)FLOW_TQ_SEED_NS;
		st->running_est = est;
		st->running_pid = (u32)p->pid;
		/* The hint uses only estimate against mean. */
		flow_cpuperf_set(cpu, est, tq);
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
	u64 old;

	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (!tctx || !tctx->run_at ||
	    tctx->run_at == (u64)-1) {
		flow_clear_running(cpu);
		flow_on_cpu_dec();
		flow_cpuperf_restore(cpu, runnable);
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	est = flow_clamp_est(delta);
	old = flow_clamp_est(tctx->est_ns);
	tctx->est_ns = est;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
	tctx->run_at = 0;
	if (runnable) {
		u32 owner = tctx->owner;

		/* Runnable tasks requeue ordered with new est. */
		if (owner != FLOW_OWNER_NONE &&
		    flow_cpu_live(owner))
			flow_replace_cpu(owner, old, est);
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	/* Blocked tasks complete and release at once. */
	__sync_fetch_and_add(&flow_stats.completions, 1);
	flow_release(tctx);
	flow_cpuperf_restore(cpu, runnable);
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
	tctx->owner = FLOW_OWNER_NONE;
	tctx->pad = 0;
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
	if (tctx->grant_ns == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
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
	if (tctx->grant_ns == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	flow_release(tctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	u64 n;
	s32 cpu;

	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	/* Create one ordered queue per CPU. */
	bpf_for(cpu, 0, 1024) {
		u64 dsq;

		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		dsq = flow_dsq_for_cpu((u32)cpu);
		if (dsq >= (u64)SCX_DSQ_LOCAL_ON) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(dsq, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	/* Create the park DSQ for tasks with no target. */
	if ((u64)FLOW_DSQ_PARK >= (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq((u64)FLOW_DSQ_PARK, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Seed each mean with the seed value. */
	bpf_for(cpu, 0, 1024) {
		struct flow_cpu_state *st;
		u32 key;

		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (!st)
			continue;
		st->tq_ns = (u64)FLOW_TQ_SEED_NS;
		st->sum_est = 0;
		st->nr = 0;
		st->cursor = (u64)cpu;
		st->running_est = 0;
		st->running_pid = 0;
		st->pad = 0;
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
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= 30000,
	       .name			= "flow");
