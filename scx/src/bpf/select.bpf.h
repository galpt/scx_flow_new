// SPDX-License-Identifier: GPL-2.0
/*
 * Placement for the flow scheduler.
 *
 * Tags mark sync plus hardirq plus softirq wakes on the task. Tiers
 * walk prev then same group then same LLC then same LLC thread then
 * fixed order with an atomic idle claim at each step. A won claim takes
 * direct local dispatch at max frequency and skips the
 * enqueue path through the dispatch flag. Masks are tested again
 * before each wake, so a task is never kicked toward a CPU outside
 * its current mask. Frequency follows core busyness and never steers
 * placement.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SELECT_BPF_H
#define __FLOW_SELECT_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"

static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}

static __always_inline bool flow_cpu_allowed(s32 cpu, struct task_struct *p)
{
	u32 c;

	if (!p || !p->cpus_ptr)
		return false;
	if (cpu < 0)
		return false;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return false;
	return bpf_cpumask_test_cpu(c, p->cpus_ptr);
}

static __always_inline bool flow_cpu_live(u32 cpu)
{
	if (!flow_cpu_ok(cpu))
		return false;
	if (!topo_all)
		return false;
	return topo_contains(topo_all, cpu) ? true : false;
}

/* Unknown cluster reads as all ones, so group zero stays a valid match.
 * The value never collides with a seeded group id, which stays small. */
#define FLOW_CCX_UNKNOWN 0xFFFFFFFFU

static __noinline s32 flow_first_allowed(struct task_struct *p)
{
	u32 first;
	u32 c;

	if (!p || !p->cpus_ptr)
		return -1;
	first = bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(first) && flow_cpu_live(first) && flow_cpu_allowed((s32)first, p))
		return (s32)first;
	/* Scan the mask in fixed order for the first allowed live CPU, so
	 * only tasks with no usable CPU fall back to minus one. Bounded
	 * scan within the CPU bound with mask plus live checks only. */
	bpf_for(c, 0, FLOW_MAX_CPUS) {
		if (!flow_cpu_live(c))
			continue;
		if (!flow_cpu_allowed((s32)c, p))
			continue;
		return (s32)c;
	}
	return -1;
}

static __noinline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}

/* A busy core runs at max and an idle core runs at half. The call
 * stays on one live core and never sends zero. The gate also bounds
 * the id by the live ids and skips a remote target while a queue
 * lock is held, so the set never trips the invalid target exit. The
 * caller must hold the target runqueue lock for a remote set, else
 * the call skips. Frequency never steers placement. */
static __always_inline void flow_cpuperf_mark(u32 cpu, bool idle)
{
	u32 perf;

	if (!flow_cpu_ok(cpu) || !flow_cpu_live(cpu))
		return;
	if ((u64)cpu >= scx_bpf_nr_cpu_ids())
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	if (bpf_ksym_exists(scx_bpf_cpu_rq)) {
		struct rq *locked = scx_bpf_locked_rq();

		if (locked) {
			struct rq *target = scx_bpf_cpu_rq((s32)cpu);

			if (!target || target != locked)
				return;
		}
	} else {
		struct rq *locked = scx_bpf_locked_rq();

		if (locked && cpu != bpf_get_smp_processor_id())
			return;
	}
	perf = (u32)SCX_CPUPERF_ONE;
	if (idle)
		perf = (u32)(SCX_CPUPERF_ONE / 2);
	if (!perf)
		return;
	scx_bpf_cpuperf_set((s32)cpu, perf);
}

static __always_inline int flow_hint_llc(s32 hint)
{
	int v;

	if (hint < 0 || !flow_cpu_ok((u32)hint))
		return -1;
	if (!topo_all)
		return -1;
	v = topo_cpu_to_llc_id((u32)hint);
	if (v < 0 || !flow_llc_ok((u32)v))
		return -1;
	return v;
}

static __always_inline u32 flow_cpu_ccx(u32 cpu)
{
	u32 key = cpu;
	struct flow_cpu_ctx *cc;

	if (!flow_cpu_ok(cpu))
		return (u32)FLOW_CCX_UNKNOWN;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!cc)
		return (u32)FLOW_CCX_UNKNOWN;
	return READ_ONCE(cc->ccx_id);
}

static __always_inline bool flow_ccx_match(bool use, u32 cx, u32 hint)
{
	if (!use)
		return false;
	if (cx == (u32)FLOW_CCX_UNKNOWN || hint == (u32)FLOW_CCX_UNKNOWN)
		return false;
	return cx == hint;
}

/* Claim one idle CPU through the tier order. Each step uses an atomic
 * claim, so concurrent wakes never pick the same CPU. T0 is prev or
 * the waker on sync. T1 is the same group. T2 is the same LLC. T3 is
 * a partial SMT thread in the same LLC. T4 is any idle CPU in fixed
 * order. Minus one means no idle CPU was won. */
static __noinline s32 flow_claim_idle(s32 prev_cpu, s32 waker_cpu, struct task_struct *p,
				      bool sync, int hint_llc, u32 hint_ccx, bool use_ccx)
{
	const struct cpumask *idle_mask;
	const struct cpumask *smt_mask;
	bool smt_on;
	s32 best = -1;
	u32 c;

	idle_mask = scx_bpf_get_idle_cpumask();
	if (!idle_mask)
		return -1;
	smt_mask = scx_bpf_get_idle_smtmask();
	if (!smt_mask) {
		scx_bpf_put_cpumask(idle_mask);
		return -1;
	}
	smt_on = READ_ONCE(flow_smt_enabled) ? true : false;

	/* T0: prev, or waker on sync, when fully idle. */
	if (sync && waker_cpu >= 0 && flow_cpu_allowed(waker_cpu, p) &&
	    flow_cpu_live((u32)waker_cpu)) {
		if (bpf_cpumask_test_cpu((u32)waker_cpu, smt_on ? smt_mask : idle_mask)) {
			if (scx_bpf_test_and_clear_cpu_idle(waker_cpu)) {
				best = waker_cpu;
				goto out;
			}
		}
	}
	if (prev_cpu >= 0 && flow_cpu_allowed(prev_cpu, p) && flow_cpu_live((u32)prev_cpu)) {
		if (bpf_cpumask_test_cpu((u32)prev_cpu, smt_on ? smt_mask : idle_mask)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
				best = prev_cpu;
				goto out;
			}
		}
	}
	/* T1: same group fully idle core. */
	if (hint_llc >= 0 && use_ccx && hint_ccx != (u32)FLOW_CCX_UNKNOWN) {
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			int vl;

			if (!flow_cpu_live(c) || !flow_cpu_allowed((s32)c, p))
				continue;
			if (!bpf_cpumask_test_cpu(c, smt_mask))
				continue;
			vl = topo_cpu_to_llc_id(c);
			if (vl != hint_llc)
				continue;
			if (!flow_ccx_match(use_ccx, flow_cpu_ccx(c), hint_ccx))
				continue;
			if (scx_bpf_test_and_clear_cpu_idle((s32)c)) {
				best = (s32)c;
				goto out;
			}
		}
	}
	/* T2: same LLC fully idle core. */
	if (hint_llc >= 0) {
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			int vl;

			if (!flow_cpu_live(c) || !flow_cpu_allowed((s32)c, p))
				continue;
			if (!bpf_cpumask_test_cpu(c, smt_mask))
				continue;
			vl = topo_cpu_to_llc_id(c);
			if (vl != hint_llc)
				continue;
			if (scx_bpf_test_and_clear_cpu_idle((s32)c)) {
				best = (s32)c;
				goto out;
			}
		}
	}
	/* T3: same LLC partial idle thread. */
	if (hint_llc >= 0) {
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			int vl;

			if (!flow_cpu_live(c) || !flow_cpu_allowed((s32)c, p))
				continue;
			if (!bpf_cpumask_test_cpu(c, idle_mask))
				continue;
			vl = topo_cpu_to_llc_id(c);
			if (vl != hint_llc)
				continue;
			if (scx_bpf_test_and_clear_cpu_idle((s32)c)) {
				best = (s32)c;
				goto out;
			}
		}
	}
	/* T4: any idle CPU in fixed order. */
	bpf_for(c, 0, FLOW_MAX_CPUS) {
		if (!flow_cpu_live(c) || !flow_cpu_allowed((s32)c, p))
			continue;
		if (!bpf_cpumask_test_cpu(c, idle_mask))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle((s32)c)) {
			best = (s32)c;
			goto out;
		}
	}
out:
	scx_bpf_put_cpumask(smt_mask);
	scx_bpf_put_cpumask(idle_mask);
	return best;
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct flow_task_ctx *t;
	s32 hint = prev_cpu;
	s32 waker_cpu;
	bool sync;
	int hint_llc = -1;
	u32 hint_ccx = (u32)FLOW_CCX_UNKNOWN;
	bool use_ccx;
	s32 cpu_id = -1;
	u32 llc = 0;
	int vl;

	if (!p)
		return hint;
	sync = (wake_flags & SCX_WAKE_SYNC) ? true : false;
	use_ccx = READ_ONCE(flow_ccx_prefer) ? true : false;
	waker_cpu = (s32)bpf_get_smp_processor_id();

	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (t) {
		u32 fl = READ_ONCE(t->flags);

		if (wake_flags & SCX_WAKE_SYNC)
			fl |= (u32)FLOW_FLAG_IS_SYNC_WAKEUP;
		else
			fl &= (u32)~(u32)FLOW_FLAG_IS_SYNC_WAKEUP;
		if (bpf_in_hardirq() || bpf_in_nmi())
			fl |= (u32)FLOW_FLAG_WOKEN_BY_HARDIRQ;
		else
			fl &= (u32)~(u32)FLOW_FLAG_WOKEN_BY_HARDIRQ;
		if (bpf_in_serving_softirq())
			fl |= (u32)FLOW_FLAG_WOKEN_BY_SOFTIRQ;
		else
			fl &= (u32)~(u32)FLOW_FLAG_WOKEN_BY_SOFTIRQ;
		WRITE_ONCE(t->flags, fl);
	}

	if (flow_is_pinned(p))
		return flow_constrained_target(hint, p);

	/* Anchor sync wakes on the waker when it shares the LLC. */
	if (sync && waker_cpu >= 0 && flow_cpu_ok((u32)waker_cpu) &&
	    flow_cpu_allowed(waker_cpu, p) && flow_cpu_live((u32)waker_cpu)) {
		if (hint < 0 || !flow_cpu_allowed(hint, p) ||
		    flow_hint_llc(waker_cpu) == flow_hint_llc(hint))
			hint = waker_cpu;
	}
	if (hint >= 0 && flow_cpu_ok((u32)hint) && topo_all &&
	    topo_contains(topo_all, (u32)hint)) {
		hint_llc = flow_hint_llc(hint);
		hint_ccx = flow_cpu_ccx((u32)hint);
	}

	cpu_id = flow_claim_idle(hint, waker_cpu, p, sync, hint_llc, hint_ccx, use_ccx);
	if (cpu_id < 0)
		return flow_constrained_target(hint, p);

	/* Direct dispatch on the won idle CPU. Compute the due
	 * time, ramp to max, insert to local, and mark the flag so enqueue
	 * is skipped for this activation. */
	if (!t)
		return cpu_id;
	vl = topo_cpu_to_llc_id((u32)cpu_id);
	if (vl >= 0 && flow_llc_ok((u32)vl))
		llc = (u32)vl;
	else if (flow_llc_ok(READ_ONCE(t->llc_id)))
		llc = READ_ONCE(t->llc_id);
	{
		u64 vd = flow_calc_when_to_run(p, t);
		struct flow_running_state *rs = &flow_running_state[(u32)cpu_id];
		u64 slice = flow_calc_slice(t, rs);

		t->llc_id = llc;
		t->pinned_cpu = -1;
		t->slice_ns = slice;
		WRITE_ONCE(t->flags, READ_ONCE(t->flags) | (u32)FLOW_FLAG_DIRECT_DISPATCH);
		scx_bpf_task_set_dsq_vtime(p, vd);
		if (flow_cpu_ok((u32)cpu_id) && (u64)(u32)cpu_id < scx_bpf_nr_cpu_ids())
			flow_cpuperf_mark((u32)cpu_id, false);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
		scx_bpf_kick_cpu(cpu_id, SCX_KICK_IDLE);
		flow_stat_inc(llc, 1);
		flow_stat_inc(llc, 7);
	}
	return cpu_id;
}
#endif
