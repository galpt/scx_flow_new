// SPDX-License-Identifier: GPL-2.0
/*
 * Flow wakeup kicks.
 *
 * The constrained kick preempts when the running time leads by at
 * least the threshold with slice past the tail, else it wakes idle.
 * Both sides compare latency shifted keys, so latency wins ties by
 * one slice. The pinned kick preempts past the tail with no gap
 * check, since a pinned wait cannot run elsewhere. A streak at or
 * above the bound turns an idle wake into a preempt. Targets that
 * are missing, disallowed, or offline count a skip with no wake.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_PREEMPT_BPF_H
#define __FLOW_PREEMPT_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "vtime.bpf.h"

/**
 * flow_kick_constrained - wake the constrained target of a task.
 * @tgt: target CPU, or minus one when none exists.
 * @use_v: queue key of the waiter.
 * @p: waiter.
 * @llc: LLC to charge.
 *
 * Revalidates the mask before each wake so a mask change between
 * pick and kick never wakes off mask.
 *
 * Returns: one when a preempt fired, else zero.
 */
static __always_inline int flow_kick_constrained(s32 tgt, s64 use_v,
						 struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;
	u64 gap;

	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	{
		s64 run_v = rs->lat ? flow_vtime_boost(rs->vtime, 1) : rs->vtime;

		if (run_v <= use_v)
			goto idle;
		gap = (u64)(run_v - use_v);
	}
	if (gap >= (u64)FLOW_PREEMPT_THRESH) {
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		return 1;
	}
idle:
	/* A CPU that keeps burning full slices holds the head past */
	/* the gap test, so the streak preempts with no gap check and */
	/* counts the escape next to the preempt. */
	if (rs->gen != 0 && rs->hog_streak >= (u32)FLOW_STREAK_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 8);
			return 0;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 8);
			return 0;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		flow_stat_inc(llc, 12);
		return 1;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
	return 0;
}

/**
 * flow_kick_pinned - wake the target of a pinned waiter.
 * @tgt: target CPU, or minus one when none exists.
 * @use_v: unused queue key, kept for call shape.
 * @p: waiter.
 * @llc: LLC to charge.
 *
 * Preempts at once when a task runs past the tail. An empty target
 * wakes idle. The streak shares the constrained bound and count.
 */
static __always_inline void flow_kick_pinned(s32 tgt, s64 use_v,
					     struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;

	(void)use_v;
	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
		flow_stat_inc(llc, 8);
		return;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
	return;
idle:
	if (rs->gen != 0 && rs->hog_streak >= (u32)FLOW_STREAK_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 8);
			return;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 8);
			return;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		flow_stat_inc(llc, 12);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}

/**
 * flow_kick_idle_only - wake idle for an insert without context.
 * @task_cpu: hint CPU for the target lookup.
 * @p: waiter.
 * @llc: LLC to charge.
 *
 * Skips preemption since there is no running state to compare.
 * Cheap by design with no running state lookup.
 */
static __always_inline void flow_kick_idle_only(s32 task_cpu,
						struct task_struct *p, u32 llc)
{
	s32 tgt = flow_constrained_target(task_cpu, p);

	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}

#endif
