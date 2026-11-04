// SPDX-License-Identifier: GPL-2.0
/*
 * Flow kick helpers with steal-outcome split.
 *
 * Moved from main with an LLC param for per LLC counting. Predicates
 * are unchanged: preempt only when the target is allowed plus the
 * running vtime is ahead by at least the threshold plus the running
 * slice is past the tail, else wake idle. 11 counts preempt kicks,
 * 12 counts idle kicks, 13 counts skips with no wake. Preempt is not
 * counted as steal. Kick validates the target first and skips when no
 * allowed CPU exists so an offline or disallowed target never takes
 * a wake. Allowed implies within bounds, so the not-ok early skip
 * keeps the base idle-path outcome of no wake while counting it.
 * No knob with fail closed choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_PREEMPT_BPF_H
#define __FLOW_PREEMPT_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"

/* Preempt when the running vtime is ahead by at least the threshold */
/* and the running slice is past the tail. Uses unsigned gap so the */
/* compare stays valid across wrap. Preempt is not counted as steal. */
/* Kick preempts only when the target is allowed, else it wakes idle. */
/* Idle kick validates the target first and skips when no allowed CPU */
/* exists so an offline or disallowed target never takes a wake. */
static __always_inline void flow_kick_for_enq(s32 task_cpu, s64 use_v,
					     struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;
	u64 gap;
	if (task_cpu < 0) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_allowed(task_cpu, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu)) {
		flow_stat_inc(llc, 13);
		return;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	if (rs->vtime <= use_v)
		goto idle;
	gap = (u64)(rs->vtime - use_v);
	if (gap >= (u64)FLOW_PREEMPT_THRESH) {
		scx_bpf_kick_cpu(task_cpu, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 11);
		return;
	}
idle:
	if (!flow_cpu_allowed(task_cpu, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
	flow_stat_inc(llc, 12);
}

/* Wake idle only for inserts without task context. No preempt. */
static __always_inline void flow_kick_idle_only(s32 task_cpu,
					       struct task_struct *p, u32 llc)
{
	if (task_cpu < 0) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_allowed(task_cpu, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
	flow_stat_inc(llc, 12);
}

#endif
