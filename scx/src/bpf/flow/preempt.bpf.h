// SPDX-License-Identifier: GPL-2.0
/*
 * Flow kick helpers with steal-outcome split.
 *
 * Moved from main with an LLC param for per LLC counting. Predicates
 * are unchanged: preempt only when the target is allowed plus the
 * running vtime is ahead by at least the threshold plus the running
 * slice is past the tail, else wake idle. Pinned uses a fast path that
 * preempts when the target runs a task past the tail with no vtime gap
 * check, since a pinned wait cannot run elsewhere. A streak at or above
 * the pop retry bound turns an idle wake into a preempt so a hold ends.
 * 11 counts preempt kicks, 12 counts idle kicks, 13 counts skips with no
 * wake, 17 counts streak preempts. Preempt is not counted as steal. Kick
 * validates the target first and skips when no allowed CPU exists so an
 * offline or disallowed target never takes a wake. Allowed implies within
 * bounds, so the not-ok early skip keeps the base idle-path outcome of no
 * wake while counting it. No knob with fail closed choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_PREEMPT_BPF_H
#define __FLOW_PREEMPT_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"

/* Constrained kick to the allowed live target only. Preempts when the */
/* running vtime is ahead by at least the threshold past the tail, */
/* else wakes idle. A streak at or above the pop retry bound turns the */
/* idle path into a preempt so a hold ends. Skips with no wake when no */
/* allowed live target exists. The idle path re-validates after the */
/* preempt test so a mask change between pick and kick never takes an */
/* off mask wake. Overlap is intentional. */
static __always_inline void flow_kick_constrained(s32 tgt, s64 use_v,
						  struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;
	u64 gap;

	if (tgt < 0) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
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
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 11);
		return;
	}
idle:
	/* Streak escalation. A CPU that keeps burning full slices holds the */
	/* head past the normal gap test, so a streak at or above the bound */
	/* preempts with no gap check. Counts the escape in addition to the */
	/* preempt so the hold stays visible. */
	if (rs->gen != 0 && rs->hog_streak >= (u32)FLOW_POP_RETRY_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 13);
			return;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 13);
			return;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 11);
		flow_stat_inc(llc, 17);
		return;
	}
	/* Re-validation keeps an off mask wake out when the mask changes */
	/* between pick and kick. Bound overlap with live is intentional. */
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 13);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 12);
}

/* Pinned kick to the allowed live target only. Preempts at once when a */
/* task runs past the tail with no vtime gap check, since a pinned wait */
/* cannot run elsewhere. An empty target wakes idle. A tail target with a */
/* streak at or above the bound preempts so a hold ends. Skips with no */
/* wake when no allowed live target exists. Re-validates before each wake */
/* so a mask change never takes an off mask wake. */
static __always_inline void flow_kick_pinned(s32 tgt, s64 use_v,
					     struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;

	(void)use_v;
	if (tgt < 0) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
		flow_stat_inc(llc, 13);
		return;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 11);
	return;
idle:
	/* Streak escalation shares the constrained rule with the same bound */
	/* and the same escape count so a pinned hold ends with no new knob. */
	if (rs->gen != 0 && rs->hog_streak >= (u32)FLOW_POP_RETRY_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 13);
			return;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 13);
			return;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 11);
		flow_stat_inc(llc, 17);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 13);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 12);
}

/* Preempt when the running vtime is ahead by at least the threshold */
/* and the running slice is past the tail. Uses unsigned gap so the */
/* compare stays valid across wrap. Preempt is not counted as steal. */
/* Kick preempts only when the target is allowed, else it wakes idle. */
/* Idle kick validates the target first and skips when no allowed CPU */
/* exists so an offline or disallowed target never takes a wake. */
static __always_inline void flow_kick_for_enq(s32 task_cpu, s64 use_v,
					      struct task_struct *p, u32 llc)
{
	s32 tgt = flow_constrained_target(task_cpu, p);

	flow_kick_constrained(tgt, use_v, p, llc);
}

/* Wake idle only for inserts without task context. No preempt. */
/* No running state lookup keeps the wake cheap. Re-validation keeps off */
/* mask wakes out when the mask changes between pick and kick. Bound */
/* overlap with live is intentional, live adds the init count range. */
static __always_inline void flow_kick_idle_only(s32 task_cpu,
						struct task_struct *p, u32 llc)
{
	s32 tgt = flow_constrained_target(task_cpu, p);

	if (tgt < 0) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 13);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 13);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 12);
}

/* Kick budgets stay threshold 500us plus tail 125us with */
/* per LLC 11 preempt, 12 idle, 13 skip plus 17 escape, preempt never */
/* counted as steal. Pinned preempts past the tail with no gap check. */
/* Docs only, no logic change. */

#endif
