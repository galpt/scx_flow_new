// SPDX-License-Identifier: GPL-2.0
/*
 * Flow placement guards.
 *
 * Moved from main with predicates unchanged. Null inputs fail closed
 * with no move. No SMT probe runs and each CPU stands single. History
 * helpers classify the three bit yield record with bit math only and
 * never move placement on their own.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_GUARDS_BPF_H
#define __FLOW_GUARDS_BPF_H

#include "../intf.h"

/* Pinned when only one CPU is allowed or migration is disabled. */
/* Null task fails closed with no bypass. */
static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}

/* True when cpu is in the task mask. Null mask fails closed. */
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

/* Live CPU needs bound plus init count range. Hotplug beyond needs restart. */
/* Init seeds one row per discovered CPU and the count stays fixed, so a */
/* CPU at or beyond the count fails closed with no wake. Offline inside */
/* the range also needs restart and stays scoped there. Head checks use */
/* a single peek plus an allowed test at the caller with no helper, so */
/* no second peek runs. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	u64 n;

	if (!flow_cpu_ok(cpu))
		return false;
	n = READ_ONCE(flow_nr_cpus);
	if (n && (u64)cpu >= n)
		return false;
	return true;
}

/* First allowed CPU in the task mask. Fails closed to minus one */
/* with no move when no allowed live target exists. Live keeps the */
/* init range so a beyond range CPU never takes a wake. */
static __always_inline s32 flow_first_allowed(struct task_struct *p)
{
	u32 first;

	if (!p || !p->cpus_ptr)
		return -1;
	first = bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_live(first))
		return -1;
	if (!flow_cpu_allowed((s32)first, p))
		return -1;
	return (s32)first;
}

/* Constrained target for inserts plus kicks. Keeps the hint when it */
/* stays allowed and live, else falls back to the first allowed live */
/* CPU. Fails closed to minus one with no move when no target exists. */
static __always_inline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}

/* Latency test on the three bit history. Two of three yield bits read */
/* as latency, else the task holds as a hog. Fresh zero reads as a hog */
/* so a new task proves latency with early yields first. Bit math only */
/* with no loop and no map use. */
static __always_inline bool flow_hist_is_lat(u8 hist)
{
	u32 b0 = (u32)(hist & 1U);
	u32 b1 = (u32)((hist >> 1) & 1U);
	u32 b2 = (u32)((hist >> 2) & 1U);
	return b0 + b1 + b2 >= 2U;
}

/* Shift one yield bit into the three bit history. A stop with remain */
/* records one for an early yield, a full burn records zero. Keeps only */
/* the newest three bits with no wrap past the mask. */
static __always_inline u8 flow_hist_push(u8 hist, u8 bit)
{
	return (u8)(((hist << 1) | (bit & 1U)) & 7U);
}

/* Guards fail closed on null plus out of bound, no SMT */
/* probe runs, each CPU stands single. Pinned plus constrained kicks reuse */
/* the same guards with no new shape. Docs only, no logic change. */

#endif
