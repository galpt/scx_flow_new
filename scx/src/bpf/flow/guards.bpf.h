// SPDX-License-Identifier: GPL-2.0
/*
 * Flow placement guards.
 *
 * Predicates for pinning, mask membership, and liveness, plus the
 * yield history helpers. Null inputs fail closed. Each CPU is
 * treated singly with no sibling probe.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_GUARDS_BPF_H
#define __FLOW_GUARDS_BPF_H

#include "../intf.h"

/**
 * flow_is_pinned - check whether a task cannot migrate.
 * @p: task to test, may be NULL.
 *
 * A task with one allowed CPU or disabled migration must run where
 * it is queued.
 *
 * Returns: true when pinned, else false.
 */
static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}

/**
 * flow_cpu_allowed - check mask membership.
 * @cpu: CPU to test.
 * @p: task carrying the mask.
 *
 * Returns: true when the CPU is in the mask, else false.
 */
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

/**
 * flow_cpu_live - check the seeded CPU range.
 * @cpu: CPU to test.
 *
 * Init seeds one row per discovered CPU and the count stays fixed,
 * so a CPU past the count needs a restart. Before init the count
 * reads zero and every bound CPU reads live, which is safe since
 * init seeds the count before any queue use.
 *
 * Returns: true when the CPU is usable, else false.
 */
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

/**
 * flow_first_allowed - first live allowed CPU in the mask.
 * @p: task carrying the mask.
 *
 * Returns: the CPU id, or minus one when none exists.
 */
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

/**
 * flow_constrained_target - queue and kick target for a task.
 * @hint: preferred CPU, usually where the task woke.
 * @p: task carrying the mask.
 *
 * Keeps the hint when it stays allowed and live, else falls back
 * to the first allowed live CPU.
 *
 * Returns: the target CPU, or minus one when none exists.
 */
static __always_inline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}

/**
 * flow_hist_is_lat - classify the yield history.
 * @hist: three bit record of recent stops.
 *
 * Two of three early yields read as latency sensitive, else the
 * task reads as a hog. Fresh zero reads as a hog, so a new task
 * proves latency with early yields first.
 *
 * Returns: true for latency, else false.
 */
static __always_inline bool flow_hist_is_lat(u8 hist)
{
	u32 b0 = (u32)(hist & 1U);
	u32 b1 = (u32)((hist >> 1) & 1U);
	u32 b2 = (u32)((hist >> 2) & 1U);
	return b0 + b1 + b2 >= 2U;
}

/**
 * flow_hist_push - shift one stop outcome into the history.
 * @hist: current record.
 * @bit: one for an early yield, zero for a full burn.
 *
 * Returns: the updated record.
 */
static __always_inline u8 flow_hist_push(u8 hist, u8 bit)
{
	return (u8)(((hist << 1) | (bit & 1U)) & 7U);
}

#endif
