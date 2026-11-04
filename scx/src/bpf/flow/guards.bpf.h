// SPDX-License-Identifier: GPL-2.0
/*
 * Flow placement guards.
 *
 * Moved from main with predicates unchanged. Null inputs fail closed
 * with no move. No SMT probe runs and each CPU stands single.
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

/* True when the peeked head of a DSQ can run on cpu. Null peek fails */
/* closed with no move. This keeps a pinned head on its allowed CPU and */
/* skips a steal that would run off mask with no loss. Peek is hint only */
/* but pinned tasks wait in per CPU local queues so shared heads are */
/* migratable in the common case. */
static __always_inline bool flow_dsq_head_allowed(u64 dsq, u32 cpu)
{
	struct task_struct *p;
	if (!flow_cpu_ok(cpu))
		return false;
	p = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!p)
		return false;
	return flow_cpu_allowed((s32)cpu, p);
}

#endif
