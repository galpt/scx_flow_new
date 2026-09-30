// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op for the flow core.
 *
 * Keeps the previous CPU when allowed and live. Falls back to the
 * first allowed live CPU. Stale masks fail closed with an error and
 * one gate count so callers never run on a stale CPU. The daemon owns
 * placement. The core keeps mask wins and progress. One fallback
 * helper pairs the previous plus first checks with the gate count
 * through one exit so a missed gate cannot slip through.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fallback with previous, first, gate in one place. */
/* Gives previous when allowed and live else first when allowed */
/* and live else error with one gate count. Callers reach the gate */
/* solely here so every failure counts once with no missed reject. */
static __always_inline s32 flow_fallback_cpu(
	const struct task_struct *p, s32 prev_cpu)
{
	s32 first;
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return -EINVAL;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 here;
	(void)wake_flags;
	if (is_migration_disabled(p) || p->nr_cpus_allowed == 1) {
		here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		return flow_fallback_cpu(p, prev_cpu);
	}
	return flow_fallback_cpu(p, prev_cpu);
}
