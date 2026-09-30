// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op for the thin core.
 *
 * Keeps the previous CPU when allowed and live. Falls back to the
 * first allowed live CPU. Stale masks fail closed to the previous CPU
 * with one gate count. The daemon owns placement. The core keeps mask
 * wins and progress.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 here;
	s32 first;
	(void)wake_flags;
	if (is_migration_disabled(p)) {
		here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		flow_gate_reject();
		return prev_cpu;
	}
	if (p->nr_cpus_allowed == 1) {
		here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		flow_gate_reject();
		return prev_cpu;
	}
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
