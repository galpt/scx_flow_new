// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;
	(void)wake_flags;
	this_cpu = (s32)bpf_get_smp_processor_id();
	/* Pinned tasks stay where the mask allows with no scan. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		return prev_cpu;
	}
	/* Single mask tasks keep the same pinned path with no scan. */
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		return prev_cpu;
	}
	/* The waker CPU is free when it runs nothing and the mask allows. */
	/* An idle core cannot stack so locality stays free with no cost. */
	if (flow_cpu_ok(p, this_cpu)) {
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		if (wst && wst->running_pid == 0)
			return this_cpu;
	}
	/* One idle scan only with no depth or group pass. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0 && flow_cpu_ok(p, picked))
		return picked;
	/* The previous CPU keeps cache warmth when the mask allows. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* The first allowed CPU is the fail closed fallback. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return prev_cpu;
}
