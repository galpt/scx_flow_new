/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Placement, included by main.bpf.c via include.
 *
 * Idle choice prefers the previous LLC domain, then
 * any idle CPU, then the previous CPU, the current
 * CPU, and the first allowed CPU. Pinned tasks and
 * tasks that cannot move stay local with a park hint
 * when no CPU allows.
 */

/*
 * Idle CPU in the same LLC as the previous CPU.
 * Skips the second thread of a busy core when the
 * idle set marks fully idle cores. Returns minus
 * one when no LLC idle CPU is found. Single and
 * unknown hosts return at once with no scan.
 */
static s32 flow_llc_idle(const struct task_struct *p,
	s32 prev_cpu)
{
	u32 want;
	const struct cpumask *idle_smt;
	s32 cpu;
	s32 found = -1;

	if (!flow_llc_ok(flow_llc_nr))
		return -1;
	if (prev_cpu < 0)
		return -1;
	if ((u32)prev_cpu >= (u32)FLOW_MAX_CPUS)
		return -1;
	if ((u64)prev_cpu >= nr_cpu_ids)
		return -1;
	want = flow_cpu_llc[(u32)prev_cpu];
	if (!flow_llc_known(want))
		return -1;
	idle_smt = scx_bpf_get_idle_smtmask();
	bpf_for(cpu, 0, 1024) {
		u32 id;

		if (cpu < 0)
			continue;
		if ((u32)cpu >= (u32)FLOW_MAX_CPUS)
			break;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		id = flow_cpu_llc[(u32)cpu];
		if (id != want)
			continue;
		if (!flow_cpu_ok(p, cpu))
			continue;
		if (idle_smt) {
			if (!bpf_cpumask_test_cpu((u32)cpu,
			    idle_smt))
				continue;
		}
		if (scx_bpf_test_and_clear_cpu_idle(cpu)) {
			found = cpu;
			break;
		}
	}
	if (idle_smt)
		scx_bpf_put_idle_cpumask(idle_smt);
	return found;
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;
	s32 llc_pick;

	this_cpu = (s32)bpf_get_smp_processor_id();
	/* Single CPU ends at the first allowed CPU. */
	/* Tasks that cannot move stay on the current CPU. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		/* No allowed CPU, park hint for enqueue. */
		return prev_cpu;
	}
	/* Pinned tasks stay where they are. */
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		/* The single allowed CPU is the valid hint. */
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		/* No allowed CPU, park hint for enqueue. */
		return prev_cpu;
	}
	/* Prefer an idle CPU in the previous LLC domain. */
	/* Single and unknown hosts skip the LLC step. */
	llc_pick = flow_llc_idle(p, prev_cpu);
	if (llc_pick >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, llc_pick))
			return llc_pick;
	}
	/* Prefer an idle CPU inside the mask. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, picked))
			return picked;
	}
	/* Fall back to the previous CPU when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* Fall back to the current CPU when allowed. */
	if (flow_cpu_ok(p, this_cpu))
		return this_cpu;
	/* Try the first allowed CPU when allowed. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	/* No allowed CPU, park hint for enqueue. */
	return prev_cpu;
}
