/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Placement, included by main.bpf.c via include.
 *
 * Idle choice prefers the idle prior Cpu with no
 * count, then the previous LLC domain, then any idle
 * Cpu, then the previous Cpu, the current Cpu, and
 * the first allowed Cpu. Pinned tasks and tasks that
 * cannot move stay local with a park hint when no Cpu
 * allows.
 */

/*
 * Idle Cpu in the same LLC as the previous Cpu.
 * Skips the second thread of a busy core when the
 * idle set marks fully idle cores. Returns minus
 * one when no LLC idle Cpu is found. Single and
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

		/* Negative check stays for the verifier with */
		/* no behavior change, since the loop starts */
		/* at zero. */
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
	/* Single Cpu ends at the first allowed Cpu. */
	/* Tasks that cannot move stay on the current Cpu. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		/* No allowed Cpu, park hint for enqueue. */
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
		/* The single allowed Cpu is the valid hint. */
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		/* No allowed Cpu, park hint for enqueue. */
		return prev_cpu;
	}
	/* Sticky idle prior reuse with no count. */
	if ((u64)FLOW_GATE_STICKY && flow_cpu_ok(p, prev_cpu)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;
	}
	/* Sticky batching keeps near deadlines on prior. */
	/* The window is tiny past the mean floor, so a */
	/* batch keeps warmth with no fair loss. Fresh */
	/* tasks with no deadline skip batch at once. */
	if ((u64)FLOW_GATE_IEDF && flow_cpu_ok(p, prev_cpu)) {
		struct flow_task_ctx *batch_tctx;
		struct flow_cpu_state *batch_st;

		batch_tctx = flow_lookup(p);
		batch_st = flow_cpu((u32)prev_cpu);
		if (batch_tctx && batch_st && batch_tctx->deadline != 0) {
			if (flow_batch_within(batch_tctx->deadline,
			    batch_st->frontier))
				return prev_cpu;
		}
	}
	/* Prefer an idle Cpu in the previous LLC domain. */
	/* Single and unknown hosts skip the LLC step. */
	llc_pick = flow_llc_idle(p, prev_cpu);
	if (llc_pick >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, llc_pick))
			return llc_pick;
	}
	/* Prefer an idle Cpu inside the mask. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0) {
		/* Idle choice honors the mask, recheck is safe. */
		if (flow_cpu_ok(p, picked))
			return picked;
	}
	/* Fall back to the previous Cpu when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* Fall back to the current Cpu when allowed. */
	if (flow_cpu_ok(p, this_cpu))
		return this_cpu;
	/* Try the first allowed Cpu when allowed. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	/* No allowed Cpu, park hint for enqueue. */
	return prev_cpu;
}
