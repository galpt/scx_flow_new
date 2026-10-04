// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU thin wrapper over the SSF placement.
 *
 * Takes idle first with no state cost, then the previous CPU when it
 * meets the deadline, then the slowest sufficient fit in O(VISIT) with
 * VISIT at most eight peers, then the best sufficient fallback in at
 * most four peers with no topology signal. Pinned tasks stay where the
 * mask allows with no scan. An empty mask falls through to the machine
 * tier at enqueue. One ktime read serves the previous plus SSF plus BSF
 * checks, and pow2 hosts mask with no divide.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 first;
	u64 deadline = 0;
	struct flow_task_ctx *tctx;
	(void)wake_flags;
	this_cpu = (s32)bpf_get_smp_processor_id();
	if (unlikely(is_migration_disabled(p))) {
		s32 here = scx_bpf_task_cpu(p);
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
	if (unlikely(p->nr_cpus_allowed == 1)) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		flow_gate_reject();
		return prev_cpu;
	}
	if (likely(flow_cpu_ok(p, this_cpu))) {
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		if (wst && READ_ONCE(wst->running_pid) == 0)
			return this_cpu;
	}
	{
		s32 picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (picked >= 0 && flow_cpu_ok(p, picked))
			return picked;
	}
	tctx = flow_lookup(p);
	if (likely(tctx))
		deadline = READ_ONCE(tctx->deadline);
	if (unlikely(deadline == 0) && likely(flow_cpu_ok(p, prev_cpu)))
		return prev_cpu;
	/* One ktime serves previous plus SSF plus BSF with no second read. */
	/* Early exit on the previous CPU avoids both scans when it meets, */
	/* so the common stay keeps one drain check with no peer walk. */
	{
		u64 now = flow_now();
		if (flow_cpu_ok(p, prev_cpu)) {
			if (flow_cpu_meets((u32)prev_cpu, deadline, now))
				return prev_cpu;
		}
		/* Shared SSF scan in O(VISIT) with VISIT at most eight plus */
		/* the BSF fallback in at most four with no topology signal. */
		/* The cursor spreads passes with no hotspot and races best */
		/* effort. Pow2 hosts mask with no divide, others modulo. */
		{
			u64 nr = nr_cpu_ids;
			struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
			u32 cursor = wst ? READ_ONCE(wst->cursor) : 0;
			u32 best;
			u32 bsf;
			if (nr > 1 && nr <= (u64)FLOW_MAX_CPUS) {
				u32 n = (u32)nr;
				u32 start = flow_wrap_idx((u64)cursor + 1ULL, n);
				u32 next = flow_wrap_idx((u64)start + 1ULL, n);
				best = flow_ssf_pick(p, deadline, now,
				    (u32)this_cpu, cursor, nr);
				if (best != 0xffffffffU) {
					if (wst)
						__sync_lock_test_and_set(&wst->cursor,
						    next);
					return (s32)best;
				}
				/* BSF fallback with the smallest drain and no */
				/* topology walk, so symmetric hosts still spread. */
				/* Capped at four peers, so the fallback halves */
				/* the scan cost with the same order. */
				bsf = flow_bsf_pick(p, deadline, now,
				    (u32)this_cpu, cursor, nr);
				if (bsf != 0xffffffffU) {
					if (wst)
						__sync_lock_test_and_set(&wst->cursor,
						    next);
					return (s32)bsf;
				}
			}
		}
	}
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
