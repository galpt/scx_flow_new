// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU thin wrapper over the SSF placement.
 *
 * Takes idle first with no state cost, then the previous CPU when it
 * meets the deadline, then the slowest sufficient fit in O(VISIT) with
 * VISIT at most eight peers in two node-local phases, then the best
 * sufficient fallback over the next four peers past the SSF window from
 * cursor plus 9 with drain plus minimum plus id tiebreak. The two scans
 * cover twelve unique peers with no overlap when the host holds at
 * least twelve CPUs, else the windows wrap, so the fallback extends
 * coverage instead of rescanning. The shared cursor with dispatch steal
 * advances by two with best effort races and no atomic order. Pinned
 * tasks stay where the mask allows with no scan. An empty mask falls
 * through to the machine tier at enqueue. One ktime read serves the
 * previous plus SSF plus BSF checks, and pow2 hosts mask with no divide.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_select_best - slowest plus best sufficient pick in one call.
 * @p: task to place.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU for the cursor plus the self skip.
 *
 * Runs the SSF scan over eight peers from the cursor plus the disjoint
 * BSF fallback over the next four past the SSF window from cursor plus
 * 9, so twelve unique peers hold with no overlap on large hosts. The
 * shared cursor with steal advances by two on success with best effort
 * races, so passes spread with no hotspot. Outlined with noinline to
 * keep verifier headroom on the select path with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_select_best(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu)
{
	u64 nr = nr_cpu_ids;
	struct flow_cpu_state *wst = flow_cpu(this_cpu);
	u32 cursor = wst ? READ_ONCE(wst->cursor) : 0;
	u32 best;
	u32 bsf;
	u32 n;
	bool pow2;
	u32 start;
	u32 next;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return 0xffffffffU;
	n = (u32)nr;
	pow2 = flow_is_pow2((u64)n);
	if (pow2) {
		start = (u32)(((u64)cursor + 1ULL) & ((u64)n - 1ULL));
		next = (u32)(((u64)start + 1ULL) & ((u64)n - 1ULL));
	} else {
		start = (u32)(((u64)cursor + 1ULL) % (u64)n);
		next = (u32)(((u64)start + 1ULL) % (u64)n);
	}
	(void)start;
	best = flow_ssf_pick(p, deadline, now, this_cpu, cursor, nr);
	if (best != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return best;
	}
	bsf = flow_bsf_pick(p, deadline, now, this_cpu, cursor, nr);
	if (bsf != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return bsf;
	}
	return 0xffffffffU;
}
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
		u32 best;
		if (flow_cpu_ok(p, prev_cpu)) {
			if (flow_cpu_meets((u32)prev_cpu, deadline, now))
				return prev_cpu;
		}
		/* Shared SSF plus disjoint BSF in one outlined call with no */
		/* topology signal, so select keeps twelve peer coverage. */
		best = flow_select_best(p, deadline, now, (u32)this_cpu);
		if (best != 0xffffffffU)
			return (s32)best;
	}
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
