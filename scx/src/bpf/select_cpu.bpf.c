// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op.
 *
 * Placement keeps the waker CPU when idle and allowed, then any idle
 * CPU, then the previous CPU when shallow, else the shallowest same
 * cache peer over bound 8, then the first allowed CPU. Pinned tasks
 * stay where the mask allows with no scan, and the task mask always
 * wins. An empty mask falls through to the global queue at enqueue.
 * Topology stays display only except the cache domain used here.
 * See enqueue.bpf.c for the lane choice after select.
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
	/* The previous CPU keeps cache warmth when shallow and allowed. */
	/* Fast plus deadline past 4 plus 12 scans the cache domain. */
	if (flow_cpu_ok(p, prev_cpu)) {
		s32 qf = scx_bpf_dsq_nr_queued(
		    flow_fast_dsq((u32)prev_cpu));
		s32 qv = scx_bpf_dsq_nr_queued(
		    flow_vtime_dsq((u32)prev_cpu));
		u64 depth = 0;
		if (qf > 0)
			depth += (u64)qf;
		if (qv > 0)
			depth += (u64)qv;
		if (depth < (u64)FLOW_FAST_D +
		    (u64)FLOW_OWN_VTIME_CAP)
			return prev_cpu;
	}
	/* A deep previous CPU scans the same cache domain bound 8. */
	/* The shallowest live allowed peer wins with salt spread. */
	/* The waker cursor steps by 8 with wrap, so passes spread. */
	{
		u64 nr = nr_cpu_ids;
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		struct flow_topo *wtp = flow_topo((u32)this_cpu);
		u32 want = wtp ? wtp->llc : 0;
		u32 cursor = wst ? wst->cursor : 0;
		u32 salt = 0;
		u32 start = 0;
		u32 best = 0xffffffffU;
		u64 best_depth = 0xffffffffffffffffULL;
		u32 off;
		if (nr > 1 && nr <= (u64)FLOW_MAX_CPUS) {
			u32 n = (u32)nr;
			salt = bpf_get_prandom_u32() % n;
			start = (cursor + 1U + salt) % n;
			bpf_for(off, 0, FLOW_STEAL_BOUND) {
				u32 peer = (start + off) % n;
				struct flow_topo *ptp;
				s32 pf;
				s32 pv;
				u64 pd = 0;
				if (peer == (u32)this_cpu)
					continue;
				if (!flow_cpu_ok(p, (s32)peer))
					continue;
				ptp = flow_topo(peer);
				if (ptp && wtp && ptp->llc != want)
					continue;
				pf = scx_bpf_dsq_nr_queued(
				    flow_fast_dsq(peer));
				pv = scx_bpf_dsq_nr_queued(
				    flow_vtime_dsq(peer));
				if (pf > 0)
					pd += (u64)pf;
				if (pv > 0)
					pd += (u64)pv;
				if (pd < best_depth) {
					best_depth = pd;
					best = peer;
				}
			}
			if (wst)
				wst->cursor = (start + 8U) % n;
			if (best != 0xffffffffU)
				return (s32)best;
		}
	}
	/* A shallow scan miss keeps the previous CPU when allowed. */
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	/* The first allowed CPU is the fail closed fallback. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return prev_cpu;
}
