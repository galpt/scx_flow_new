// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op.
 *
 * Placement keeps the waker CPU when idle and allowed, then any
 * idle CPU, then a cache scan, then the previous CPU, then the
 * first allowed CPU. The scan walks bound 8 same cache peers from
 * a cursor plus salt start with one depth probe per peer, and the
 * shallowest peer wins only when strictly shallower than previous,
 * so warmth never loses to a tie. Pinned tasks stay where the mask
 * allows with no scan, and the task mask always wins. An empty
 * mask falls through to the global queue at enqueue. Topology
 * stays display only except the cache domain used here. See
 * enqueue.bpf.c for the deadline choice after select.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;
	bool prev_ok;
	u64 prev_depth = 0xffffffffffffffffULL;
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
	/* The pid read uses a relaxed load to match the running stores. */
	if (flow_cpu_ok(p, this_cpu)) {
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		if (wst && READ_ONCE(wst->running_pid) == 0)
			return this_cpu;
	}
	/* One idle scan only with no depth pass. */
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0 && flow_cpu_ok(p, picked))
		return picked;
	/* Previous depth comes from one deadline probe with no scan. */
	prev_ok = flow_cpu_ok(p, prev_cpu);
	if (prev_ok) {
		s32 qv = scx_bpf_dsq_nr_queued(
		    flow_vtime_dsq((u32)prev_cpu));
		if (qv > 0)
			prev_depth = (u64)qv;
		else
			prev_depth = 0;
	}
	/* A missing previous CPU still scans with max depth. */
	/* The shallowest live allowed peer wins only when strictly */
	/* shallower than previous, so warmth never loses to a tie. */
	/* A missing domain view fails open to the same domain. */
	/* Live is the attach snapshot with no online read, so a stale */
	/* pick still lands with mask wins at enqueue. */
	/* The scan pays at most eight probes with one per peer. */
	/* An empty peer stops the scan with no further probe. */
	/* The waker cursor steps by 8 with wrap, so passes spread. */
	/* The cursor advances only on a hit with no ABI change, */
	/* so misses skip the store with no correctness use. */
	/* The cursor races best effort with no atomic order, so a lost */
	/* update only shifts the next start with no correctness use. */
	{
		u64 nr = nr_cpu_ids;
		struct flow_cpu_state *wst = flow_cpu((u32)this_cpu);
		struct flow_topo *wtp = flow_topo((u32)this_cpu);
		u32 want = wtp ? wtp->llc : 0;
		u32 cursor = wst ? READ_ONCE(wst->cursor) : 0;
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
				s32 pv;
				u64 pd;
				if (peer == (u32)this_cpu)
					continue;
				if (!flow_cpu_ok(p, (s32)peer))
					continue;
				ptp = flow_topo(peer);
				if (ptp && wtp && ptp->llc != want)
					continue;
				/* One depth probe per peer, vtime only. */
				/* An empty peer ends the scan at once. */
				pv = scx_bpf_dsq_nr_queued(
				    flow_vtime_dsq(peer));
				if (pv < 0)
					continue;
				pd = (u64)pv;
				if (pd < best_depth) {
					best_depth = pd;
					best = peer;
					if (pd == 0)
						break;
				}
			}
			if (wst && best != 0xffffffffU)
				__sync_lock_test_and_set(
				    &wst->cursor,
				    (start + 8U) % n);
			if (best != 0xffffffffU) {
				if (!prev_ok || best_depth < prev_depth)
					return (s32)best;
			}
		}
	}
	/* A scan miss or a deeper peer keeps the previous CPU when allowed. */
	if (prev_ok)
		return prev_cpu;
	/* The first allowed CPU is the fail closed fallback. */
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return prev_cpu;
}
