// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline plus fair helpers for the core.
 *
 * Holds the deadline plus fair time plus drain readiness checks with
 * saturating math. Every task joins a tier queue with no bound, and
 * queue order plus tier choice use the fair key while placement tests
 * the deadline. Drain sums local plus node with saturation, so a busy
 * node holds the local tier with no wait. The CPU minimum read stays
 * best effort with zero on miss. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task still meets its deadline from the given time. */
/* A zero deadline means no order yet, so the check passes with no */
/* miss. A time past the deadline fails, so the caller rejoins a tier. */
static __always_inline bool flow_deadline_ok(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return true;
	if (flow_time_before(now, deadline))
		return true;
	if (now == deadline)
		return true;
	return false;
}
/* Minimum vruntime of one CPU with zero on miss. */
/* A missing row means no history, so zero keeps new tasks eligible. */
static __always_inline u64 flow_cpu_min(u32 cpu)
{
	struct flow_cpu_state *st = flow_cpu(cpu);
	if (!st)
		return 0;
	return READ_ONCE(st->min_vruntime);
}
/* Drain depth of one CPU as queued slices times the quantum. */
/* Saturates on wrap, so a huge depth clamps instead of wrapping to */
/* an idle view. A bad read drops to zero with no boost. */
static __always_inline u64 flow_drain_ns(u64 dsq)
{
	s32 n = scx_bpf_dsq_nr_queued(dsq);
	u64 depth;
	if (n <= 0)
		return 0;
	depth = (u64)n;
	if (depth > (u64)~0ULL / (u64)FLOW_QUANTUM_NS)
		return (u64)~0ULL;
	return depth * (u64)FLOW_QUANTUM_NS;
}
/* Combined drain of one CPU as local plus node with saturation. */
/* Sums both depths, so a busy node holds the local tier with no wait. */
/* A missing node reads zero with no boost. Sparse nodes fold to zero. */
static __always_inline u64 flow_cpu_drain(u32 cpu)
{
	u64 local = flow_drain_ns(flow_local_dsq(cpu));
	u32 node = flow_cpu_node(cpu);
	u64 shared = 0;
	if (node < (u32)FLOW_MAX_NODES &&
	    (u64)node < nr_node_ids)
		shared = flow_drain_ns(flow_node_dsq(node));
	return flow_sat_add(local, shared);
}
/* True when one CPU can finish its local plus node drain before a deadline. */
/* Adds now plus combined drain with saturation, so a huge drain fails */
/* closed with no wrap to an early view. */
static __always_inline bool flow_cpu_meets(u32 cpu,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_cpu_drain(cpu);
	ready = flow_sat_add(now, drain);
	if (ready == (u64)~0ULL)
		return false;
	if (flow_time_before(ready, deadline))
		return true;
	if (ready == deadline)
		return true;
	return false;
}
/* True when one CPU can finish its local plus node drain before a fair time. */
/* Mirrors the deadline check for the fair key, so the bypass plus the tier */
/* choice test fair order while placement tests the deadline. A zero fair */
/* time means no fair order yet, so the check passes with no gate. */
static __always_inline bool flow_cpu_meets_fair(u32 cpu,
	u64 vtime, u64 now)
{
	u64 drain;
	u64 ready;
	if (vtime == 0)
		return true;
	drain = flow_cpu_drain(cpu);
	ready = flow_sat_add(now, drain);
	if (ready == (u64)~0ULL)
		return false;
	if (flow_time_before(ready, vtime))
		return true;
	if (ready == vtime)
		return true;
	return false;
}
