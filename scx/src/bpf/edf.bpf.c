// SPDX-License-Identifier: GPL-2.0
/*
 * EDF deadline plus eligibility plus hoisted drain for the core.
 *
 * Holds the burst predictor plus the absolute deadline plus the fair
 * key plus the eligibility gate. Every task earns a deadline from the
 * predictor else the hint period, and queue order uses the earlier of
 * deadline plus virtual deadline with a 2ms lag bound. Eligibility
 * gates every kick, so hogs pace while lagging tasks wake. Drain sums
 * local plus node with saturation, so a busy node holds the local tier
 * with no wait. Hoisted depths feed the same drain with no second poll,
 * so enqueue bypass plus tier escalation share one read. Runs under the
 * caller with no lock.
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
/* Drain nanos from a hoisted queued hint with no kfunc. */
/* Non-positive hints read zero with no boost. Saturates on wrap, so a */
/* huge depth clamps instead of wrapping to an idle view. */
static __always_inline u64 flow_drain_from_q(s32 n)
{
	u64 depth;
	if (n <= 0)
		return 0;
	depth = (u64)n;
	if (depth > (u64)~0ULL / (u64)FLOW_QUANTUM_NS)
		return (u64)~0ULL;
	return depth * (u64)FLOW_QUANTUM_NS;
}
/**
 * flow_cpu_drain_hint - combined drain from hoisted local plus node.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 *
 * Sums both drains with saturation and no kfunc, so a busy node holds
 * the local tier with no wait on the same reads as the bypass gate.
 *
 * Returns: combined drain in nanos.
 */
static __always_inline u64 flow_cpu_drain_hint(s32 local_q, s32 node_q)
{
	return flow_sat_add(flow_drain_from_q(local_q),
	    flow_drain_from_q(node_q));
}
/**
 * flow_cpu_drain - combined drain of one CPU as local plus node.
 * @cpu: CPU id below the 1024 bound.
 *
 * Sums both depths with saturation, so a busy node holds the local
 * tier with no wait. A missing node reads zero with no boost, and
 * sparse nodes fold to zero.
 *
 * Outlined with noinline to keep verifier headroom: callers in meets
 * plus fair plus BSF share one copy with no inline growth.
 *
 * Returns: combined drain in nanos.
 */
static __noinline u64 flow_cpu_drain(u32 cpu)
{
	u64 local = flow_drain_ns(flow_local_dsq(cpu));
	u32 node = flow_cpu_node((u32)cpu);
	u64 shared = 0;
	if (node < (u32)FLOW_MAX_NODES &&
	    (u64)node < nr_node_ids)
		shared = flow_drain_ns(flow_node_dsq(node));
	return flow_sat_add(local, shared);
}
/**
 * flow_ready_before - test ready time against deadline with wrap safety.
 * @ready: ready time in nanos, max fails closed.
 * @deadline: absolute deadline in nanos.
 *
 * Fails closed on saturated ready, else wrap safe before plus equal,
 * so a huge drain never reads as early with no wrap to the front.
 *
 * Outlined with noinline to share one compare copy across drain plus
 * deadline checks with no inline growth and no order change.
 *
 * Returns: true when @ready falls before or on @deadline.
 */
static __noinline bool flow_ready_before(u64 ready, u64 deadline)
{
	if (ready == (u64)~0ULL)
		return false;
	if (flow_time_before(ready, deadline))
		return true;
	if (ready == deadline)
		return true;
	return false;
}
/**
 * flow_cpu_meets_hint - test deadline against hoisted combined drain.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 *
 * Adds now plus the hoisted combined drain with saturation and no
 * kfunc, so placement checks share the enqueue reads with no wrap to
 * an early view.
 *
 * Returns: true when the drain finishes before @deadline.
 */
static __always_inline bool flow_cpu_meets_hint(s32 local_q, s32 node_q,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_cpu_drain_hint(local_q, node_q);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, deadline);
}
/**
 * flow_cpu_meets - test deadline against one CPU drain.
 * @cpu: CPU id below the 1024 bound.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 *
 * Adds now plus the combined local plus node drain with saturation,
 * so a huge drain fails closed with no wrap to an early view. The
 * drain poll plus the compare split across two noinline calls, so the
 * SSF plus BSF loops share one copy each with no inline growth.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: true when the drain finishes before @deadline.
 */
static __noinline bool flow_cpu_meets(u32 cpu,
	u64 deadline, u64 now)
{
	u64 drain;
	u64 ready;
	if (deadline == 0)
		return true;
	drain = flow_cpu_drain(cpu);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, deadline);
}
/**
 * flow_cpu_meets_fair - test fair time against one CPU drain.
 * @cpu: CPU id below the 1024 bound.
 * @vtime: fair time, zero meets all.
 * @now: current time in nanos.
 *
 * Mirrors the deadline check for the fair key, so the bypass plus the
 * tier choice test fair order while placement tests the deadline. A
 * zero fair time means no fair order yet, so the check passes. The
 * drain poll plus the compare split across two noinline calls, so the
 * loops share one copy each with no inline growth.
 *
 * Outlined with noinline to keep verifier headroom with no order change.
 *
 * Returns: true when the drain finishes before @vtime.
 */
__attribute__((unused)) static __noinline bool flow_cpu_meets_fair(u32 cpu,
	u64 vtime, u64 now)
{
	u64 drain;
	u64 ready;
	if (vtime == 0)
		return true;
	drain = flow_cpu_drain(cpu);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, vtime);
}
/**
 * flow_cpu_meets_fair_hint - test fair time against hoisted drain.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 * @vtime: fair time, zero meets all.
 * @now: current time in nanos.
 *
 * Mirrors the drain check for the fair key with no kfunc, so the bypass
 * plus the tier choice share one hoist with the same order. A zero fair
 * time means no fair order yet, so the check passes with no gate.
 *
 * Returns: true when the drain finishes before @vtime.
 */
static __always_inline bool flow_cpu_meets_fair_hint(s32 local_q,
	s32 node_q, u64 vtime, u64 now)
{
	u64 drain;
	u64 ready;
	if (vtime == 0)
		return true;
	drain = flow_cpu_drain_hint(local_q, node_q);
	ready = flow_sat_add(now, drain);
	return flow_ready_before(ready, vtime);
}
