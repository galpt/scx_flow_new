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
/*
 * RED guarantee core for the flow scheduler.
 *
 * Holds the residual plus load plus exceeding time with tolerance used
 * only for the guarantee. Like rt.c, the deadline bounds the check,
 * unlike fair.c, no vruntime shapes it. A newcomer with zero exceed
 * passes at once, else the caller seeks a least value victim with cost
 * past the exceed plus deadline at or before the newcomer plus never
 * critical, else the newcomer rejects. The reject queue stays value
 * ordered outside dispatch, and a saved delta at or past 128us
 * reclaims one head with positive laxity. Runs under the caller with
 * no lock and no RCU walk here, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_red_newcomer_exceed - exceeding time of one newcomer.
 * @deadline: newcomer absolute deadline in nanos.
 * @now: current time in nanos.
 * @avg: burst average in nanos, zero for no history.
 * @slice: stored slice in nanos, zero for no history.
 * @is_crit: true marks critical with zero tolerance.
 *
 * Costs burst else slice else quantum, tolerates 64us for hard only,
 * then residuals deadline minus now minus cost with wrap safety. Like
 * rt.c, tolerance aids only the guarantee, unlike fair.c, it never
 * shapes queue order.
 *
 * Returns: exceeding time in nanos, zero when guaranteed.
 */
static __always_inline u64 flow_red_newcomer_exceed(u64 deadline,
	u64 now, u64 avg, u32 slice, bool is_crit)
{
	u64 cost = flow_red_cost(avg, slice);
	u64 tol = flow_red_tol(is_crit);
	s64 resid = flow_red_residual(deadline, now, cost);
	return flow_red_exceed(resid, tol);
}
/**
 * flow_red_victim_ok - test one victim for one exceed.
 * @v_deadline: victim deadline in nanos, zero fails closed.
 * @n_deadline: newcomer deadline in nanos, zero fails closed.
 * @v_cost: victim remaining cost in nanos.
 * @exceed: newcomer exceeding time in nanos, zero fails closed.
 * @v_crit: true marks a critical victim that never rejects.
 *
 * Victim needs cost past the exceed plus deadline at or before the
 * newcomer, so only work ahead of the overload pays. Like rt.c, the
 * least value pays first, unlike fair.c, no vruntime shapes it. A
 * critical victim never passes with no swap.
 *
 * Returns: true when the victim may cover the exceed.
 */
static __always_inline bool flow_red_victim_ok(u64 v_deadline,
	u64 n_deadline, u64 v_cost, u64 exceed, bool v_crit)
{
	if (exceed == 0)
		return false;
	if (v_crit)
		return false;
	if (v_deadline == 0 || n_deadline == 0)
		return false;
	if (v_cost <= exceed)
		return false;
	if (v_cost <= (u64)FLOW_RED_EMAX_NS && exceed <= (u64)FLOW_RED_EMAX_NS) {
		if (v_cost <= exceed)
			return false;
	}
	if (flow_time_before(n_deadline, v_deadline))
		return false;
	return true;
}
/**
 * flow_red_reclaim_ok - test reclaim from one saved delta.
 * @saved: saved execution in nanos from one completion.
 * @exceed: head exceeding time in nanos.
 * @laxity: head laxity in nanos, zero means no room.
 *
 * Reclaims when the saved delta reaches past 128us plus covers the
 * head exceed with positive laxity, so Theorem 6 holds with no scan
 * here. Like rt.c, the delta funds the retry, unlike fair.c, no share
 * shapes it.
 *
 * Returns: true when the head may rejoin.
 */
static __always_inline bool flow_red_reclaim_ok(u64 saved, u64 exceed,
	u64 laxity)
{
	if (saved < (u64)FLOW_RED_EMAX_NS)
		return false;
	if (laxity == 0)
		return false;
	if (saved < exceed)
		return false;
	return true;
}
