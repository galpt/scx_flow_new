// SPDX-License-Identifier: GPL-2.0
/*
 * Select scan with slowest plus best sufficient fit for the core.
 *
 * Holds the SSF scan plus the BSF fallback plus the combined best pick
 * plus the single ktime scan tail. The SSF scan takes the slowest
 * sufficient CPU in two node-local phases with a near minimum tiebreak
 * on the CPU minima through a single best plus a locality flag, so
 * light work never takes a fast CPU and close peers win ties with no
 * extra scan. The BSF fallback takes the best sufficient CPU with the
 * smallest combined drain plus minimum plus id tiebreak over the next
 * four peers past the SSF window from cursor plus 9, so the two scans
 * cover twelve unique peers with no overlap when the host holds at
 * least twelve CPUs, else the windows wrap and overlap, and symmetric
 * hosts still spread work with no topology walk. SSF runs in O(VISIT)
 * with VISIT at most eight peers from the cursor with no hotspot, and
 * BSF adds at most four more from the disjoint window. The shared
 * cursor with dispatch steal advances by two with best effort races
 * and no atomic order. One ktime read serves the previous plus SSF
 * plus BSF checks, and pow2 hosts mask with no divide. Runs under the
 * caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_ssf_pick - slowest sufficient pick among allowed peers.
 * @p: task to place.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU skipped as the busy waker.
 * @cursor: shared cursor for the scan start.
 *
 * Scans at most eight peers from the cursor and skips the busy waker,
 * so the pass stays bounded with no extra walk. Node-local peers win
 * in a first phase within the 64-unit window with the same slowest
 * sufficient plus near minimum rule, so cache stays close with no
 * extra scan and no topology walk. A local candidate beats a remote
 * best in the window, while a clearly slower peer still wins across
 * phases with wrap safe adds. The single best plus a locality flag
 * keeps one pass with no extra visits, so the twelve peer budget with
 * BSF holds when the host holds at least twelve CPUs, else the windows
 * wrap. Peers within 64 units of the best count as near minimum, and
 * the smallest minimum wins those ties with wrap safe order, so
 * lagging CPUs take work first.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_ssf_pick(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu, u32 cursor)
{
	u32 best = 0xffffffffU;
	u32 best_units = 0xffffffffU;
	u64 best_min = (u64)~0ULL;
	bool best_local = false;
	u32 this_node;
	u32 off;
	u64 nr = nr_cpu_ids;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return best;
	this_node = flow_cpu_node(this_cpu);
	{
		u32 n = (u32)nr;
		bool pow2;
		u32 start;
		/* Hoist the pow2 check once per scan, so peers step with */
		/* one mask or modulo each with no per peer power test. */
		/* Keeps the same wrap order with fewer verifier states. */
		pow2 = flow_is_pow2((u64)n);
		if (pow2)
			start = (u32)(((u64)cursor + 1ULL) & ((u64)n - 1ULL));
		else
			start = (u32)(((u64)cursor + 1ULL) % (u64)n);
		bpf_for(off, 0, FLOW_DISPATCH_MAX_VISIT) {
			u32 peer;
			u32 units;
			u64 pmin;
			bool same;
			if ((u64)off >= (u64)n)
				break;
			if (pow2)
				peer = (u32)(((u64)start + (u64)off) &
				    ((u64)n - 1ULL));
			else
				peer = (u32)(((u64)start + (u64)off) % (u64)n);
			if (peer == this_cpu)
				continue;
			if (!flow_cpu_ok(p, (s32)peer))
				continue;
			if (!flow_cpu_meets(peer, deadline, now))
				continue;
			units = flow_cpu_units(peer);
			pmin = flow_cpu_min(peer);
			same = flow_cpu_node(peer) == this_node;
			if (best != 0xffffffffU) {
				/* u64 adds keep the 64-unit window wrap safe. */
				if ((u64)units + 64ULL < (u64)best_units) {
					best_units = units;
					best_min = pmin;
					best = peer;
					best_local = same;
					continue;
				}
				if ((u64)units > (u64)best_units + 64ULL)
					continue;
				/* Node-local phase wins ties in the window. */
				if (same && !best_local) {
					best_units = units < best_units ?
					    units : best_units;
					best_min = pmin;
					best = peer;
					best_local = true;
					continue;
				}
				if (!same && best_local)
					continue;
				if (!flow_time_before(pmin, best_min) &&
				    pmin != best_min)
					continue;
				if (pmin == best_min && peer >= best)
					continue;
				best_units = units < best_units ?
				    units : best_units;
				best_min = pmin;
				best = peer;
				best_local = same;
				continue;
			}
			best_units = units;
			best_min = pmin;
			best = peer;
			best_local = same;
		}
	}
	return best;
}
/**
 * flow_bsf_pick - best sufficient fallback over the disjoint window.
 * @p: task to place.
 * @deadline: absolute deadline, zero meets all.
 * @now: current time in nanos.
 * @this_cpu: waker CPU skipped as the busy waker.
 * @cursor: shared cursor for the disjoint start.
 *
 * Scans the next four peers past the SSF window from cursor plus 9 for
 * the smallest combined drain that still meets, so symmetric hosts
 * spread work with no capacity signal and no overlap with SSF when the
 * host holds at least twelve CPUs, else the windows wrap. Equal drains
 * break toward the smallest minimum with wrap safe order, then the
 * smallest peer id, so ties spread with no hotspot. Covers twelve
 * unique peers with SSF at the same order on large hosts, so select
 * pays at most 12 checks per pass.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: peer id or 0xffffffffU when no peer meets.
 */
static __noinline u32 flow_bsf_pick(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu, u32 cursor)
{
	u32 best = 0xffffffffU;
	u64 best_drain = (u64)~0ULL;
	u64 best_min = (u64)~0ULL;
	u32 off;
	u64 nr = nr_cpu_ids;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return best;
	{
		u32 n = (u32)nr;
		bool pow2;
		u32 start;
		u32 bsf_start;
		/* Hoist the pow2 check once per fallback, so peers step */
		/* with one mask or modulo each with no per peer power test. */
		/* Keeps the same disjoint twelve peer order with fewer states. */
		pow2 = flow_is_pow2((u64)n);
		if (pow2) {
			start = (u32)(((u64)cursor + 1ULL) & ((u64)n - 1ULL));
			bsf_start = (u32)(((u64)start +
			    (u64)FLOW_DISPATCH_MAX_VISIT) & ((u64)n - 1ULL));
		} else {
			start = (u32)(((u64)cursor + 1ULL) % (u64)n);
			bsf_start = (u32)(((u64)start +
			    (u64)FLOW_DISPATCH_MAX_VISIT) % (u64)n);
		}
		bpf_for(off, 0, FLOW_BSF_MAX_PEERS) {
			u32 peer;
			u64 drain;
			u64 pmin;
			if ((u64)off >= (u64)n)
				break;
			if (pow2)
				peer = (u32)(((u64)bsf_start + (u64)off) &
				    ((u64)n - 1ULL));
			else
				peer = (u32)(((u64)bsf_start + (u64)off) %
				    (u64)n);
			if (peer == this_cpu)
				continue;
			if (!flow_cpu_ok(p, (s32)peer))
				continue;
			if (!flow_cpu_meets(peer, deadline, now))
				continue;
			drain = flow_cpu_drain(peer);
			pmin = flow_cpu_min(peer);
			if (best == 0xffffffffU || drain < best_drain) {
				best_drain = drain;
				best_min = pmin;
				best = peer;
				continue;
			}
			if (drain != best_drain)
				continue;
			if (pmin != best_min &&
			    !flow_time_before(pmin, best_min))
				continue;
			if (pmin == best_min && peer >= best)
				continue;
			best_min = pmin;
			best = peer;
		}
	}
	return best;
}
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
	best = flow_ssf_pick(p, deadline, now, this_cpu, cursor);
	if (best != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return best;
	}
	bsf = flow_bsf_pick(p, deadline, now, this_cpu, cursor);
	if (bsf != 0xffffffffU) {
		if (wst)
			__sync_lock_test_and_set(&wst->cursor, next);
		return bsf;
	}
	return 0xffffffffU;
}
/**
 * flow_select_scan - run previous plus SSF plus BSF plus fallback.
 * @p: task to place.
 * @prev_cpu: previous CPU for the meet check plus the fallback.
 * @deadline: absolute deadline, zero meets all.
 * @this_cpu: waker CPU for the cursor plus the self skip.
 *
 * One ktime serves the previous plus SSF plus BSF with no second read.
 * Early exit on the previous CPU avoids both scans when it meets, so
 * the common stay keeps one drain check with no peer walk. Shared SSF
 * plus disjoint BSF run in one outlined call with no topology signal,
 * so select keeps twelve peer coverage. An empty mask falls through to
 * the machine tier at enqueue.
 *
 * Outlined with noinline to keep verifier headroom on the select path
 * with no order change.
 *
 * Returns: picked CPU or @prev_cpu on fallback with gate count.
 */
static __noinline s32 flow_select_scan(const struct task_struct *p,
	s32 prev_cpu, u64 deadline, u32 this_cpu)
{
	u64 now;
	u32 best;
	s32 first;
	/* One ktime serves previous plus SSF plus BSF with no second read. */
	now = flow_now();
	/* Early exit on the previous CPU avoids both scans when it meets, */
	/* so the common stay keeps one drain check with no peer walk. */
	if (flow_cpu_ok(p, prev_cpu)) {
		if (flow_cpu_meets((u32)prev_cpu, deadline, now))
			return prev_cpu;
	}
	/* Shared SSF plus disjoint BSF in one outlined call with no */
	/* topology signal, so select keeps twelve peer coverage. */
	best = flow_select_best(p, deadline, now, this_cpu);
	if (best != 0xffffffffU)
		return (s32)best;
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return prev_cpu;
}
