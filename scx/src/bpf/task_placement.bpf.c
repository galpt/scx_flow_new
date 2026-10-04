// SPDX-License-Identifier: GPL-2.0
/*
 * Task placement with slowest sufficient fit plus steal.
 *
 * Holds the SSF scan plus the BSF fallback plus the steal window plus
 * the hint threaded moves. The SSF scan takes the slowest sufficient
 * CPU in two node-local phases with a near minimum tiebreak on the CPU
 * minima through a single best plus a locality flag, so light work
 * never takes a fast CPU and close peers win ties with no extra scan.
 * The BSF fallback takes the best sufficient CPU with the smallest
 * combined drain plus minimum plus id tiebreak over the next four
 * peers past the SSF window from cursor plus 9, so the two
 * scans cover twelve unique peers with no overlap and symmetric hosts
 * still spread work with no topology walk. SSF runs in O(VISIT) with
 * VISIT at most eight peers from the cursor with no hotspot, and BSF
 * adds at most four more from the disjoint window. The steal window
 * spans four to eight peers proportional to remaining visits from the
 * same shared cursor with stride two and mask wins on drain. Hint
 * threaded moves thread hoisted depths with no second poll, and queue
 * runnable hints gate every RCU walk with a benign TOCTOU that only
 * delays work to the next pass with no loss. Runs under the caller with
 * no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one CPU may run one task through its mask. */
/* Live proven at entry, so mask alone gates here with no live branch. */
static __always_inline bool flow_mask_ok(s32 cpu,
	const struct task_struct *p)
{
	if (unlikely(cpu < 0))
		return false;
	if (unlikely(!p))
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* One candidate with the shared mask gate plus move in one place. */
/* Gives one on move else zero with no state and one mask test. */
static __always_inline u32 flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!p))
		return 0;
	if (unlikely(!flow_mask_ok(cpu, p)))
		return 0;
	return (u32)scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
/* Move one queued task with a hoisted hint plus a BPF mask gate. */
/* Takes a queue id plus a CPU scalar plus the per pass visit count plus */
/* the hoisted queued hint with no extra queue poll, so dispatch tiers */
/* plus steal peers skip the second kfunc with the same visit cap. Visits */
/* cap per pass shared across tiers with resume next pass at eight, so */
/* the loop never holds RCU across the whole queue. The TOCTOU between */
/* the hoisted hint and the iterator recheck only repeats or skips a pass */
/* with no loss, since the next pass re-reads the hint with no stall. */
/**
 * flow_move_one_hint - move one task using a hoisted queue hint.
 * @dsq: tier queue id to drain.
 * @cpu: target CPU for the mask gate.
 * @visits: per pass visit count shared across tiers.
 * @queued: hoisted queued depth, non-positive skips with no kfunc.
 *
 * Returns: one on move else zero with no state.
 */
static __noinline u32 flow_move_one_hint(u64 dsq, s32 cpu, u32 *visits,
	s32 queued)
{
	struct task_struct *p;
	u32 moved = 0;
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!visits))
		return 0;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return 0;
	if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
		return 0;
	if (likely(queued <= 0))
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (unlikely(moved))
			break;
		if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
			break;
		(*visits)++;
		moved += flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p);
	}
	bpf_rcu_read_unlock();
	return moved;
}
/* Steal one queued task from peer locals with a bounded window. */
/* Scans four to eight peers proportional to remaining visits, so the */
/* steal stays bounded with no hotspot. Each peer shares the per pass */
/* visit cap at eight through the shared move, so a miss heavy peer */
/* never holds RCU across the whole queue. Stolen work counts in the */
/* local bucket with no new counter, so stats stay at 120B. The start */
/* hoists once outside the loop with pow2 masking, so peers step from */
/* start plus offset with no per peer add chain. The TOCTOU between the */
/* per peer empty hint and the shared move only delays the steal to the */
/* next pass with no loss. The cursor is shared with select at stride */
/* two with best effort races and no atomic order. */
static __noinline u32 flow_steal_one(s32 cpu, u32 *visits, u32 cursor)
{
	u32 moved = 0;
	u32 window;
	u32 off;
	u64 nr;
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!visits))
		return 0;
	if (unlikely(!flow_cpu_live((u32)cpu)))
		return 0;
	if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
		return 0;
	nr = nr_cpu_ids;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return 0;
	/* Proportional window spans 4 to 8 peers from remaining visits. */
	/* A fresh pass with full visits scans eight peers, while a spent */
	/* pass with few visits left scans four peers. Bounds use the shared */
	/* steal plus visit constants with no literal. */
	window = (u32)FLOW_STEAL_MIN_PEERS +
	    (((u32)FLOW_DISPATCH_MAX_VISIT - *visits) >> 1);
	if (window < (u32)FLOW_STEAL_MIN_PEERS)
		window = (u32)FLOW_STEAL_MIN_PEERS;
	if (window > (u32)FLOW_STEAL_MAX_PEERS)
		window = (u32)FLOW_STEAL_MAX_PEERS;
	{
		u32 n = (u32)nr;
		u32 start = flow_wrap_idx((u64)cursor + 1ULL, n);
		bpf_for(off, 0, FLOW_STEAL_MAX_PEERS) {
			u32 peer;
			u64 peer_dsq;
			u32 got;
			/* Start hoists once with pow2 masking, so peers step */
			/* from start plus offset with no per peer add chain. */
			if ((u64)off >= (u64)window)
				break;
			if (unlikely(moved))
				break;
			if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
				break;
			peer = flow_wrap_idx((u64)start + (u64)off, n);
			if (peer == (u32)cpu)
				continue;
			if (unlikely(!flow_cpu_live(peer)))
				continue;
			peer_dsq = flow_local_dsq(peer);
			/* Queue runnable hint threads once into the shared hint */
			/* move with no second poll, so each peer pays one queue */
			/* read total. The hint move rechecks under RCU with the */
			/* same visit cap, so a race only delays the steal to the */
			/* next pass with no loss. */
			{
				s32 pq = scx_bpf_dsq_nr_queued(peer_dsq);
				if (pq <= 0)
					continue;
				got = flow_move_one_hint(peer_dsq, cpu, visits, pq);
			}
			if (got)
				moved += got;
		}
	}
	return moved;
}
/* Slowest sufficient pick among allowed peers in O(VISIT). */
/* Scans at most eight peers from the cursor and skips the busy waker, */
/* so the pass stays bounded with no extra walk. Node-local peers win in */
/* a first phase within the 64-unit window with the same slowest */
/* sufficient plus near minimum rule, so cache stays close with no extra */
/* scan and no topology walk. A local candidate beats a remote best in */
/* the window, while a clearly slower peer still wins across phases with */
/* wrap safe adds. The single best plus a locality flag keeps one pass */
/* with no extra visits, so the twelve peer budget with BSF holds. Peers */
/* within 64 units of the best count as near minimum, and the smallest */
/* minimum wins those ties with wrap safe order, so lagging CPUs take */
/* work first. */
/* Returns the peer id or 0xffffffffU when no peer meets. */
static __always_inline u32 flow_ssf_pick(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu, u32 cursor, u64 nr)
{
	u32 best = 0xffffffffU;
	u32 best_units = 0xffffffffU;
	u64 best_min = (u64)~0ULL;
	bool best_local = false;
	u32 this_node;
	u32 off;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return best;
	this_node = flow_cpu_node(this_cpu);
	{
		u32 n = (u32)nr;
		u32 start = flow_wrap_idx((u64)cursor + 1ULL, n);
		bpf_for(off, 0, FLOW_DISPATCH_MAX_VISIT) {
			u32 peer;
			u32 units;
			u64 pmin;
			bool same;
			if ((u64)off >= (u64)n)
				break;
			peer = flow_wrap_idx((u64)start + (u64)off, n);
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
/* Best sufficient fallback with the smallest drain plus tiebreak. */
/* Scans the next four peers past the SSF window from cursor plus 9 for */
/* the smallest combined drain that still meets, so symmetric hosts */
/* spread work with no capacity signal and no overlap with SSF. Equal */
/* drains break toward the smallest minimum with wrap safe order, then */
/* the smallest peer id, so ties spread with no hotspot. Covers twelve */
/* unique peers with SSF at the same order, so select pays at most 12 */
/* checks per pass. Returns the peer id or 0xffffffffU. */
static __always_inline u32 flow_bsf_pick(const struct task_struct *p,
	u64 deadline, u64 now, u32 this_cpu, u32 cursor, u64 nr)
{
	u32 best = 0xffffffffU;
	u64 best_drain = (u64)~0ULL;
	u64 best_min = (u64)~0ULL;
	u32 off;
	if (nr <= 1 || nr > (u64)FLOW_MAX_CPUS)
		return best;
	{
		u32 n = (u32)nr;
		u32 start = flow_wrap_idx((u64)cursor + 1ULL, n);
		u32 bsf_start = flow_wrap_idx((u64)start +
		    (u64)FLOW_DISPATCH_MAX_VISIT, n);
		bpf_for(off, 0, FLOW_BSF_MAX_PEERS) {
			u32 peer;
			u64 drain;
			u64 pmin;
			if ((u64)off >= (u64)n)
				break;
			peer = flow_wrap_idx((u64)bsf_start + (u64)off, n);
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
