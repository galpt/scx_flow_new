// SPDX-License-Identifier: GPL-2.0
/*
 * Task placement steal plus hint moves for the core.
 *
 * Holds the steal window plus the hint threaded moves. The steal window
 * spans four to eight peers proportional to remaining visits from the
 * same shared cursor with stride two and mask wins on drain. Hint
 * threaded moves thread hoisted depths with no second poll, and queue
 * runnable hints gate every RCU walk with a benign TOCTOU that only
 * delays work to the next pass with no loss. The SSF scan plus the BSF
 * fallback live in select/scan.bpf.c with the same order, so select
 * keeps twelve unique peers with no overlap on large hosts. Runs under
 * the caller with no lock.
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
	/* Proportional window spans 4 to 8 peers from remaining visits with */
	/* saturation, so overspent visits hold four with no wrap. A fresh */
	/* pass with full visits scans eight peers, while a spent pass with */
	/* few visits left scans four peers. Bounds use the shared steal plus */
	/* visit constants with no literal, matching the Rust steal_window. */
	{
		u32 remain = *visits >= (u32)FLOW_DISPATCH_MAX_VISIT ? 0 :
		    (u32)FLOW_DISPATCH_MAX_VISIT - *visits;
		window = (u32)FLOW_STEAL_MIN_PEERS + (remain >> 1);
	}
	if (window < (u32)FLOW_STEAL_MIN_PEERS)
		window = (u32)FLOW_STEAL_MIN_PEERS;
	if (window > (u32)FLOW_STEAL_MAX_PEERS)
		window = (u32)FLOW_STEAL_MAX_PEERS;
	{
		u32 n = (u32)nr;
		bool pow2 = flow_is_pow2((u64)n);
		u32 start;
		/* Hoist the pow2 check once per steal, so peers step with */
		/* one mask or modulo each with no per peer power test. */
		if (pow2)
			start = (u32)(((u64)cursor + 1ULL) & ((u64)n - 1ULL));
		else
			start = (u32)(((u64)cursor + 1ULL) % (u64)n);
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
			if (pow2)
				peer = (u32)(((u64)start + (u64)off) &
				    ((u64)n - 1ULL));
			else
				peer = (u32)(((u64)start + (u64)off) % (u64)n);
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
