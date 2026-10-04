// SPDX-License-Identifier: GPL-2.0
/*
 * Tier moves for the dispatch pass.
 *
 * Moves one queued task to local with a uniform skip plus a BPF
 * mask gate. Each of four tiers calls once in fixed order, and an
 * empty queue moves nothing with no scan. The kernel keeps each
 * priority queue list in fair order, so the earliest matching fair
 * time moves with mask wins on drain and no BPF sort. A head that
 * cannot run on the dealing CPU skips to the next entry through the
 * shared move, so one foreign task never stalls its tier for that pass.
 * Visits share the per pass cap at sixty four across four tiers with
 * leftover work
 * resuming next pass, so one pass never holds RCU across the whole
 * queue while staying work conserving across passes. Homeless work
 * waits in the machine queue with all other shared work, so no trip
 * touches the kernel global queue. Fresh joins enter tier order at
 * once with no hold. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Move one queued task to local with a uniform skip plus a BPF mask gate. */
/* Takes a queue id plus a CPU scalar plus the per pass visit count with */
/* no struct pass, so every tier verifies through this one call. The gate */
/* runs first for the CPU, then the queue depth leaves at once with no RCU */
/* hold, so idle tiers stay cheap. The length is an opportunistic early */
/* out only with no correctness use, so a join racing the read still meets */
/* the next pass with no loss. The shared move gates affinity with no */
/* kernel error, so an empty queue returns zero with no scan and no miss */
/* count. An unmatching head skips to the next entry through the */
/* shared gate, so one foreign task never stalls its tier for that */
/* pass. Visits cap per pass shared across tiers with resume next pass, */
/* so the loop never holds RCU across the whole queue. Static tier order */
/* is local plus node plus machine plus steal with no reorder. The steal */
/* tier scans peer locals within the bounded window with mask wins. */
static __noinline u32 flow_move_one(u64 dsq, s32 cpu, u32 *visits)
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
	if (likely(scx_bpf_dsq_nr_queued(dsq) <= 0))
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
/* Scans at least 8 peers and at most 16 peers proportional to remaining */
/* visits, so the steal stays bounded with no hotspot. Each peer shares */
/* the per pass visit cap through the shared move, so a miss heavy peer */
/* never holds RCU across the whole queue. The first matching fair time */
/* moves with mask wins on drain and no BPF sort. Stolen work counts in */
/* the local bucket with no new counter, so stats stay at 120B. Runs under */
/* the caller with no lock and a bounded bpf_for window, so the verifier */
/* sees one fixed path with no unrolled caller tree. */
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
	/* Proportional window spans 8 to 16 peers from remaining visits. */
	/* A fresh pass with full visits scans sixteen peers, while a spent */
	/* pass with few visits left scans eight peers, so the steal window */
	/* tracks the visit budget with no extra state. */
	window = (u32)FLOW_STEAL_MIN_PEERS +
	    (((u32)FLOW_DISPATCH_MAX_VISIT - *visits) >> 3);
	if (window < (u32)FLOW_STEAL_MIN_PEERS)
		window = (u32)FLOW_STEAL_MIN_PEERS;
	if (window > (u32)FLOW_STEAL_MAX_PEERS)
		window = (u32)FLOW_STEAL_MAX_PEERS;
	bpf_for(off, 0, 16) {
		u32 peer;
		u64 peer_dsq;
		u32 got;
		if ((u64)off >= (u64)window)
			break;
		if (unlikely(moved))
			break;
		if (unlikely(*visits >= (u32)FLOW_DISPATCH_MAX_VISIT))
			break;
		peer = (u32)(((u64)(cursor + 1U + off)) % nr);
		if (peer == (u32)cpu)
			continue;
		if (unlikely(!flow_cpu_live(peer)))
			continue;
		peer_dsq = flow_local_dsq(peer);
		got = flow_move_one(peer_dsq, cpu, visits);
		if (got)
			moved += got;
	}
	return moved;
}
