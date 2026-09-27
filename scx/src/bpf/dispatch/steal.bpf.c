// SPDX-License-Identifier: GPL-2.0
/*
 * Steal scan for the dispatch pass.
 *
 * Runs only with an empty local queue, so a busy CPU keeps its
 * own order. The sibling wins when deep enough, then the same
 * cache domain over bound 8, then one gated cross domain move
 * of a starved head only. Donors hold at least two in every
 * tier, and every tier moves a single task with no extra charge.
 * The cursor spreads passes with no hotspot. Runs under the
 * caller RCU read lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when the head of one donor waited past the floor. */
/* Takes DSQ plus now scalars with no struct pass. A missing head */
/* or a missing state fails closed with no move. Outlined so the */
/* remote scan verifies once with no per peer inline copy. */
static __noinline bool flow_head_starved(u64 dsq,
	u64 now)
{
	struct task_struct *head;
	struct task_struct *trusted;
	struct flow_task_ctx *tctx;
	bool old = false;

	head = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!head)
		return false;
	trusted = bpf_task_from_pid(head->pid);
	if (!trusted)
		return false;
	tctx = flow_lookup(trusted);
	if (tctx && flow_starved(tctx->wait_at, now))
		old = true;
	bpf_task_release(trusted);
	return old;
}

/* SMT sibling pick with narrow inputs. Returns the donor DSQ or zero. */
static __noinline u64 flow_steal_pick_smt(s32 cpu)
{
	struct flow_topo *tp = flow_topo((u32)cpu);
	u32 sib;

	if (!tp)
		return 0;
	if (tp->smt_sib == 0xffffffffU)
		return 0;
	sib = tp->smt_sib;
	if (sib == (u32)cpu)
		return 0;
	if (!flow_cpu_live(sib))
		return 0;
	if (scx_bpf_dsq_nr_queued(flow_vtime_dsq(sib)) <
	    (s32)FLOW_STEAL_MIN_DEPTH)
		return 0;
	return flow_vtime_dsq(sib);
}

/* Same cache domain pick over bound 8 with narrow inputs. */
/* Returns the donor DSQ or zero with early exit on first hit. */
static __noinline u64 flow_steal_pick_llc(s32 cpu, u32 start)
{
	struct flow_topo *tp = flow_topo((u32)cpu);
	u32 want = tp ? tp->llc : 0;
	u32 off;

	bpf_for(off, 0, FLOW_STEAL_BOUND) {
		u32 peer;
		struct flow_topo *ptp;
		u64 pdsq;

		peer = (start + off) % (u32)nr_cpu_ids;
		if (peer == (u32)cpu)
			continue;
		if (!flow_cpu_live(peer))
			continue;
		ptp = flow_topo(peer);
		if (ptp && tp && ptp->llc != want)
			continue;
		pdsq = flow_vtime_dsq(peer);
		if (scx_bpf_dsq_nr_queued(pdsq) <
		    (s32)FLOW_STEAL_MIN_DEPTH)
			continue;
		return pdsq;
	}
	return 0;
}

/* Gated cross domain pick over bound 8 with narrow inputs. */
/* Returns the donor DSQ or zero for a starved head only. */
static __noinline u64 flow_steal_pick_remote(s32 cpu, u32 start,
	u64 now)
{
	u32 off;

	bpf_for(off, 0, FLOW_STEAL_BOUND) {
		u32 peer;
		u64 pdsq;

		peer = (start + off) % (u32)nr_cpu_ids;
		if (peer == (u32)cpu)
			continue;
		if (!flow_cpu_live(peer))
			continue;
		pdsq = flow_vtime_dsq(peer);
		if (scx_bpf_dsq_nr_queued(pdsq) <
		    (s32)FLOW_STEAL_MIN_DEPTH)
			continue;
		if (!flow_head_starved(pdsq, now))
			continue;
		return pdsq;
	}
	return 0;
}

/* One peer steal over bound 8 peers with SMT first. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
/* The cursor advances only on a donor hit with no ABI change, */
/* so misses skip the store with no correctness use. */
static __noinline u32 flow_steal_one(s32 cpu, u32 budget,
	u32 base)
{
	struct flow_cpu_state *st = flow_cpu((u32)cpu);
	u32 start;
	u64 steal_dsq = 0;
	u32 lim;
	u32 got;

	if (!st)
		return 0;
	if (nr_cpu_ids <= 1)
		return 0;
	if (base >= budget)
		return 0;
	start = (READ_ONCE(st->cursor) + 1U) %
	    (u32)nr_cpu_ids;
	steal_dsq = flow_steal_pick_smt(cpu);
	if (!steal_dsq)
		steal_dsq = flow_steal_pick_llc(cpu, start);
	if (!steal_dsq) {
		u64 now = flow_now();

		steal_dsq = flow_steal_pick_remote(cpu, start, now);
	}
	if (!steal_dsq)
		return 0;
	__sync_lock_test_and_set(&st->cursor,
	    (start + 8U) % (u32)nr_cpu_ids);
	lim = base + 1U;
	if (lim > budget)
		lim = budget;
	if (base >= lim)
		return 0;
	got = flow_drain_one(cpu, steal_dsq, lim, base);
	if (got != 0)
		__sync_fetch_and_add(&flow_stats.steal_moves,
		    (u64)got);
	return got;
}

/* Steal phase with narrow inputs. Runs only with an empty local */
/* queue, so donors keep two. Returns the steal moves. */
static __noinline u32 flow_phase_steal(s32 cpu, u64 own_dsq,
	u32 budget, u32 base)
{
	if (base >= budget)
		return 0;
	if (nr_cpu_ids <= 1)
		return 0;
	if (scx_bpf_dsq_nr_queued(own_dsq) != 0)
		return 0;
	return flow_steal_one(cpu, budget, base);
}
