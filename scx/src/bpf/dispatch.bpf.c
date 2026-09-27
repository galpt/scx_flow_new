// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains in fixed order. The own deadline queue moves
 * first with the header cap, then one peer steal moves a single task,
 * then the kernel global plus the shared overflow tail with a
 * shared cap at 4, and last a gated starvation pass over overflow
 * when nothing moved. Empty trips pay one queued read with no scan.
 * Steal never visits a peer deadline queue unless the local queue
 * drained empty, so a busy CPU keeps its own order. The SMT
 * sibling wins first, then the same cache domain, then a gated
 * cross domain move of a head that waited past 2ms. Donors hold
 * at least two, and stolen tasks pay no extra charge. See intf.h
 * for the caps and enqueue.bpf.c for the deadline choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. */
/* Moves mask allowed tasks to local with a miss cap at 4. */
/* One bad head never blocks later work with no full scan. */
/* Plain move keeps LOCAL_ON order, since the move with vtime */
/* stays for user to user DSQ order only. */
static __noinline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved + base >= budget)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
/* Starvation drain for the gated passes with a 2ms floor. */
/* Young tasks count one miss each, so old tasks behind them surface. */
static __noinline u32 flow_drain_starved(s32 cpu,
	u64 dsq, u32 budget, u32 base, u64 now)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		struct flow_task_ctx *tctx;
		if (moved + base >= budget)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		tctx = flow_lookup(p);
		if (!tctx || !flow_starved(tctx->wait_at, now)) {
			bpf_task_release(p);
			miss++;
			continue;
		}
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
/* True when the head of one donor waited past the floor. */
/* A missing head or a missing state fails closed with no move. */
/* The peek stays inside RCU with the lookup, so the head stays valid. */
static __noinline bool flow_head_starved(u64 dsq,
	u64 now)
{
	struct task_struct *head;
	struct task_struct *trusted;
	struct flow_task_ctx *tctx;
	bool old = false;
	bpf_rcu_read_lock();
	head = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!head) {
		bpf_rcu_read_unlock();
		return false;
	}
	trusted = bpf_task_from_pid(head->pid);
	if (!trusted) {
		bpf_rcu_read_unlock();
		return false;
	}
	tctx = flow_lookup(trusted);
	if (tctx && flow_starved(tctx->wait_at, now))
		old = true;
	bpf_task_release(trusted);
	bpf_rcu_read_unlock();
	return old;
}
/* One peer steal over bound 8 peers with SMT first. */
/* Runs only with an empty local queue, so a busy CPU keeps its */
/* own deadline order. The sibling wins when deep enough, then */
/* the same cache domain, then one gated cross domain move of a */
/* starved head only. Donors hold at least two in every tier, */
/* and every tier moves a single task with no extra charge. */
static __noinline u32 flow_steal_one(s32 cpu, u32 budget,
	u32 base)
{
	struct flow_cpu_state *st = flow_cpu((u32)cpu);
	struct flow_topo *tp = flow_topo((u32)cpu);
	u32 start;
	u32 salt = 0;
	u64 steal_dsq = 0;
	bool have = false;
	u32 off;
	u32 lim;
	u32 got;
	if (!st)
		return 0;
	if (nr_cpu_ids <= 1)
		return 0;
	/* Prandom salt spreads passes with no lockstep hotspot. */
	salt = bpf_get_prandom_u32() % (u32)nr_cpu_ids;
	start = (st->cursor + 1U + salt) % (u32)nr_cpu_ids;
	/* SMT sibling first with one live check and no scan. */
	if (tp && tp->smt_sib != 0xffffffffU) {
		u32 sib = tp->smt_sib;
		if (sib != (u32)cpu && flow_cpu_live(sib) &&
		    scx_bpf_dsq_nr_queued(flow_vtime_dsq(sib)) >=
		    (s32)FLOW_STEAL_MIN_DEPTH) {
			steal_dsq = flow_vtime_dsq(sib);
			have = true;
		}
	}
	/* Same cache domain next over the bound 8 window. */
	if (!have) {
		u32 want = tp ? tp->llc : 0;
		bpf_for(off, 0, FLOW_STEAL_BOUND) {
			u32 peer;
			struct flow_topo *ptp;
			u64 pdsq;
			if (have)
				continue;
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
			steal_dsq = pdsq;
			have = true;
		}
	}
	/* Gated cross domain last with a starved head only. */
	/* Donors hold at least two, and young heads keep the pass shut. */
	if (!have) {
		u64 now = flow_now();
		bpf_for(off, 0, FLOW_STEAL_BOUND) {
			u32 peer;
			u64 pdsq;
			if (have)
				continue;
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
			steal_dsq = pdsq;
			have = true;
		}
	}
	st->cursor = (start + 8U) % (u32)nr_cpu_ids;
	if (!have)
		return 0;
	/* One move per pass with no batch steal. */
	lim = base + 1U;
	if (lim > budget)
		lim = budget;
	got = flow_drain_one(cpu, steal_dsq, lim, base);
	if (got != 0)
		__sync_fetch_and_add(&flow_stats.steal_moves,
		    (u64)got);
	return got;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	/* Budget 32 bounds one pass with no stall. */
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 global_moved = 0;
	u64 own_vtime;
	u64 over;
	u32 lim;
	u32 got;
	bool local_empty;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	own_vtime = flow_vtime_dsq((u32)cpu);
	over = flow_overflow_dsq();
	/* Own deadline queue first with the header cap and mask wins. */
	/* Priority order reaches local in queue order with one probe. */
	if (scx_bpf_dsq_nr_queued(own_vtime) != 0) {
		lim = moved + flow_own_cap(budget);
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, own_vtime, lim, moved);
		moved += got;
	}
	local_empty = scx_bpf_dsq_nr_queued(own_vtime) == 0;
	/* One steal trip over bound 8 peers with a single move. */
	/* Runs only with an empty local queue, so donors keep two. */
	if (moved < budget && local_empty && nr_cpu_ids > 1) {
		got = flow_steal_one(cpu, budget, moved);
		moved += got;
	}
	/* Kernel global plus overflow next with a shared cap at 4. */
	if (moved < budget &&
	    (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_GLOBAL) != 0 ||
	    scx_bpf_dsq_nr_queued(over) != 0)) {
		lim = moved + flow_tail_cap(budget);
		if (lim > budget)
			lim = budget;
		if (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_GLOBAL) != 0) {
			got = flow_drain_one(cpu,
			    (u64)SCX_DSQ_GLOBAL, lim, moved);
			moved += got;
			global_moved += got;
		}
		if (moved < lim &&
		    scx_bpf_dsq_nr_queued(over) != 0) {
			got = flow_drain_one(cpu, over, lim, moved);
			moved += got;
			over_moved += got;
		}
	}
	/* Gated backstop over overflow when nothing moved yet. */
	/* Young tasks miss past, so old tasks behind them still surface. */
	if (moved == 0) {
		lim = flow_gated_cap(budget);
		if (lim > budget)
			lim = budget;
		got = flow_drain_starved(cpu, over, lim, 0,
		    flow_now());
		moved += got;
		over_moved += got;
	}
	if (moved != 0)
		__sync_fetch_and_add(&flow_stats.slot_moves,
		    (u64)moved);
	if (over_moved != 0)
		__sync_fetch_and_add(&flow_stats.park_moves,
		    (u64)over_moved);
	if (global_moved != 0)
		__sync_fetch_and_add(&flow_stats.global_moves,
		    (u64)global_moved);
}
