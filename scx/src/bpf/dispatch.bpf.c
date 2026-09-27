// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Each pass drains in fixed order. The own fast FIFO moves first with a
 * depth of four, then the own deadline queue with twelve, then one peer
 * steal, then the kernel global plus the shared overflow tail, and last
 * a gated starvation pass over overflow. Steal never visits a peer fast
 * queue, so sleepy tasks stay local. The SMT sibling wins first, then
 * the same cache domain, then a gated cross domain move of a task that
 * waited past 1.5ms. Stolen tasks pay a weight scaled 500us penalty in
 * virtual time with no knob to turn it off. See intf.h for the caps and
 * enqueue.bpf.c for the matching lane choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. */
/* Moves mask allowed tasks to local with a miss cap at 4. */
/* One bad head never blocks later work with no full scan. */
/* Plain move keeps LOCAL_ON order with no vtime write, since the move */
/* with vtime stays for user to user DSQ order only. */
static __noinline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base, bool penalty)
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
			if (penalty &&
			    (u64)FLOW_STEAL_PENALTY_ON != 0) {
				struct flow_task_ctx *tctx =
				    flow_lookup(p);
				if (tctx) {
					u32 w = flow_weight_clamp(
					    p->scx.weight);
					tctx->vruntime +=
					    flow_steal_penalty(w);
					__sync_fetch_and_add(
					    &flow_stats.steal_penalties,
					    1);
				}
			}
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
/* Starvation drain for the gated passes with a 1.5ms floor. */
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
		if (!tctx || tctx->wait_at == 0 ||
		    now < tctx->wait_at ||
		    now - tctx->wait_at <= (u64)FLOW_STARVE_NS) {
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
/* One peer steal over bound 8 peers with SMT first. */
/* The sibling wins when deep enough, then the same cache domain, */
/* then one gated cross domain move of starved work only. Fast queues */
/* never take part, so stolen work always comes from deadline queues. */
static __noinline u32 flow_steal_one(s32 cpu, u32 budget,
	u32 base, bool local_empty)
{
	struct flow_cpu_state *st = flow_cpu((u32)cpu);
	struct flow_topo *tp = flow_topo((u32)cpu);
	u32 start;
	u32 salt = 0;
	u64 need;
	u64 steal_dsq = 0;
	bool have = false;
	bool idle;
	bool win_left;
	u32 off;
	u32 lim;
	u32 got;
	if (!st)
		return 0;
	if (nr_cpu_ids <= 1)
		return 0;
	idle = st->running_pid == 0;
	win_left = !local_empty;
	/* Prandom salt spreads passes with no lockstep hotspot. */
	salt = bpf_get_prandom_u32() % (u32)nr_cpu_ids;
	start = (st->cursor + 1U + salt) % (u32)nr_cpu_ids;
	need = flow_steal_need(idle && base == 0 && !win_left);
	/* SMT sibling first with one live check and no scan. */
	if (tp && tp->smt_sib != 0xffffffffU) {
		u32 sib = tp->smt_sib;
		if (sib != (u32)cpu && flow_cpu_live(sib) &&
		    scx_bpf_dsq_nr_queued(flow_vtime_dsq(sib)) >=
		    (s32)need) {
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
			    (s32)need)
				continue;
			steal_dsq = pdsq;
			have = true;
		}
	}
	/* Gated cross domain only with an empty local window. */
	/* Donors hold at least two, and only starved tasks move. */
	if (!have && local_empty && base == 0) {
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
			if (scx_bpf_dsq_nr_queued(pdsq) < 2)
				continue;
			lim = base + 1U;
			if (lim > budget)
				lim = budget;
			got = flow_drain_starved(cpu, pdsq, lim,
			    base, now);
			if (got != 0) {
				__sync_fetch_and_add(
				    &flow_stats.steal_moves,
				    (u64)got);
				st->cursor = (start + 8U) %
				    (u32)nr_cpu_ids;
				return got;
			}
		}
		st->cursor = (start + 8U) % (u32)nr_cpu_ids;
		return 0;
	}
	if (!have) {
		st->cursor = (start + 8U) % (u32)nr_cpu_ids;
		return 0;
	}
	lim = base + 1U;
	if (lim > budget)
		lim = budget;
	got = flow_drain_one(cpu, steal_dsq, lim, base, true);
	if (got != 0)
		__sync_fetch_and_add(&flow_stats.steal_moves,
		    (u64)got);
	st->cursor = (start + 8U) % (u32)nr_cpu_ids;
	return got;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 global_moved = 0;
	u64 own_fast;
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
	own_fast = flow_fast_dsq((u32)cpu);
	own_vtime = flow_vtime_dsq((u32)cpu);
	over = flow_overflow_dsq();
	/* Own fast FIFO first with room left for the rest. */
	/* Depth stays at 4 with insertion order and no class filter. */
	if (scx_bpf_dsq_nr_queued(own_fast) != 0) {
		lim = moved + flow_fast_cap(budget);
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, own_fast, lim, moved,
		    false);
		moved += got;
	}
	/* Own deadline queue next with a cap at 12 and mask wins. */
	/* Insertion order tracks deadlines under monotonic virtual time. */
	if (moved < budget &&
	    scx_bpf_dsq_nr_queued(own_vtime) != 0) {
		lim = moved + flow_own_cap(budget);
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, own_vtime, lim, moved,
		    false);
		moved += got;
	}
	local_empty = scx_bpf_dsq_nr_queued(own_fast) == 0 &&
	    scx_bpf_dsq_nr_queued(own_vtime) == 0;
	/* One steal trip over bound 8 peers with a single move. */
	/* Need is 1 when idle and empty else 2 so busy owners keep one. */
	if (moved < budget && nr_cpu_ids > 1) {
		got = flow_steal_one(cpu, budget, moved,
		    local_empty);
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
			    (u64)SCX_DSQ_GLOBAL, lim, moved, false);
			moved += got;
			global_moved += got;
		}
		if (moved < lim &&
		    scx_bpf_dsq_nr_queued(over) != 0) {
			got = flow_drain_one(cpu, over, lim, moved,
			    false);
			moved += got;
			over_moved += got;
		}
	}
	/* Gated cross domain backstop over overflow when idle local. */
	/* Young tasks miss past, so old tasks behind them still surface. */
	if (moved == 0) {
		lim = flow_tail_cap(budget);
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
