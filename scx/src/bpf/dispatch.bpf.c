// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op
 *
 * Drains per CPU queues with overflow plus peer steal and a kick safety net.
 * One shared drain body feeds every trip with mask wins and move to local,
 * so only DSQ id selection branches. Own per CPU own group runs at 31,
 * own overflow at 4, own CPU other group at 4, other overflow at 4, then
 * peer steal visits 8 peers with single move toward budget 32. Sweep
 * covers zero move window only at 256 with reset on move. Pinned tasks
 * rest in overflow, so trips visit them every pass. All trips share one
 * drain body with mask wins and move to local, so per queue order stays
 * FIFO.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. Own, overflow, other CPU, other */
/* overflow, and peer use one for_each with mask wins and move to local, so */
/* only DSQ id selection branches outside with no duplicated loop body. */
/* Inlined into the trip loop, so the verifier merges states at the loop */
/* back edge with one body analysis instead of per-site repeats. Base */
/* carries moved so far with budget kept whole, so the break reads one wide */
/* sum with no narrow remainder beside it and states merge. Callers */
/* precompute DSQ and capped live already proven at dispatch top. No stats */
/* inside, so the caller aggregates moves once per dispatch with no per */
/* queue atomics. */
static __always_inline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved + base >= budget)
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
		} else {
			bpf_task_release(p);
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 scap;
	u32 own_cap;
	u8 sgroup = 0;
	u8 ogroup = 0;
	u64 own = 0;
	u64 own_over = 0;
	u64 other_cpu = 0;
	u64 other_over = 0;
	u32 off;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	sgroup = flow_group_live((u32)cpu,
	    nr_cpu_ids);
	ogroup = sgroup ^ 1U;
	own = flow_slot_cpu_dsq((u32)cpu, sgroup);
	own_over = flow_slot_overflow_dsq(sgroup);
	other_cpu = flow_slot_cpu_dsq((u32)cpu, ogroup);
	other_over = flow_slot_overflow_dsq(ogroup);
	scap = flow_slot_cap(budget);
	own_cap = flow_slot_own_cap(budget);
	/* Local trips at 4 with one body. Own runs at 31 with one slot left, */
	/* overflows and other CPU run at 4 with empty skip and no iterator, */
	/* so light pays no empty scan. Bound 4 sits under the */
	/* steal bound with one body analysis at the loop back edge. */
	bpf_for(off, 0, 4) {
		u64 dsq;
		u32 cap;
		u32 lim;
		u32 got;
		if (off == 0) {
			dsq = own;
			cap = own_cap;
		} else if (off == 1) {
			dsq = own_over;
			cap = scap;
		} else if (off == 2) {
			dsq = other_cpu;
			cap = scap;
		} else {
			dsq = other_over;
			cap = scap;
		}
		if (off != 0 &&
		    scx_bpf_dsq_nr_queued(dsq) == 0)
			continue;
		lim = moved + cap;
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, dsq, lim, moved);
		moved += got;
		if (off == 1 || off == 3)
			over_moved += got;
	}
	/* Peer steal at bound 8 with single move toward budget 32. Donor scan */
	/* reads 8 peers with one read each and no iterator, so shallow donors */
	/* skip early. Need is 1 when idle empty, else 2, so idle owners collect */
	/* the last task with no strand while busy owners leave one. Window */
	/* reads four local queues once after local trips with no global scan, */
	/* so need plus defer plus sweep share one window with no extra reads. */
	/* Scan keeps the first donor with work, then one shared drain moves a */
	/* single task with mask wins, so one bad head never blocks later work. */
	/* Single CPU hosts skip the whole pass with one check up front. */
	{
		bool win_left;
		struct flow_cpu_state *st;
		bool idle = false;
		u64 need = 2ULL;
		win_left = scx_bpf_dsq_nr_queued(own) != 0 ||
		    scx_bpf_dsq_nr_queued(own_over) != 0 ||
		    scx_bpf_dsq_nr_queued(other_cpu) != 0 ||
		    scx_bpf_dsq_nr_queued(other_over) != 0;
		st = flow_cpu((u32)cpu);
		if (st && st->running_pid == 0)
			idle = true;
		if (idle && moved == 0 && !win_left)
			need = flow_steal_need(true);
		else
			need = flow_steal_need(false);
		if (moved < budget && nr_cpu_ids > 1) {
			u64 steal_dsq = 0;
			bool have = false;
			bpf_for(off, 0, 8) {
				u32 peer;
				u64 pdsq;
				u64 q;
				if (have)
					continue;
				peer = ((u32)cpu + 1U + off) & 1023U;
				pdsq = flow_slot_cpu_dsq(peer, sgroup);
				q = scx_bpf_dsq_nr_queued(pdsq);
				if (q < need)
					continue;
				steal_dsq = pdsq;
				have = true;
			}
			if (have) {
				u32 lim = moved + 1U;
				u32 got;
				if (lim > budget)
					lim = budget;
				got = flow_drain_one(cpu, steal_dsq, lim,
				    moved);
				moved += got;
				/* Adds got with no branch, so the verifier keeps one state */
				/* with no extra jump and zero adds no count change. */
				/* See intf.h for the steal need helper. */
				__sync_fetch_and_add(&flow_stats.steal_moves,
				    (u64)got);
			}
		}
		if (moved != 0)
			__sync_fetch_and_add(&flow_stats.slot_moves,
			    (u64)moved);
		if (over_moved != 0)
			__sync_fetch_and_add(&flow_stats.park_moves,
			    (u64)over_moved);
		if (moved >= (u32)FLOW_SLOT_D && win_left)
			__sync_fetch_and_add(&flow_stats.slot_defer,
			    1);
		{
			volatile u32 vcpu3 = (u32)cpu;
			u32 sidx3 = vcpu3 & 1023U;
			u16 sweep = flow_slot_sweep_cnt[sidx3];
			bool kick = false;
			if (moved == 0 && win_left &&
			    sweep < (u16)FLOW_SLOT_SWEEP_MAX) {
				kick = true;
				flow_slot_sweep_cnt[sidx3] =
				    sweep + 1;
			}
			if (moved > 0)
				flow_slot_sweep_cnt[sidx3] = 0;
			if (kick) {
				scx_bpf_kick_cpu(cpu,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.slot_kicks, 1);
			}
		}
	}
}
