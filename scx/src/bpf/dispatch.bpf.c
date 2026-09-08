/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Service, included by main.bpf.c via include.
 *
 * Own queue drains first, then the park queue, then
 * idle steals from peers. Each drain visits every
 * queued task in order and moves allowed tasks past
 * bad heads. Steals scan peers with a rotating cursor
 * bounded per pass.
 */

/*
 * Drain one per CPU queue with skip past bad heads.
 * The iterator visits every queued task in order, so
 * one dead, foreign, or failed head never blocks
 * later work. Exiting tasks move to the local DSQ to
 * run to exit, so they never wedge behind a skip.
 * Each eligible task moves to the local DSQ of the
 * asking CPU. Returns the count moved, capped at the
 * given budget.
 */
static __always_inline u32 flow_drain_own(s32 cpu,
	u32 budget)
{
	struct task_struct *p;
	u64 dsq;
	u32 moved = 0;

	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	if (budget == 0)
		return 0;
	dsq = flow_dsq_for_cpu((u32)cpu);
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved >= budget)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			continue;
		}
		bpf_task_release(p);
		moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}

/*
 * Drain the park queue with skip past bad heads. The
 * iterator visits every parked task in order, so one
 * dead, foreign, or failed head never blocks later
 * work. Exiting tasks move to the local DSQ to run
 * to exit, so they never wedge behind a skip. Each
 * eligible task moves to the local DSQ of the asking
 * CPU. Returns the count moved, capped at the given
 * budget.
 */
static __always_inline u32 flow_drain_park(s32 cpu,
	u32 budget)
{
	struct task_struct *p;
	u32 moved = 0;

	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	if (budget == 0)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, FLOW_DSQ_PARK, 0) {
		if (moved >= budget)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			continue;
		}
		bpf_task_release(p);
		__sync_fetch_and_add(&flow_stats.park_moves, 1);
		moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}

/*
 * Steal one task from a peer queue for an idle thief.
 * The iterator visits every queued task in order, so
 * one dead, foreign, or failed head never blocks
 * later work. The first allowed task moves to the
 * local DSQ of the thief. Exiting tasks move when
 * allowed, so they run to exit on the owner or on a
 * thief. Thin donors keep their last task, so steals
 * need at least two queued tasks. Returns one when a
 * task moved and zero otherwise.
 */
static __always_inline u32 flow_drain_peer(s32 thief,
	u32 peer)
{
	struct task_struct *p;
	u64 dsq;
	bool stole = false;

	if (thief < 0)
		return 0;
	if (!flow_cpu_live((u32)thief))
		return 0;
	if (!flow_cpu_live(peer))
		return 0;
	if (thief == (s32)peer)
		return 0;
	dsq = flow_dsq_for_cpu(peer);
	if (scx_bpf_dsq_nr_queued(dsq) == 0)
		return 0;
	if ((u64)FLOW_GATE_STICKY &&
	    scx_bpf_dsq_nr_queued(dsq) <
	    (u64)FLOW_STEAL_MIN_DEPTH)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (!bpf_cpumask_test_cpu((u32)thief,
		    p->cpus_ptr)) {
			bpf_task_release(p);
			continue;
		}
		if (!scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)thief, 0)) {
			bpf_task_release(p);
			continue;
		}
		bpf_task_release(p);
		stole = true;
		break;
	}
	bpf_rcu_read_unlock();
	if (stole) {
		__sync_fetch_and_add(&flow_stats.steal_moves, 1);
		return 1;
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_DISPATCH_MAX_BATCH;
	u32 moved = 0;
	u32 own_left = 0;

	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* Own queue drains first with skip past bad heads. */
	moved += flow_drain_own(cpu, budget - moved);
	if (moved >= budget)
		return;
	/* Parked tasks move when the mask allows. */
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_PARK) > 0)
		moved += flow_drain_park(cpu, budget - moved);
	if (moved >= budget)
		return;
	own_left = scx_bpf_dsq_nr_queued(
	    flow_dsq_for_cpu((u32)cpu));
	/* An idle CPU steals past unmovable leftovers. */
	/* A busy CPU with local work stays home. */
	if (own_left > 0 && moved > 0)
		return;
	if (scx_bpf_dsq_nr_queued((u64)FLOW_DSQ_PARK) > 0 &&
	    moved > 0)
		return;
	/* Idle thieves scan peers with a rotating cursor. */
	{
		struct flow_cpu_state *st;
		u32 cur;
		u32 i;

		st = flow_cpu((u32)cpu);
		cur = st ? (u32)st->cursor : 0;
		bpf_for(i, 0, 8) {
			u32 peer;

			if (moved >= budget)
				break;
			if (i >= (u32)FLOW_STEAL_BOUND)
				break;
			peer = flow_steal_next(cur,
			    (u32)nr_cpu_ids);
			cur = peer;
			if (!flow_cpu_live(peer))
				continue;
			if ((s32)peer == cpu)
				continue;
			moved += flow_drain_peer(cpu, peer);
		}
		if (st)
			__sync_lock_test_and_set(&st->cursor, cur);
	}
}
