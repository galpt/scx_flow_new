// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op
 *
 * Drains own, park, and peer queues with park isolation. Keeps dispatch on
 * halves with peer steals that respect mask, depth, and idle rescue.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
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
static __always_inline u32 flow_drain_park(s32 cpu,
	u32 budget)
{
	struct task_struct *p;
	u64 park;
	u8 thief_group;
	u32 moved = 0;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	if (budget == 0)
		return 0;
	thief_group = flow_group_of_cpu((u32)cpu,
	    nr_cpu_ids);
	park = flow_park_for_group(thief_group);
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, park, 0) {
		if (moved >= budget)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			__sync_fetch_and_add(&flow_stats.park_moves, 1);
			moved++;
		} else {
			bpf_task_release(p);
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
static __always_inline u32 flow_drain_peer(s32 thief,
	u32 peer, u64 min_depth)
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
	if (scx_bpf_dsq_nr_queued(dsq) < min_depth)
		return 0;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)thief,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)thief, 0)) {
			bpf_task_release(p);
			stole = true;
			break;
		}
		bpf_task_release(p);
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
	u64 park;
	u8 thief_group;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	thief_group = flow_group_of_cpu((u32)cpu,
	    nr_cpu_ids);
	park = flow_park_for_group(thief_group);
	moved += flow_drain_own(cpu, budget - moved);
	if (moved >= budget)
		return;
	if (scx_bpf_dsq_nr_queued(park) > 0)
		moved += flow_drain_park(cpu, budget - moved);
	if (moved >= budget)
		return;
	own_left = scx_bpf_dsq_nr_queued(
	    flow_dsq_for_cpu((u32)cpu));
	if (own_left > 0 && moved > 0)
		return;
	{
		u64 park_left;
		u64 min_depth;
		struct flow_cpu_state *st;
		u32 cur;
		u32 i;
		u32 j;
		park_left = scx_bpf_dsq_nr_queued(park);
		if (park_left > 0 && moved > 0)
			return;
		if (moved == 0 && own_left == 0)
			min_depth = 1;
		else
			min_depth = (u64)FLOW_STEAL_MIN_DEPTH;
		st = flow_cpu((u32)cpu);
		cur = st ? st->cursor : 0;
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
			moved += flow_drain_peer(cpu, peer,
			    min_depth);
		}
		/* Keep rate and stand with new peer. CAS keeps fresh flags with 4 tries. */
		/* One kick per slice alone, bounded extra IPIs on exact overlap only. */
		if (st) {
			bpf_for(j, 0, 4) {
				u32 seen = st->cursor;
				u32 want =
				    flow_cursor_store(cur,
				    seen);
				u32 got =
				    __sync_val_compare_and_swap(
				    &st->cursor, seen, want);
				if (got == seen)
					break;
				if (j == 3)
					__sync_lock_test_and_set(
					    &st->cursor, want);
			}
		}
	}
}
