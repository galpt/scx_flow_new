// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. */
/* Moves mask allowed tasks to local with a miss cap at 4. */
/* One bad head never blocks later work with no full scan. */
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
		if (miss >= 4U)
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
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 over_moved = 0;
	u32 own_cap;
	u64 own;
	u64 over;
	u32 lim;
	u32 got;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	own = flow_slot_cpu_dsq((u32)cpu);
	over = flow_slot_overflow_dsq();
	own_cap = flow_slot_own_cap(budget);
	/* Own queue first with room left for overflow and steal. */
	if (scx_bpf_dsq_nr_queued(own) != 0) {
		lim = moved + own_cap;
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, own, lim, moved);
		moved += got;
	}
	/* Overflow next with a cap at 4 and mask wins. */
	/* Shares the miss cap at 4 with no head stall. */
	if (moved < budget && scx_bpf_dsq_nr_queued(over) != 0) {
		lim = moved + flow_slot_cap(budget);
		if (lim > budget)
			lim = budget;
		got = flow_drain_one(cpu, over, lim, moved);
		moved += got;
		over_moved += got;
	}
	/* One steal trip over bound 8 peers with a single move. */
	/* Need is 1 when idle and empty else 2 so busy owners keep one. */
	/* The cursor steps by 8 with wrap so passes spread with no hotspot. */
	if (moved < budget && nr_cpu_ids > 1) {
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		if (st) {
			u32 start = (st->cursor + 1U) %
			    (u32)nr_cpu_ids;
			u64 steal_dsq = 0;
			bool have = false;
			bool idle = st->running_pid == 0;
			bool win_left =
			    scx_bpf_dsq_nr_queued(own) != 0 ||
			    scx_bpf_dsq_nr_queued(over) != 0;
			u64 need = flow_steal_need(
			    idle && moved == 0 && !win_left);
			u32 off;
			bpf_for(off, 0, FLOW_STEAL_BOUND) {
				u32 peer;
				u64 pdsq;
				if (have)
					continue;
				peer = (start + off) %
				    (u32)nr_cpu_ids;
				if (!flow_cpu_live(peer))
					continue;
				pdsq = flow_slot_cpu_dsq(peer);
				if (scx_bpf_dsq_nr_queued(pdsq) <
				    need)
					continue;
				steal_dsq = pdsq;
				have = true;
			}
			if (have) {
				lim = moved + 1U;
				if (lim > budget)
					lim = budget;
				got = flow_drain_one(cpu, steal_dsq,
				    lim, moved);
				moved += got;
				if (got != 0)
					__sync_fetch_and_add(
					    &flow_stats.steal_moves,
					    (u64)got);
			}
			st->cursor = (start + 8U) %
			    (u32)nr_cpu_ids;
		}
	}
	if (moved != 0)
		__sync_fetch_and_add(&flow_stats.slot_moves,
		    (u64)moved);
	if (over_moved != 0)
		__sync_fetch_and_add(&flow_stats.park_moves,
		    (u64)over_moved);
}
