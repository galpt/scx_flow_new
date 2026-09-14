// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op
 *
 * Drains the group slot store in rotation with k-trips, cross-group rescue,
 * defer counts, and a kick safety net. One shared drain body feeds every trip
 * with mask wins and move to local, so only DSQ id selection branches. Seek
 * feeds stats only and never gates a drain, so stale marks add fallback work
 * with no hide.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. Own, overflow, fill, and rescue use */
/* one for_each with mask wins and move to local, so only DSQ id selection */
/* branches outside with no duplicated loop body. Inlined into the trip loop, */
/* so the verifier merges states at the loop back edge with one body analysis */
/* instead of per-site subprogram repeats. Base carries moved so far with */
/* budget kept whole, so the break reads one wide sum with no narrow */
/* remainder beside it and states merge. Callers precompute DSQ and capped */
/* live already proven at dispatch top. No stats inside, so the caller */
/* aggregates moves once per dispatch with no per bucket atomics. */
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
/* Wheel seek over head and fine with count to first set. Head holds */
/* near slots 0 to 7, fine holds 0 to 255. Each level uses count trailing */
/* zeros, so no linear 256 scan runs. No loop nests with for_each either */
/* way: seek runs before drains with no for_each inside seek and no seek */
/* inside for_each. Head hit returns with no array read, fine hit returns */
/* with no further read, empty returns 256 skips with the tail slot, so hot */
/* stays fast with bounded cost. Coarse far blocks rest in the group */
/* overflow tail drained by trips, so the window remainder still sees far */
/* work with no second seek and no hide. Stats only, never a drain gate. */
static __always_inline u32 flow_wheel_seek_full(u32 *slot_out)
{
	u32 head = flow_wheel_head;
	u32 h = head & 0xFFU;
	u64 w0;
	u64 w1;
	u64 w2;
	u64 w3;
	u32 b;
	u32 slot;
	if (h != 0) {
		b = (u32)__builtin_ctz(h);
		*slot_out = b;
		return b;
	}
	w0 = flow_wheel_fine[0];
	if (w0 != 0ULL) {
		b = (u32)__builtin_ctzll(w0);
		slot = b;
		*slot_out = slot;
		return slot;
	}
	w1 = flow_wheel_fine[1];
	if (w1 != 0ULL) {
		b = (u32)__builtin_ctzll(w1);
		slot = 64U + b;
		*slot_out = slot;
		return slot;
	}
	w2 = flow_wheel_fine[2];
	if (w2 != 0ULL) {
		b = (u32)__builtin_ctzll(w2);
		slot = 128U + b;
		*slot_out = slot;
		return slot;
	}
	w3 = flow_wheel_fine[3];
	if (w3 != 0ULL) {
		b = (u32)__builtin_ctzll(w3);
		slot = 192U + b;
		*slot_out = slot;
		return slot;
	}
	*slot_out = (u32)FLOW_WHEEL_TOTAL;
	return 256U;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 own_moved = 0;
	u32 scap;
	u32 k;
	u8 slot_cur = 0;
	u8 sgroup = 0;
	u8 ogroup = 0;
	u64 odsq = 0;
	u64 odsq_own = 0;
	u64 rdsq = 0;
	u32 seek_slot = (u32)FLOW_WHEEL_TOTAL;
	bool far_marked = false;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	sgroup = flow_group_live((u32)cpu,
	    nr_cpu_ids);
	odsq = flow_slot_overflow_dsq(sgroup);
	/* Seek counts hierarchical skips with head, fine, and empty */
	/* hits. Marks only accumulate with no clear, so seek stays fail-positive */
	/* with drains owning moves. Drains always run below with no early */
	/* return, since marks feed stats only and never gate a drain. The slot */
	/* feeds the near hint for defer below with overflow covering far. */
	{
		u32 skips = flow_wheel_seek_full(&seek_slot);
		__sync_fetch_and_add(&flow_stats.wheel_skips,
		    (u64)skips);
		if (seek_slot < 8U)
			__sync_fetch_and_add(
			    &flow_stats.wheel_head_hits, 1);
		else if (seek_slot < 256U)
			__sync_fetch_and_add(
			    &flow_stats.wheel_fine_hits, 1);
		else
			__sync_fetch_and_add(
			    &flow_stats.wheel_empty, 1);
		far_marked = seek_slot !=
		    (u32)FLOW_WHEEL_TOTAL;
	}
	/* Rotation loads the per CPU slot cursor at dispatch top with plain */
	/* owning CPU access. The store below keeps capped-conditional retain, */
	/* so a capped own leftover retries next dispatch instead of a 256 wrap */
	/* delay while unmovable-only leftover advances with no pin. Decoupled */
	/* from the steal cursor, so hot buckets never freeze. One u8 per CPU */
	/* with BSS zero start. Volatile mask keeps the index proven. */
	{
		volatile u32 vcpu = (u32)cpu;
		u32 sidx = vcpu & 1023U;
		slot_cur = flow_slot_cur[sidx];
	}
	odsq_own = flow_slot_dsq(sgroup,
	    (u64)slot_cur);
	ogroup = sgroup ^ 1U;
	rdsq = flow_slot_dsq(ogroup,
	    (u64)slot_cur);
	scap = flow_slot_cap(budget);
	/* One slot loop shares the single generic body with DSQ id branching */
	/* outside, so own, overflow, and 2 fill keep one subprogram call each. */
	/* Trip 0 owns the cursor bucket to budget, so hot work drains in one */
	/* visit with no 256 wrap delay. Trip 1 owns overflow and trips 2 to 3 */
	/* own fill ahead distinct from own, each capped at D with lim toward */
	/* budget, so 2 times D is 8 with overflow 4 toward budget 32 and defer */
	/* covering rest. Own move count tracks trip 0 for capped retain below, */
	/* so unmovable-only leftover advances with no pin. Bound 4 sits under */
	/* the steal bound with no new nest beyond the shared drain shape. */
	bpf_for(k, 0, 4) {
		u64 dsq;
		u32 cap;
		u32 lim;
		if (k == 0) {
			dsq = odsq_own;
			cap = budget;
		} else if (k == 1) {
			dsq = odsq;
			cap = scap;
		} else {
			u8 b = flow_slot_add(slot_cur,
			    k - 2);
			dsq = flow_slot_dsq(sgroup,
			    (u64)b);
			cap = scap;
		}
		lim = moved + cap;
		if (lim > budget)
			lim = budget;
		moved += flow_drain_one(cpu, dsq, lim, moved);
		if (k == 0)
			own_moved = moved;
	}
	/* Capped retain with always rescue. Capped own leftover retries next */
	/* dispatch with budget, so hot work with 32 moved keeps cur for retry */
	/* with no 256 wrap delay. Uncapped leftover means the drain visited */
	/* every task with moves below the cap, so the rest is mask-blocked or */
	/* failed and must advance with no pin. Retain stays liveness-safe, */
	/* since it holds only on progress at the cap. Rescue runs always with */
	/* budget open and no empty gate, so every dispatch visits the other */
	/* group cursor bucket with 1 toward budget with no strand when own */
	/* holds movable work. One keeps the cross-group visit with minimal */
	/* jump cost while rotation plus the kick chain still sweep every */
	/* bucket. Both FIFO, so per DSQ one flavor holds with mask */
	/* wins inside the shared body. Recomputes the index to keep no live */
	/* across the loop. */
	{
		volatile u32 vcpu2 = (u32)cpu;
		u32 sidx2 = vcpu2 & 1023U;
		bool left = scx_bpf_dsq_nr_queued(
		    odsq_own) != 0;
		bool capped = own_moved >= budget;
		if (left && capped)
			flow_slot_cur[sidx2] = slot_cur;
		else
			flow_slot_cur[sidx2] =
			    flow_slot_next(slot_cur);
		if (moved < budget) {
			u32 lim2 = moved + 1U;
			if (lim2 > budget)
				lim2 = budget;
			moved += flow_drain_one(cpu, rdsq,
			    lim2, moved);
		}
	}
	if (moved != 0)
		__sync_fetch_and_add(&flow_stats.slot_moves,
		    (u64)moved);
	/* Defer with the kick safety net. Own keeps the cursor bucket, park */
	/* keeps the group overflow, rescue keeps the other group cursor */
	/* bucket. Fill ahead rides the trip drains with no remainder read, */
	/* so leftover fill becomes own within 2 rotations with no strand */
	/* and no extra fan-out. Defer aggregates once per dispatch with */
	/* one atomic when moves reach D with any work left in the window or a */
	/* far mark from the top seek. The far hint predates the drains, so only */
	/* the window reads stay exact with no global scan. Monotonic marks keep */
	/* far fail-positive with no hide, so defer reads as D-cap exception. */
	/* Safety net kicks once per dispatch with leftover: progress kick covers */
	/* window leftover with any move, far kick covers marked tails with any */
	/* move, sweep kick covers zero-move marks with bound 255 and reset on */
	/* move with no infinite loop. */
	{
		u64 own_left;
		u64 park_left;
		bool rescue_left;
		bool window_left;
		bool far_left = far_marked;
		own_left = scx_bpf_dsq_nr_queued(odsq_own);
		park_left = scx_bpf_dsq_nr_queued(odsq);
		rescue_left = scx_bpf_dsq_nr_queued(rdsq) != 0;
		window_left = own_left > 0 || park_left > 0 ||
		    rescue_left;
		if (moved >= (u32)FLOW_SLOT_D &&
		    (window_left || far_left))
			__sync_fetch_and_add(&flow_stats.slot_defer,
			    1);
		{
			volatile u32 vcpu3 = (u32)cpu;
			u32 sidx3 = vcpu3 & 1023U;
			u8 sweep = flow_slot_sweep_cnt[sidx3];
			bool kick = false;
			if (moved > 0 && window_left)
				kick = true;
			else if (moved > 0 && far_left)
				kick = true;
			else if (moved == 0 && far_left &&
			    sweep < 255) {
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
