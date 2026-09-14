// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op
 *
 * Drains the group slot store in rotation with k-trips,
 * cross-group rescue, defer counts, and a kick safety net.
 * One shared drain body feeds every trip with mask wins and
 * move to local, so only DSQ id selection branches. Seek
 * feeds stats only and never gates a drain or a kick, so
 * stale marks add no storm with no hide. Kicks use window
 * truth only with far progress when idle jumps far.
 * Far jumps to the next own bucket ahead when idle with
 * no window, so boot 15 and 61 drain within 3 hops with
 * no 15 step walk and late 61 still chains. Hint and
 * window gate keep the far scan off the hot path with
 * no hide. Pinned tasks rest in overflow, so trips visit
 * them every pass with no rotation.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Shared drain with DSQ and budget only. Own, overflow, */
/* fill, other overflow, and rescue use one for_each with mask */
/* wins and move to local, so only DSQ id selection branches */
/* outside with no duplicated loop body. Inlined into the trip */
/* loop, so the verifier merges states at the loop back edge */
/* with one body analysis instead of per-site repeats. Base */
/* carries moved so far with budget kept whole, so the break */
/* reads one wide sum with no narrow remainder beside it and */
/* states merge. Callers precompute DSQ and capped live already */
/* proven at dispatch top. No stats inside, so the caller */
/* aggregates moves once per dispatch with no per bucket */
/* atomics. */
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
/* Wheel seek over head and fine with count to first set. */
/* Head holds near slots 0 to 7, fine holds 0 to 255. Each */
/* level uses count trailing zeros, so no linear 256 scan */
/* runs. No loop nests with for_each either way. Seek runs */
/* before drains with no for_each inside seek and no seek */
/* inside for_each. Head hit returns with no array read, fine */
/* hit returns with no further read, empty returns 256 skips */
/* with the tail slot, so hot stays fast with bounded cost. */
/* Coarse far blocks rest in the group overflow tails drained */
/* by trips, so no second seek runs. Stats only, never a drain */
/* or kick gate. */
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
/* Next own bucket ahead with queued work when idle. */
/* Scans 256 ahead from cur with nr_queued truth and */
/* no mark use, so stale marks add no force. Returns */
/* the first bucket ahead with work, else cur with */
/* found clear, so the caller jumps only on far work. */
/* Bound 256 covers every bucket in one pass, so boot */
/* 15 and 61 drain within 3 hops with no 15 step walk. */
static __always_inline u8 flow_slot_far_next(u8 cur,
	u8 group, bool *found)
{
	u8 res = cur;
	bool have = false;
	u32 off;

	bpf_for(off, 0, 256) {
		u8 b;
		u64 dsq;

		if (have)
			continue;
		b = (u8)((u32)cur + off);
		dsq = flow_slot_dsq(group, (u64)b);
		if (scx_bpf_dsq_nr_queued(dsq) != 0) {
			res = b;
			have = true;
		}
	}
	*found = have;
	return res;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget = (u32)FLOW_SLOT_BUDGET;
	u32 moved = 0;
	u32 own_moved = 0;
	u32 scap;
	u32 own_cap;
	u32 k;
	u8 slot_cur = 0;
	u8 sgroup = 0;
	u8 ogroup = 0;
	u64 odsq = 0;
	u64 odsq_own = 0;
	u64 rdsq = 0;
	u64 oodsq = 0;
	u32 seek_slot = (u32)FLOW_WHEEL_TOTAL;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	sgroup = flow_group_live((u32)cpu,
	    nr_cpu_ids);
	odsq = flow_slot_overflow_dsq(sgroup);
	/* Seek counts hierarchical skips with head, fine, */
	/* and empty hits. Marks only accumulate with no clear, */
	/* so seek stays fail-positive with drains owning moves. */
	/* Drains always run below with no early return, since */
	/* marks feed stats only and never gate a drain or kick. */
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
	}
	/* Rotation loads the per CPU slot cursor at dispatch */
	/* top with plain owning CPU access. The store below keeps */
	/* capped-conditional retain with at most 3 in a row, so a */
	/* capped own leftover retries next dispatch instead of a */
	/* 1024 wrap delay while unmovable-only leftover advances */
	/* with no pin. Decoupled from the steal cursor, so hot */
	/* buckets stay bounded with no freeze. One u8 per CPU with */
	/* BSS zero start. Volatile mask keeps the index proven. */
	{
		volatile u32 vcpu = (u32)cpu;
		u32 sidx = vcpu & 1023U;
		slot_cur = flow_slot_cur[sidx];
	}
	/* Far sweep jumps to the next own bucket ahead when */
	/* idle with no own work, so boot 15 and 61 drain */
	/* within 3 hops with no 15 step walk and late 61 */
	/* still finds a jump on the next idle pass. Hint */
	/* checks the last near insert first with one read, */
	/* so one far bucket jumps with no 256 scan. Window */
	/* gate skips the scan when overflow, fill, rescue, */
	/* or other overflow holds work, since trips drain */
	/* that window with far work waiting at most 2 */
	/* rotations. Else scans own group only with */
	/* nr_queued truth and no mark use, so stale marks */
	/* add no force. Runs only when own holds no work, */
	/* so hot pays no scan with no storm. Bound 256 */
	/* worst hops with one far kick. Mark holds per CPU */
	/* far jump this pass in BSS with no live across */
	/* trips, so states stay flat. */
	{
		u64 pre_own;
		bool pre_empty;

		pre_own = flow_slot_dsq(sgroup,
		    (u64)slot_cur);
		pre_empty =
		    scx_bpf_dsq_nr_queued(pre_own) == 0;
		if (pre_empty) {
			u8 hint = flow_slot_hint[sgroup &
			    1U];
			u64 hint_dsq = flow_slot_dsq(
			    sgroup, (u64)hint);
			bool done = false;

			if (scx_bpf_dsq_nr_queued(
			    hint_dsq) != 0) {
				volatile u32 vcpu2 =
				    (u32)cpu;
				u32 sidx2 = vcpu2 &
				    1023U;

				slot_cur = hint;
				flow_slot_cur[sidx2] =
				    hint;
				flow_slot_far[sidx2] = 1;
				done = true;
			}
			if (!done) {
				u8 og = sgroup ^ 1U;
				u64 od =
				    flow_slot_overflow_dsq(
				    sgroup);
				u64 f0 = flow_slot_dsq(
				    sgroup,
				    (u64)flow_slot_add(
				    slot_cur, 0));
				u64 f1 = flow_slot_dsq(
				    sgroup,
				    (u64)flow_slot_add(
				    slot_cur, 1));
				u64 rd = flow_slot_dsq(
				    og, (u64)slot_cur);
				u64 od2 =
				    flow_slot_overflow_dsq(
				    og);
				bool win =
				    scx_bpf_dsq_nr_queued(
				    od) != 0 ||
				    scx_bpf_dsq_nr_queued(
				    f0) != 0 ||
				    scx_bpf_dsq_nr_queued(
				    f1) != 0 ||
				    scx_bpf_dsq_nr_queued(
				    rd) != 0 ||
				    scx_bpf_dsq_nr_queued(
				    od2) != 0;

				if (win) {
					volatile u32 vcpu2 =
					    (u32)cpu;
					u32 sidx2 = vcpu2 &
					    1023U;

					flow_slot_far[sidx2] =
					    0;
				} else {
					bool have = false;
					u8 next =
					    flow_slot_far_next(
					    slot_cur, sgroup,
					    &have);

					if (have) {
						volatile u32 vcpu2 =
						    (u32)cpu;
						u32 sidx2 =
						    vcpu2 &
						    1023U;

						slot_cur = next;
						flow_slot_cur[
						    sidx2] = next;
						flow_slot_far[
						    sidx2] = 1;
					} else {
						volatile u32 vcpu2 =
						    (u32)cpu;
						u32 sidx2 =
						    vcpu2 &
						    1023U;

						flow_slot_far[
						    sidx2] = 0;
					}
				}
			}
		} else {
			volatile u32 vcpu2 = (u32)cpu;
			u32 sidx2 = vcpu2 & 1023U;

			flow_slot_far[sidx2] = 0;
		}
	}
	odsq_own = flow_slot_dsq(sgroup,
	    (u64)slot_cur);
	ogroup = sgroup ^ 1U;
	rdsq = flow_slot_dsq(ogroup,
	    (u64)slot_cur);
	oodsq = flow_slot_overflow_dsq(ogroup);
	scap = flow_slot_cap(budget);
	own_cap = flow_slot_own_cap(budget);
	/* One slot loop shares the single generic body with DSQ */
	/* id branching outside, so own, overflow, 2 fill, and */
	/* other overflow keep one subprogram call each. Trip 0 */
	/* owns the cursor bucket at budget minus one, so hot work */
	/* drains with one slot left for the rest with no strand. */
	/* Trip 1 owns own overflow and trips 2 to 3 own fill ahead */
	/* distinct from own, trip 4 owns other overflow, each at D */
	/* with lim toward budget, so 4 times D is 16 toward 32 and */
	/* defer covers rest. Overflow trips skip empty with one */
	/* read and no iterator, so light pays no empty scan with */
	/* no hide. Trip 4 keeps cross-group overflow drainable */
	/* with mask wins, so a hog far task on an all-light host */
	/* still drains bounded. Own count tracks trip 0 for */
	/* capped retain below, so unmovable-only leftover */
	/* advances with no pin. Bound 5 sits under the steal */
	/* bound with no new nest beyond the shared shape. */
	bpf_for(k, 0, 5) {
		u64 dsq;
		u32 cap;
		u32 lim;
		if (k == 0) {
			dsq = odsq_own;
			cap = own_cap;
		} else if (k == 1) {
			dsq = odsq;
			cap = scap;
		} else if (k == 4) {
			dsq = oodsq;
			cap = scap;
		} else {
			u8 b = flow_slot_add(slot_cur,
			    k - 2);
			dsq = flow_slot_dsq(sgroup,
			    (u64)b);
			cap = scap;
		}
		if ((k == 1 || k == 4) &&
		    scx_bpf_dsq_nr_queued(dsq) == 0)
			continue;
		lim = moved + cap;
		if (lim > budget)
			lim = budget;
		moved += flow_drain_one(cpu, dsq, lim, moved);
		if (k == 0)
			own_moved = moved;
	}
	/* Capped retain with bound and gated rescue. Capped */
	/* own leftover at 31 retries next dispatch with no 1024 */
	/* wrap delay. At most 3 retains in a row with force */
	/* advance, so sustained hot never pins far buckets. */
	/* Uncapped leftover means the drain visited every task */
	/* with moves below the cap, so the rest is mask-blocked */
	/* or failed and must advance with no pin. Retain stays */
	/* liveness-safe, since it holds only on progress at the */
	/* cap with a bounded count. Rescue runs with budget */
	/* open and rescue work only, so empty rescue pays one */
	/* read with no iterator and no strand when own holds */
	/* movable work. One keeps the cross-group visit with */
	/* minimal jump cost while rotation and the kick chain */
	/* still sweep every bucket. Both FIFO, so per DSQ one */
	/* flavor holds with mask wins inside the shared body. */
	/* Recomputes the index to keep no live across the loop. */
	{
		volatile u32 vcpu2 = (u32)cpu;
		u32 sidx2 = vcpu2 & 1023U;
		bool left = scx_bpf_dsq_nr_queued(
		    odsq_own) != 0;
		bool capped = own_cap != 0 &&
		    own_moved >= own_cap;
		u8 rcnt = flow_slot_retain_cnt[sidx2];
		bool keep = left && capped &&
		    rcnt < (u8)FLOW_SLOT_RETAIN_MAX;
		if (keep) {
			flow_slot_cur[sidx2] = slot_cur;
			flow_slot_retain_cnt[sidx2] = rcnt + 1;
		} else {
			flow_slot_cur[sidx2] =
			    flow_slot_next(slot_cur);
			flow_slot_retain_cnt[sidx2] = 0;
		}
		if (moved < budget &&
		    scx_bpf_dsq_nr_queued(rdsq) != 0) {
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
	/* Defer with the kick safety net. Own keeps the cursor */
	/* bucket, park keeps own overflow, rescue keeps other */
	/* cursor, other overflow keeps the far tail. Fill ahead */
	/* rides the trip drains with no remainder read, so leftover */
	/* fill becomes own within 2 rotations with no strand and no */
	/* extra fan-out. Defer aggregates once per dispatch with */
	/* one atomic when moves reach D with work left in the */
	/* window. The window reads stay exact with nr_queued truth */
	/* and no global scan, so defer reads as D-cap exception */
	/* with no storm. Safety net kicks once per dispatch with */
	/* leftover: progress kick covers window leftover with any */
	/* move, sweep kick covers zero-move window with bound 256 */
	/* and reset on move with no infinite loop. Far adds one */
	/* progress kick when idle jumps far, so late 61 still */
	/* chains after 15 drains with no window. Marks feed stats */
	/* only and never gate a kick. */
	{
		u64 own_left;
		u64 park_left;
		bool rescue_left;
		bool other_left;
		bool window_left;
		own_left = scx_bpf_dsq_nr_queued(odsq_own);
		park_left = scx_bpf_dsq_nr_queued(odsq);
		rescue_left = scx_bpf_dsq_nr_queued(rdsq) != 0;
		other_left = scx_bpf_dsq_nr_queued(oodsq) != 0;
		window_left = own_left > 0 || park_left > 0 ||
		    rescue_left || other_left;
		if (moved >= (u32)FLOW_SLOT_D && window_left)
			__sync_fetch_and_add(&flow_stats.slot_defer,
			    1);
		{
			volatile u32 vcpu3 = (u32)cpu;
			u32 sidx3 = vcpu3 & 1023U;
			u16 sweep = flow_slot_sweep_cnt[sidx3];
			bool far = flow_slot_far[sidx3] != 0;
			bool kick = false;
			if (moved > 0 && (window_left || far))
				kick = true;
			else if (moved == 0 && window_left &&
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
