// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Every wakeup earns one EDF deadline from the burst predictor else
 * the hint period plus one virtual deadline from vruntime plus slice
 * over weight, and every task joins a tier queue with no admission
 * bound. Queue order uses the earlier of the two times, so urgent
 * tasks still win while hogs fall behind with lag bounds. Tasks join
 * direct when the target can drain before the shared home, so no task
 * waits for a busy CPU while shared room stays open. Missed tasks
 * rejoin a tier queue with a fresh deadline plus a miss count and one
 * idle kick and no wait. Pinned tasks wait in a tier queue with wait
 * set and one idle kick. Exiting tasks run at once on the task CPU
 * with no queue wait and no gate. The gate runs first for all other
 * arrivals, so a stale CPU plus a moved task fails closed with one
 * counter. The predictor average plus deviation shape later deadlines
 * with shift updates from stopping, so short bursts earn tight
 * deadlines with no table walk. Vruntime advances by scaled service
 * with no divide, and the CPU minimum folds forward on every charge,
 * so fairness tracks service with no table. Every tier join counts one
 * admit with no reject, so the counters track joins with no bound. The
 * exiting plus idle direct plus helper plus direct block form the four
 * kick points, so every wait meets at most one kick with no storm. A
 * direct preempt needs an eligible arrival plus a 100us margin lead
 * with more than 100us still left on the owner, so near ties plus
 * nearly done owners never bounce while one kick per wait stays.
 * Slice expiry paces the rest, so no slice write and no stamp run
 * here. See intf.h for the deadline plus fairness helpers and
 * dispatch.bpf.c for the tier scans.
 *
 * The op splits across enqueue/target, insert, and kick files with
 * the enqueue body here. Each helper stays inline except the kick,
 * which stays noinline with scalar input, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/target.bpf.c"
#include "enqueue/insert.bpf.c"
#include "enqueue/kick.bpf.c"

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	u64 now;
	u64 period;
	u64 deadline;
	u64 vtime;
	u32 hint;
	u64 avg = 0;
	u64 dev = 0;
	bool is_reenq = false;
	/* Requeue plus last slice expiry bypass the cgroup hint read plus */
	/* the occupant preempt lookup, so slice rotation stays cheap. The */
	/* cached hint in the task state carries the period, and the owner */
	/* paces at slice expiry with no extra kick. The requeue case is */
	/* rare beside fresh wakeups, so it stays unlikely. */
	if (unlikely(enq_flags & (SCX_ENQ_REENQ | SCX_ENQ_LAST)))
		is_reenq = true;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	/* The gate never runs here, so exiting work stays exempt. Exiting */
	/* is rare, so it stays unlikely. */
	if (unlikely(p->flags & PF_EXITING)) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    (u64)FLOW_QUANTUM_NS, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst &&
			    READ_ONCE(tst->running_pid) == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	tctx = NULL;
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	now = flow_now();
	/* The gate runs first with no state create, so stale CPUs plus */
	/* moved tasks fail closed with no alloc cost. The lookup stays */
	/* read only here, and the create follows only on pass. Rejects are */
	/* rare, so they stay unlikely. Gate misses rejoin the machine tier */
	/* with a fallback deadline as the fair time, so no path needs a */
	/* tail queue. */
	if (unlikely(!flow_entry_ok(sel, p, 0) && !flow_entry_ok(
	    scx_bpf_task_cpu(p), p, 0))) {
		struct flow_task_ctx *lctx = flow_lookup(p);
		u32 fh = 0;
		u64 fdl;
		flow_gate_reject();
		if (lctx) {
			lctx->wait_at = now;
			fh = READ_ONCE(lctx->hint_us);
		}
		if (fh == 0)
			fh = flow_task_hint(p);
		fdl = flow_fallback_deadline(now, fh);
		flow_machine_insert(p, fdl);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	tctx = flow_get(p);
	/* Tasks without state join a tier queue with a fallback deadline */
	/* as the fair time plus an idle kick. The kick targets one idle */
	/* allowed CPU with no preempt, so a waiting task wakes without a */
	/* storm. The gate already passed, so this path holds no gate count */
	/* with no double count. Missing state is rare, so it stays unlikely. */
	if (unlikely(!tctx)) {
		s32 mc = flow_pick_target(p, sel);
		u32 mh = flow_task_hint(p);
		u64 mdl = flow_fallback_deadline(now, mh);
		if (flow_cpu_ok(p, mc))
			flow_tier_insert(p, mc, mdl, mdl, now);
		else
			flow_machine_insert(p, mdl);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	/* Ensure the fairness fields hold sane defaults with no divide. */
	/* A zero weight means no history, so the neutral share applies. */
	/* A zero slice means no history, so the fixed quantum applies. */
	{
		u32 w = READ_ONCE(tctx->weight);
		u32 s = READ_ONCE(tctx->slice_ns);
		if (w == 0)
			__sync_lock_test_and_set(&tctx->weight,
			    (u32)FLOW_WEIGHT_BASE);
		if (s == 0)
			__sync_lock_test_and_set(&tctx->slice_ns,
			    (u32)FLOW_QUANTUM_NS);
	}
	/* Pinned tasks wait in a tier queue with wait set and one idle kick. */
	/* Pinning is rare, so it stays unlikely. The tier keeps mask wins */
	/* on drain, so a pinned task still meets only its allowed CPU. */
	/* Queue order uses the fair time of deadline plus virtual deadline. */
	/* Weight copies uniformly with no cgroup special case. */
	if (unlikely(pinned)) {
		s32 pc = flow_pick_target(p, sel);
		u32 ph;
		u64 pdl;
		u64 pvr;
		u32 pw;
		u32 ps;
		u64 pvd;
		u64 pvt;
		if (is_reenq) {
			ph = READ_ONCE(tctx->hint_us);
		} else {
			u32 pwgt = (u32)FLOW_WEIGHT_BASE;
			/* One cache plus one row read for both values, so */
			/* the fresh pinned path pays no double lookup. */
			flow_task_hint_weight(p, &ph, &pwgt);
			__sync_lock_test_and_set(&tctx->weight,
			    flow_weight_clamp(pwgt));
		}
		tctx->hint_us = ph;
		pdl = flow_fallback_deadline(now, ph);
		tctx->wait_at = now;
		if (READ_ONCE(tctx->deadline) == 0)
			__sync_lock_test_and_set(&tctx->deadline, pdl);
		pdl = READ_ONCE(tctx->deadline);
		pvr = READ_ONCE(tctx->vruntime);
		pw = READ_ONCE(tctx->weight);
		ps = READ_ONCE(tctx->slice_ns);
		if (pw == 0)
			pw = (u32)FLOW_WEIGHT_BASE;
		if (ps == 0)
			ps = (u32)FLOW_QUANTUM_NS;
		pvd = flow_virt_deadline(pvr, (u64)ps, pw);
		pvt = flow_fair_vtime(pdl, pvd);
		if (flow_cpu_ok(p, pc))
			flow_tier_insert(p, pc, pdl, pvt, now);
		else
			flow_machine_insert(p, pvt);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU waits in the machine tier with an idle kick. */
	/* The fallback deadline carries the fair time with no virtual use. */
	if (!flow_cpu_ok(p, cpu)) {
		u32 nh;
		u64 ndl;
		flow_gate_reject();
		tctx->wait_at = now;
		if (is_reenq)
			nh = READ_ONCE(tctx->hint_us);
		else
			nh = flow_task_hint(p);
		ndl = flow_fallback_deadline(now, nh);
		flow_machine_insert(p, ndl);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (READ_ONCE(tctx->deadline) == 0 && READ_ONCE(tctx->wait_at) == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	/* One predictor period plus one EDF deadline plus one fair time. */
	/* A zero average means no history, so the fresh hint period */
	/* applies with the default when the hint is zero. Later wakeups */
	/* add average plus deviation with saturation, so short bursts earn */
	/* tight deadlines with no table walk. The hint plus the weight */
	/* store with no lag, while the predictor shapes only the deadline */
	/* once history exists. A miss on the last deadline counts before */
	/* the new deadline, so the miss count tracks wall completion past */
	/* deadline. Requeues reuse the cached hint plus weight with no */
	/* cgroup acquire, so slice rotation pays no hierarchy cost. The */
	/* reuse may stay stale across one slice when the share changed, so */
	/* the new values show on the next fresh wakeup with no order break. */
	/* The cache clears on migrate plus exit elsewhere, so reuse stays */
	/* correct. Vruntime clamps within the lag bound of the target */
	/* minimum with a compare and swap, so sleepers gain no more than */
	/* one boost with no storm. Weight copies uniformly for cgroup plus */
	/* root tasks with neutral on miss, so every task earns a clamped */
	/* share with no special case. */
	if (is_reenq) {
		hint = READ_ONCE(tctx->hint_us);
	} else {
		u32 wgt = (u32)FLOW_WEIGHT_BASE;
		/* One cache plus one row read for both values, so the fresh */
		/* path pays no double lookup with no behavior change. */
		flow_task_hint_weight(p, &hint, &wgt);
		__sync_lock_test_and_set(&tctx->weight, flow_weight_clamp(wgt));
	}
	avg = (u64)READ_ONCE(tctx->avg_ns);
	dev = (u64)READ_ONCE(tctx->dev_ns);
	if (avg == 0)
		period = flow_task_period(hint);
	else
		period = flow_pred_period(avg, dev);
	tctx->hint_us = hint;
	/* Clamp vruntime within the lag bound of the target minimum. */
	/* A vruntime more than 2ms behind the minimum folds forward to */
	/* minimum minus 2ms with saturation at zero, so a long sleeper */
	/* wakes only slightly early with no huge boost. The claim uses a */
	/* compare and swap, so a concurrent charge win keeps the winner */
	/* with no regression. */
	{
		u64 min = flow_cpu_min((u32)cpu);
		u64 cur = READ_ONCE(tctx->vruntime);
		u64 bound = (u64)FLOW_VLAG_MAX_NS;
		u64 floor = 0;
		if (min > bound)
			floor = min - bound;
		if (min > bound && cur < floor)
			__sync_val_compare_and_swap(&tctx->vruntime,
			    cur, floor);
	}
	if (READ_ONCE(tctx->deadline) &&
	    flow_missed(READ_ONCE(tctx->deadline), now)) {
		u64 ndl;
		u64 nvr;
		u32 nw;
		u32 ns;
		u64 nvd;
		u64 nvt;
		flow_count_miss(tctx);
		tctx->wait_at = now;
		__sync_lock_test_and_set(&tctx->period, (u32)period);
		ndl = flow_pred_deadline(now, avg, dev, hint);
		__sync_lock_test_and_set(&tctx->deadline, ndl);
		nvr = READ_ONCE(tctx->vruntime);
		nw = READ_ONCE(tctx->weight);
		ns = READ_ONCE(tctx->slice_ns);
		if (nw == 0)
			nw = (u32)FLOW_WEIGHT_BASE;
		if (ns == 0)
			ns = (u32)FLOW_QUANTUM_NS;
		nvd = flow_virt_deadline(nvr, (u64)ns, nw);
		nvt = flow_fair_vtime(ndl, nvd);
		flow_tier_insert(p, cpu, ndl, nvt, now);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	__sync_lock_test_and_set(&tctx->period, (u32)period);
	deadline = flow_pred_deadline(now, avg, dev, hint);
	__sync_lock_test_and_set(&tctx->deadline, deadline);
	tctx->wait_at = now;
	/* Fair time from the virtual deadline plus the EDF deadline. */
	/* Heavy tasks earn a near virtual time while light tasks earn a */
	/* far one with no divide, so the earlier of the two paces order */
	/* with latency still capped by the deadline. */
	{
		u64 vr = READ_ONCE(tctx->vruntime);
		u32 wt = READ_ONCE(tctx->weight);
		u32 sl = READ_ONCE(tctx->slice_ns);
		u64 vd;
		if (wt == 0)
			wt = (u32)FLOW_WEIGHT_BASE;
		if (sl == 0)
			sl = (u32)FLOW_QUANTUM_NS;
		vd = flow_virt_deadline(vr, (u64)sl, wt);
		vtime = flow_fair_vtime(deadline, vd);
	}
	/* Every join counts one admit with no bound and no reject, so the */
	/* counters track joins while tier queues hold misses plus pins. */
	__sync_fetch_and_add(&flow_stats.admits, 1);
	/* Idle direct bypass only when tiers hold no earlier work. An idle */
	/* target takes the task straight to its local queue with one idle */
	/* kick, so wakeups skip the tier plus dispatch hop. The bypass runs */
	/* only when the local plus node plus machine tiers hold no queued */
	/* work or the target still drains before the fair time, so an */
	/* earlier fair time never waits behind this arrival in a tier */
	/* queue. The deadline plus admit already hold, so order plus */
	/* counters stay correct with no extra wait. The bypass inserts */
	/* straight to local with no tier move count, so admits vs moves */
	/* drift by the bypass count with no loss while dispatch moves still */
	/* count each tier. Eligible arrivals only bypass, so hogs pace */
	/* through tiers with no direct jump. */
	{
		struct flow_cpu_state *dst = flow_cpu((u32)cpu);
		if (dst && READ_ONCE(dst->running_pid) == 0) {
			u64 own = flow_local_dsq((u32)cpu);
			u32 node = flow_cpu_node((u32)cpu);
			bool node_valid = false;
			u64 node_dsq = 0;
			bool tiers_empty = false;
			u64 bmin;
			if (node < (u32)FLOW_MAX_NODES &&
			    (u64)node < nr_node_ids) {
				node_dsq = flow_node_dsq(node);
				node_valid = true;
			}
			if (scx_bpf_dsq_nr_queued(own) <= 0 &&
			    scx_bpf_dsq_nr_queued(
			        flow_machine_dsq()) <= 0 &&
			    (!node_valid ||
			     scx_bpf_dsq_nr_queued(node_dsq) <= 0))
				tiers_empty = true;
			bmin = READ_ONCE(dst->min_vruntime);
			if ((tiers_empty ||
			    flow_cpu_meets_fair((u32)cpu, vtime, now)) &&
			    flow_eligible(READ_ONCE(tctx->vruntime), bmin,
			        READ_ONCE(tctx->vlag))) {
				scx_bpf_dsq_insert(p,
				    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
				    (u64)FLOW_QUANTUM_NS, enq_flags);
				scx_bpf_test_and_clear_cpu_idle(cpu);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				__sync_fetch_and_add(&flow_stats.kicks, 1);
				return;
			}
		}
	}
	/* Tier join through the shared insert with fair order. */
	/* The local queue takes the task when the target drains before */
	/* the deadline, else the node queue when live, else the machine */
	/* queue, so no task waits for a busy CPU while shared room stays */
	/* open. Queue order uses the fair time while placement tests the */
	/* deadline, so the slowest sufficient CPU still wins. */
	flow_tier_insert(p, cpu, deadline, vtime, now);
	/* Idle targets kick at once with no rate window. */
	/* The idle flag clears first so the kick sticks. The pid read */
	/* uses a relaxed load to match the running stores. The direct */
	/* block holds both the idle plus the preempt kick with the idle */
	/* direct bypass as its mate, so all four points keep one kick per */
	/* wait with no storm. Requeues skip the occupant lookup with no */
	/* task_from_pid cost, so slice rotation paces at expiry with no */
	/* extra kick. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 occ_pid;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		u64 occ_deadline;
		u64 margin;
		u64 occ_start;
		u64 occ_end;
		u64 tail;
		u64 avr;
		s32 avlag;
		u64 cmin;
		if (!st)
			return;
		/* Idle kicks gate on eligibility as well, so hogs pace */
		/* through tiers with no idle jump while lagging tasks still */
		/* wake at once. The gate stays with one minimum read per */
		/* wait, and the ineligible corner paces in tiers with no */
		/* kick and no storm. */
		avr = READ_ONCE(tctx->vruntime);
		avlag = READ_ONCE(tctx->vlag);
		cmin = flow_cpu_min((u32)cpu);
		if (!flow_eligible(avr, cmin, avlag))
			return;
		if (READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* Requeues pace at slice expiry with no occupant preempt, */
		/* so the task_from_pid plus cgroup plus 8 peer cost stays */
		/* out of the hot rotation path. */
		if (is_reenq)
			return;
		/* The running pid names the occupant with no curr read. */
		/* A trusted lookup carries the occupant deadline, and a */
		/* missing occupant fails closed with no kick and no count. */
		/* The occupant CPU validates before the compare, so a */
		/* migrated occupant never kicks the wrong CPU. A zero */
		/* occupant deadline means no order yet, so the arrival */
		/* paces with no kick. */
		occ_pid = READ_ONCE(st->running_pid);
		if (occ_pid == 0 || occ_pid == (u32)p->pid)
			return;
		bpf_rcu_read_lock();
		trusted = bpf_task_from_pid(occ_pid);
		if (!trusted) {
			bpf_rcu_read_unlock();
			return;
		}
		if (scx_bpf_task_cpu(trusted) != cpu) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		octx = flow_lookup(trusted);
		if (!octx) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		occ_deadline = READ_ONCE(octx->deadline);
		occ_start = READ_ONCE(octx->run_at);
		if (occ_deadline == 0) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		/* An urgent arrival leads by 100us with more than 100us left */
		/* on the owner, so near ties plus nearly done owners never */
		/* bounce. The margin adds 100us to the arrival with */
		/* saturation, and the tail needs more than 100us left on the */
		/* owner with wrap safe order, so only a truly earlier arrival */
		/* with work left preempts at once with one kick per wait. */
		/* Equal or later arrivals pace at slice expiry with no count. */
		/* The fair time leads here, so fairness plus urgency gate */
		/* the kick. */
		if (!flow_time_before(vtime, occ_deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		margin = flow_sat_add(vtime,
		    (u64)FLOW_PREEMPT_MARGIN_NS);
		if (margin == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (!flow_time_before(margin, occ_deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (occ_start == 0) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		occ_end = flow_sat_add(occ_start,
		    (u64)FLOW_QUANTUM_NS);
		if (occ_end == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		tail = flow_sat_add(now,
		    (u64)FLOW_PREEMPT_TAIL_NS);
		if (tail == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (!flow_time_before(tail, occ_end)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	}
}
