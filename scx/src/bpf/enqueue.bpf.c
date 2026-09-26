// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Arrivals map to real enqueue flags. WAKEUP marks a sleep wake with a
 * probation tick and a PI correlate. REENQ marks slice exhaust with no
 * tick. LAST keeps the local target with no redirect. PREEMPT marks
 * urgency and joins the fast lane only when duty and probation allow.
 * HEAD and IMMED mark kernel urgency and take the fast head when the
 * lane allows, else the earliest deadline. Stopping with runnable set
 * means preempted or exhausted, and without it means voluntary sleep.
 * Only SCHED_OTHER tasks may use the fast lane. Pinned tasks and foreign
 * policies rest in overflow. See intf.h for the shared helpers and
 * dispatch.bpf.c for the matching drain order.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one task cannot move to another CPU. */
static __always_inline bool flow_task_pinned(
	const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
/* Target CPU for one enqueue with trust in select. */
/* Pinned tasks keep the task CPU when allowed, else select, else first. */
/* Open tasks keep select when allowed, else the first allowed CPU. */
static __always_inline s32 flow_pick_target(
	struct task_struct *p, s32 sel, bool pinned)
{
	s32 first;
	if (pinned) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, sel))
			return sel;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		return -1;
	}
	if (sel >= 0 && flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
/* Insert one task into the fast FIFO with head choice. */
/* Elevated owners and kernel urgency take head, the rest take tail. */
static __always_inline void flow_fast_insert(
	struct task_struct *p, s32 cpu, u64 slice, bool head)
{
	u64 hflag = head ? (u64)SCX_ENQ_HEAD : 0;
	scx_bpf_dsq_insert(p, flow_fast_dsq((u32)cpu), slice,
	    hflag);
	__sync_fetch_and_add(&flow_stats.fast_admits, 1);
}
/* Insert one task into the deadline queue with a clamped deadline. */
/* The compat wrapper keeps 7.2 kernels working with no new kfunc. */
static __always_inline void flow_vtime_insert(
	struct task_struct *p, s32 cpu, u64 slice, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_vtime_dsq((u32)cpu),
	    slice, deadline, 0);
	__sync_fetch_and_add(&flow_stats.vtime_admits, 1);
}
/* Insert one task into the shared overflow tail. */
/* Pinned and foreign tasks rest here with mask wins on drain. */
static __always_inline void flow_over_insert(
	struct task_struct *p, u64 slice)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(), slice, 0);
}
/* Insert one homeless task into the kernel global queue. */
/* Tasks without state or without a live CPU rest here with */
/* mask wins on drain, and the drain counts the global moves. */
static __always_inline void flow_global_insert(
	struct task_struct *p, u64 slice)
{
	scx_bpf_dsq_insert(p, (u64)SCX_DSQ_GLOBAL, slice, 0);
}
/* Correlate one wakeup with the waiter record for PI. */
/* A short block means the waker likely held a lock while the occupant */
/* ran, so the occupant earns one 500us override with a single boost. */
/* No owner kfunc exists, so the running CPU occupant is the proxy. */
/* The occupant pointer may be untrusted on old kernels, so class and */
/* flag writes go through a trusted lookup with release on both paths. */
static __always_inline void flow_pi_correlate(s32 cpu,
	struct task_struct *p, u64 now)
{
	struct flow_pi_wait *pw;
	struct task_struct *owner;
	struct task_struct *trusted;
	struct flow_task_ctx *octx;
	u32 owner_pid;
	bool boosted = false;
	if (cpu < 0 || !flow_cpu_live((u32)cpu))
		return;
	pw = flow_pi((u32)cpu);
	if (!pw || pw->pid == 0 || pw->pid != (u32)p->pid)
		return;
	if (now < pw->at || now - pw->at > (u64)FLOW_PI_WINDOW_NS)
		return;
	pw->pid = 0;
	pw->at = 0;
	owner = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!owner || owner == p)
		return;
	owner_pid = owner->pid;
	bpf_rcu_read_lock();
	trusted = bpf_task_from_pid(owner_pid);
	if (trusted) {
		if (trusted != p) {
			octx = flow_lookup(trusted);
			if (octx && !octx->elevated) {
				octx->elevated = 1;
				octx->elev_at = (u32)now;
				scx_bpf_task_set_slice(trusted,
				    (u64)FLOW_PI_SLICE_NS);
				boosted = true;
			}
		}
		bpf_task_release(trusted);
	}
	bpf_rcu_read_unlock();
	if (!boosted)
		return;
	__sync_fetch_and_add(&flow_stats.elev_moves, 1);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_topo *tp;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	int policy;
	u32 w;
	u8 duty;
	u32 cls;
	u64 now;
	u64 slice;
	bool wakeup;
	bool urgent;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		u64 eslice = (u64)FLOW_QMIN_NS;
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			tctx = flow_lookup(p);
			if (tctx && tctx->slice_ns != 0)
				eslice = tctx->slice_ns;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    eslice, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst && tst->running_pid == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	/* Requeues count once at stopping for runnable stops. */
	/* The flag needs no second count here on the hot path. */
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	policy = p->policy;
	now = flow_now();
	/* Tasks without state keep the kernel global queue with no kick. */
	/* The next dispatch pass collects them with mask wins. */
	if (!tctx) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_global_insert(p, (u64)FLOW_QMIN_NS);
		return;
	}
	w = flow_weight_clamp(p->scx.weight);
	duty = tctx->duty;
	cls = flow_class_of(policy, duty);
	tctx->cls = (u8)cls;
	wakeup = (enq_flags & SCX_ENQ_WAKEUP) != 0;
	urgent = (enq_flags & ((u64)SCX_ENQ_HEAD |
	    (u64)SCX_ENQ_IMMED)) != 0;
	/* Probation spends one wake per low duty sleep wake cycle. */
	/* Two cycles under 15 percent graduate the task to the lane. */
	if (flow_prob_count(tctx->prob) != 0 && wakeup &&
	    flow_prob_vol(tctx->prob) &&
	    duty < (u8)FLOW_DUTY_FAST) {
		tctx->prob = flow_prob_make(
		    flow_prob_count(tctx->prob) - 1U, true);
	}
	/* Expired elevations demote here with no second boost. */
	if (tctx->elevated &&
	    (u32)now - tctx->elev_at > (u32)FLOW_PI_SLICE_NS)
		tctx->elevated = 0;
	/* Pinned, foreign, and non normal tasks rest in overflow. */
	/* Only SCHED_OTHER enters the lanes, idle and batch join the */
	/* deadline queue, and realtime stays ordered with no fast use. */
	if (pinned || (policy != (int)FLOW_POL_NORMAL &&
	    policy != (int)FLOW_POL_BATCH &&
	    policy != (int)FLOW_POL_IDLE)) {
		cpu = flow_pick_target(p, sel, pinned);
		flow_over_insert(p, flow_dyn_slice(w, 1ULL));
		return;
	}
	cpu = flow_pick_target(p, sel, false);
	if (!flow_cpu_ok(p, cpu)) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_global_insert(p, flow_dyn_slice(w, 1ULL));
		return;
	}
	if (tctx->vruntime == 0 && tctx->run_at == 0 &&
	    tctx->wait_at == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	/* The waiter wakes here, so the occupant proxy earns one boost. */
	if (wakeup)
		flow_pi_correlate(cpu, p, now);
	/* Elevated owners take the fast head with a 500us slice. */
	/* One boost per owner ends at release or expiry with no rearm. */
	if (tctx->elevated) {
		tctx->slice_ns = (u32)FLOW_PI_SLICE_NS;
		tctx->wait_at = now;
		flow_fast_insert(p, cpu, (u64)FLOW_PI_SLICE_NS,
		    true);
		goto kicked;
	}
	/* Fast lane needs a normal task past probation with low duty. */
	/* A voluntary wake also opens it, and kernel urgency takes head. */
	/* Idle and batch policies never enter, whatever the duty reads. */
	/* A preempt flagged arrival under half duty also opens it. */
	/* The check runs before any sizing, so a closed lane pays no */
	/* probe and no divide on the wakeup path. */
	bool fast_ok = flow_fast_lane_ok(policy) &&
	    flow_prob_count(tctx->prob) == 0 &&
	    (duty < (u8)FLOW_DUTY_FAST ||
	    (wakeup && flow_prob_vol(tctx->prob)) ||
	    ((enq_flags & (u64)SCX_ENQ_PREEMPT) != 0 &&
	    duty < (u8)FLOW_DUTY_BATCH));
	/* Fast arrivals size from the fast depth only with one probe. */
	/* One divide serves the insert, and no deadline forms here, */
	/* so the lag cap divide stays off the fast path. */
	if (fast_ok) {
		s32 depth = scx_bpf_dsq_nr_queued(
		    flow_fast_dsq((u32)cpu));
		if (depth < (s32)FLOW_FAST_D) {
			u64 queued = 1ULL;
			if (depth > 0)
				queued += (u64)depth;
			slice = flow_dyn_slice(w, queued);
			tctx->slice_ns = (u32)slice;
			tctx->wait_at = now;
			tp = flow_topo((u32)cpu);
			if (tp)
				tp->last_slice = slice;
			flow_fast_insert(p, cpu, slice, urgent);
			goto kicked;
		}
		__sync_fetch_and_add(&flow_stats.fast_bounds, 1);
	} else {
		if (flow_prob_count(tctx->prob) != 0)
			__sync_fetch_and_add(
			    &flow_stats.prob_holds, 1);
		else
			__sync_fetch_and_add(
			    &flow_stats.duty_gates, 1);
	}
	/* Steady tasks size from the deadline depth only with one probe. */
	/* Fresh tasks anchor at minimum minus lag cap with wrap safety. */
	{
		s32 qv = scx_bpf_dsq_nr_queued(
		    flow_vtime_dsq((u32)cpu));
		struct flow_cpu_state *mst = flow_cpu((u32)cpu);
		u64 min_v = mst ? mst->min_vruntime : 0;
		u64 queued = 1ULL;
		u64 deadline;
		if (qv > 0)
			queued += (u64)qv;
		slice = flow_dyn_slice(w, queued);
		tctx->slice_ns = (u32)slice;
		tctx->wait_at = now;
		tp = flow_topo((u32)cpu);
		if (tp)
			tp->last_slice = slice;
		deadline = flow_clamp_entry(tctx->vruntime,
		    min_v, flow_lag_cap(w));
		flow_vtime_insert(p, cpu, slice, deadline);
	}
kicked:
	/* Idle targets kick at once with no rate window. */
	/* The idle flag clears first so the kick sticks. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		struct task_struct *occupant;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		u64 last;
		u32 occ_pid;
		u32 occ_cls;
		u64 occ_vt;
		u64 occ_ran;
		u64 occ_slice;
		if (!st)
			return;
		if (st->running_pid == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* Pinned arrivals never preempt a busy CPU. */
		if (pinned) {
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		/* One prompt kick per 2ms window per CPU. */
		/* The window gates before any occupant lookup, so a hot */
		/* window skips the task lookup plus the RCU pass on the */
		/* wakeup path. The stamp still lands only on a real kick */
		/* below. Entry time serves the window with no fresh read. */
		last = flow_rate_at[(u32)cpu & 1023U];
		if (last != 0 && now - last < (u64)FLOW_PREEMPT_RATE_NS) {
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		/* Use the compat helper, it falls back to cpu_rq on old kernels. */
		/* The occupant may be untrusted there, so the class read */
		/* goes through one trusted lookup with release on each path. */
		/* The same lookup serves the slice shorten below, so the */
		/* busy path pays one task lookup plus one RCU pass. */
		occupant = __COMPAT_scx_bpf_cpu_curr(cpu);
		if (!occupant || occupant == p) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(
			    &flow_stats.preempt_kicks, 1);
			return;
		}
		occ_pid = occupant->pid;
		bpf_rcu_read_lock();
		trusted = bpf_task_from_pid(occ_pid);
		if (!trusted) {
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		octx = flow_lookup(trusted);
		if (!octx) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		occ_cls = octx->cls;
		occ_vt = octx->vruntime;
		occ_slice = octx->slice_ns;
		occ_ran = 0;
		if (octx->on_cpu && octx->run_at != 0 &&
		    now >= octx->run_at)
			occ_ran = now - octx->run_at;
		/* The copy above is trusted with no re-read. */
		/* The reference stays held, so the shorten below reuses */
		/* it with no second lookup and no second RCU pass. */
		if (occ_cls != (u32)FLOW_CLS_INTERACTIVE &&
		    occ_cls != (u32)FLOW_CLS_BATCH)
			occ_cls = (u32)FLOW_CLS_BATCH;
		/* Batch never preempts an interactive occupant. */
		if (cls == (u32)FLOW_CLS_BATCH &&
		    occ_cls == (u32)FLOW_CLS_INTERACTIVE) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		/* Interactive pairs yield at the micro quantum end. */
		if (cls == (u32)FLOW_CLS_INTERACTIVE &&
		    occ_cls == (u32)FLOW_CLS_INTERACTIVE) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			__sync_fetch_and_add(
			    &flow_stats.preempt_skipped, 1);
			return;
		}
		/* Batch pairs need an exhausted slice plus a deadline gap */
		/* past one micro quantum before a prompt kick may run. */
		if (cls == (u32)FLOW_CLS_BATCH) {
			if (occ_slice == 0 || occ_ran < occ_slice) {
				bpf_task_release(trusted);
				bpf_rcu_read_unlock();
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped, 1);
				return;
			}
			if (!flow_time_before(tctx->vruntime +
			    (u64)FLOW_MICRO_QUANTUM_NS,
			    occ_vt)) {
				bpf_task_release(trusted);
				bpf_rcu_read_unlock();
				__sync_fetch_and_add(
				    &flow_stats.preempt_skipped, 1);
				return;
			}
		}
		/* Interactive over batch shortens to the 100us floor. */
		/* Batch over batch shortens to zero at slice end. */
		/* The slice write uses the held trusted reference. */
		/* No timer kick runs here, so the floor is an */
		/* approximation with kick timing, not a precise preempt. */
		if (cls == (u32)FLOW_CLS_INTERACTIVE)
			scx_bpf_task_set_slice(trusted,
			    (u64)FLOW_PREEMPT_FLOOR_NS);
		else
			scx_bpf_task_set_slice(trusted, 0);
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		flow_rate_at[(u32)cpu & 1023U] = now;
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&flow_stats.preempt_kicks, 1);
	}
}
