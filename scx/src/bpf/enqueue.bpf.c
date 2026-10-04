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
 * with one divide, and the CPU minimum folds forward on every charge,
 * so fairness tracks service with no table. Every tier join counts one
 * admit with no reject, so the counters track joins with no bound. The
 * exiting plus idle direct plus helper plus direct block form the four
 * kick points, so every wait meets at most one kick with no storm. A
 * direct preempt needs an eligible arrival plus a 100us margin lead
 * with more than 100us still left on the owner, so near ties plus
 * nearly done owners never bounce while one kick per wait stays.
 * Slice expiry paces the rest, so no slice write and no stamp run
 * here. Local plus node depths hoist once, so the drain gated bypass
 * plus the combined drain tier escalation share one read with no second
 * poll. See intf.h for the deadline plus fairness helpers and
 * dispatch.bpf.c for the tier scans.
 *
 * The op holds the target plus insert plus kick helpers inline here
 * with the kick noinline on scalar input, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Target plus insert helpers for the enqueue pass. */
static __always_inline bool flow_task_pinned(const struct task_struct *p)
{
	if (is_migration_disabled(p))
		return true;
	if (p->nr_cpus_allowed == 1)
		return true;
	return false;
}
static __always_inline s32 flow_pick_target(struct task_struct *p, s32 sel)
{
	s32 first;
	if (sel >= 0 && flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
static __always_inline void flow_local_insert(struct task_struct *p, s32 cpu, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_local_dsq((u32)cpu), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
static __always_inline void flow_node_insert(struct task_struct *p, u32 node, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_node_dsq(node), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
static __always_inline void flow_machine_insert(struct task_struct *p, u64 vtime)
{
	scx_bpf_dsq_insert_vtime(p, flow_machine_dsq(), (u64)FLOW_QUANTUM_NS, vtime, 0);
}
static __always_inline void flow_overflow_insert(struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(), (u64)FLOW_QUANTUM_NS, enq_flags);
}
/**
 * flow_tier_insert_hint - tier join from hoisted combined drain.
 * @p: task to join, null is ignored by the insert helpers.
 * @cpu: target CPU for the drain gate.
 * @vtime: fair time used for order plus the drain gate.
 * @now: current time in nanos.
 * @local_q: hoisted own local depth, non-positive means empty.
 * @node_q: hoisted node depth, non-positive means empty.
 *
 * Takes the local tier when the hoisted combined drain finishes before
 * the fair time, else the node tier when live, else the machine tier, so
 * a busy node holds local with no wait and no second poll. Escalation
 * follows the combined drain with mask wins on dispatch drain.
 */
static __always_inline void flow_tier_insert_hint(struct task_struct *p,
	s32 cpu, u64 vtime, u64 now, s32 local_q, s32 node_q)
{
	u32 node;
	if (cpu >= 0 &&
	    flow_cpu_meets_fair_hint(local_q, node_q, vtime, now)) {
		flow_local_insert(p, cpu, vtime);
		return;
	}
	if (cpu >= 0) {
		node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES && (u64)node < nr_node_ids) {
			flow_node_insert(p, node, vtime);
			return;
		}
	}
	flow_machine_insert(p, vtime);
}
static __always_inline void flow_tier_insert(struct task_struct *p, s32 cpu, u64 vtime, u64 now)
{
	s32 local_q = 0;
	s32 node_q = 0;
	if (cpu >= 0) {
		u32 node;
		local_q = scx_bpf_dsq_nr_queued(flow_local_dsq((u32)cpu));
		node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES && (u64)node < nr_node_ids)
			node_q = scx_bpf_dsq_nr_queued(flow_node_dsq(node));
	}
	flow_tier_insert_hint(p, cpu, vtime, now, local_q, node_q);
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	u64 now;
	u64 deadline;
	u64 vtime;
	u32 hint;
	u32 hint_w = (u32)FLOW_WEIGHT_BASE;
	u32 task_w = (u32)FLOW_WEIGHT_BASE;
	u32 eff_w = (u32)FLOW_WEIGHT_BASE;
	u64 avg = 0;
	u64 dev = 0;
	bool is_reenq = false;
	u64 hoist_vr = 0;
	s32 hoist_lag = 0;
	u64 hoist_min = 0;
	bool hoist_elig = false;
	/* Requeue plus last slice expiry bypass the cgroup hint read plus */
	/* the occupant preempt lookup, so slice rotation stays cheap. The */
	/* stored hint plus hint weight in the task state carry the period */
	/* plus the share, and the owner paces at slice expiry with no */
	/* extra kick. The requeue case is rare beside fresh wakeups, so */
	/* it stays unlikely. */
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
				flow_count_kick();
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
	/* rare, so they stay unlikely. Gate misses join the overflow FIFO */
	/* with no deadline wait, so no path needs a tail queue. */
	if (unlikely(!flow_entry_ok(sel, p, 0) && !flow_entry_ok(
	    scx_bpf_task_cpu(p), p, 0))) {
		struct flow_task_ctx *lctx = flow_lookup(p);
		flow_gate_reject();
		if (lctx)
			lctx->wait_at = now;
		flow_overflow_insert(p, enq_flags);
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
			flow_tier_insert(p, mc, mdl, now);
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
	/* The effective share stacks task times hint over 128 with the hint */
	/* weight stored alongside the task base. Vruntime clamps to the */
	/* target minimum minus 2ms like open tasks, and a past deadline */
	/* counts one miss before the fresh deadline, so pins track lag */
	/* plus overload with no stale reuse. */
	if (unlikely(pinned)) {
		s32 pc = flow_pick_target(p, sel);
		u32 ph;
		u32 phint_w = (u32)FLOW_WEIGHT_BASE;
		u64 pavg;
		u64 pdev;
		u64 pdl;
		u64 pvr;
		u32 ptask_w;
		u32 peff;
		u32 ps;
		u64 pvd;
		u64 pvt;
		if (is_reenq) {
			ph = READ_ONCE(tctx->hint_us);
			phint_w = READ_ONCE(tctx->hint_w);
		} else {
			/* One cache plus one row read for both values, so */
			/* the fresh pinned path pays no double lookup. */
			/* The task base stays stored, only the hint reads. */
			flow_task_hint_weight(p, &ph, &phint_w);
		}
		tctx->hint_us = ph;
		tctx->hint_w = phint_w;
		/* Clamp vruntime within the lag bound of the pinned target. */
		/* Matches the open path, so a long sleeper wakes only slightly */
		/* early with no huge boost. A missing target skips with no poll. */
		if (pc >= 0 && flow_cpu_ok(p, pc)) {
			u64 pmin = flow_cpu_min((u32)pc);
			u64 pcur = READ_ONCE(tctx->vruntime);
			u64 pbound = (u64)FLOW_VLAG_MAX_NS;
			u64 pfloor = 0;
			if (pmin > pbound)
				pfloor = pmin - pbound;
			if (pmin > pbound && pcur < pfloor)
				__sync_val_compare_and_swap(&tctx->vruntime,
				    pcur, pfloor);
		}
		/* A past deadline counts one miss before the fresh deadline, */
		/* so pinned overload tracks like open tasks with no loss. */
		if (READ_ONCE(tctx->deadline) &&
		    flow_missed(READ_ONCE(tctx->deadline), now))
			flow_count_miss(tctx);
		/* Pinned tasks recompute the deadline from the predictor */
		/* plus hint with no stale reuse, so a pinned requeue tracks */
		/* recent bursts like open tasks with no order break. A zero */
		/* average means no history, so the hint period applies. */
		pavg = (u64)READ_ONCE(tctx->avg_ns);
		pdev = (u64)READ_ONCE(tctx->dev_ns);
		pdl = flow_pred_deadline(now, pavg, pdev, ph);
		__sync_lock_test_and_set(&tctx->deadline, pdl);
		tctx->wait_at = now;
		pvr = READ_ONCE(tctx->vruntime);
		ptask_w = READ_ONCE(tctx->weight);
		ps = READ_ONCE(tctx->slice_ns);
		if (ptask_w == 0)
			ptask_w = (u32)FLOW_WEIGHT_BASE;
		if (ps == 0)
			ps = (u32)FLOW_QUANTUM_NS;
		peff = flow_task_effective_weight(ptask_w, phint_w);
		pvd = flow_virt_deadline(pvr, (u64)ps, peff);
		pvt = flow_fair_vtime(pdl, pvd);
		if (flow_cpu_ok(p, pc))
			flow_tier_insert(p, pc, pvt, now);
		else
			flow_machine_insert(p, pvt);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU waits in the machine tier with an idle kick. */
	/* The predictor shapes the deadline when history exists else the */
	/* homeless work waits in the overflow FIFO with no fair key, so */
	/* no insert touches the kernel global queue. */
	if (!flow_cpu_ok(p, cpu)) {
		flow_gate_reject();
		tctx->wait_at = now;
		flow_overflow_insert(p, enq_flags);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (READ_ONCE(tctx->deadline) == 0 && READ_ONCE(tctx->wait_at) == 0)
		flow_count_insert();
	/* One predictor period plus one EDF deadline plus one fair time. */
	/* A zero average means no history, so the fresh hint period */
	/* applies with the default when the hint is zero. Later wakeups */
	/* add average plus deviation with saturation, so short bursts earn */
	/* tight deadlines with no table walk. The hint stores with no lag, */
	/* while the predictor shapes only the deadline once history exists. */
	/* A miss on the last deadline counts before the new deadline, so */
	/* the miss count tracks wall completion past deadline. Requeues */
	/* reuse the stored hint plus hint weight with no lookup and no */
	/* cgroup acquire, so slice rotation keeps the heavy share with no */
	/* neutral cliff. The reuse may stay stale across one slice when */
	/* the share changed, so the new values show on the next fresh */
	/* wakeup with no order break. A cgroup move shows the same way */
	/* on the next fresh wakeup with no order break. Vruntime clamps within the lag bound of the target */
	/* minimum with a compare and swap, so sleepers gain no more than */
	/* one boost with no storm. The effective share stacks task times */
	/* hint over 128 on the stack, so every task earns a clamped share */
	/* with no special case and the hint weight stored alongside. */
	if (is_reenq) {
		hint = READ_ONCE(tctx->hint_us);
		hint_w = READ_ONCE(tctx->hint_w);
	} else {
		/* One cache plus one row read for both values, so the fresh */
		/* path pays no double lookup with no behavior change. The */
		/* task base stays stored, only the hint reads here. */
		flow_task_hint_weight(p, &hint, &hint_w);
	}
	avg = (u64)READ_ONCE(tctx->avg_ns);
	dev = (u64)READ_ONCE(tctx->dev_ns);
	tctx->hint_us = hint;
	tctx->hint_w = hint_w;
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
		u32 ntask_w;
		u32 neff;
		u32 ns;
		u64 nvd;
		u64 nvt;
		flow_count_miss(tctx);
		tctx->wait_at = now;
		ndl = flow_pred_deadline(now, avg, dev, hint);
		__sync_lock_test_and_set(&tctx->deadline, ndl);
		nvr = READ_ONCE(tctx->vruntime);
		ntask_w = READ_ONCE(tctx->weight);
		ns = READ_ONCE(tctx->slice_ns);
		if (ntask_w == 0)
			ntask_w = (u32)FLOW_WEIGHT_BASE;
		if (ns == 0)
			ns = (u32)FLOW_QUANTUM_NS;
		neff = flow_task_effective_weight(ntask_w, hint_w);
		nvd = flow_virt_deadline(nvr, (u64)ns, neff);
		nvt = flow_fair_vtime(ndl, nvd);
		flow_tier_insert(p, cpu, nvt, now);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	deadline = flow_pred_deadline(now, avg, dev, hint);
	__sync_lock_test_and_set(&tctx->deadline, deadline);
	tctx->wait_at = now;
	/* Fair time from the virtual deadline plus the EDF deadline. */
	/* Heavy tasks earn a near virtual time while light tasks earn a */
	/* far one with one divide, so the earlier of the two paces order */
	/* with latency still capped by the deadline. The effective share */
	/* stacks task times hint over 128, so cgroup plus task weights */
	/* shape fairness together. */
	{
		u64 vr = READ_ONCE(tctx->vruntime);
		u32 sl = READ_ONCE(tctx->slice_ns);
		u64 vd;
		task_w = READ_ONCE(tctx->weight);
		if (task_w == 0)
			task_w = (u32)FLOW_WEIGHT_BASE;
		eff_w = flow_task_effective_weight(task_w, hint_w);
		if (sl == 0)
			sl = (u32)FLOW_QUANTUM_NS;
		vd = flow_virt_deadline(vr, (u64)sl, eff_w);
		vtime = flow_fair_vtime(deadline, vd);
	}
	/* Every join counts one admit with no bound and no reject, so the */
	/* counters track joins while tier queues hold misses plus pins. */
	flow_count_admit();
	/* Eligibility hoist reads vruntime plus lag plus minimum once per */
	/* wait with no second minimum poll. The bypass plus the kick share */
	/* this one gate, so hogs pace with one minimum read and no storm. */
	/* Dropped polls keep the same order with no behavior change. */
	hoist_vr = READ_ONCE(tctx->vruntime);
	hoist_lag = READ_ONCE(tctx->vlag);
	hoist_min = flow_cpu_min((u32)cpu);
	hoist_elig = flow_eligible(hoist_vr, hoist_min, hoist_lag);
	/* Idle direct bypass only when tiers hold no earlier fair key. An idle */
	/* target takes the task straight to its local queue with one idle kick */
	/* per wait and no preempt, so wakeups skip the tier plus dispatch hop. */
	/* The bypass runs only when the local plus node plus machine tiers hold */
	/* no queued work or the target still drains local plus node before the */
	/* fair time, so an earlier fair time never waits behind this arrival in */
	/* a tier queue. Local plus node depths hoist once here, so the empty */
	/* gate plus the drain gate share the same reads with no second poll. */
	/* The deadline plus admit already hold, so order plus counters stay */
	/* correct with no extra wait. The bypass inserts straight to local */
	/* with no tier move count, so admits vs moves drift by the bypass */
	/* count with no loss while dispatch moves still count each tier. */
	/* Strict fair order gates the bypass with eligibility plus drain, so hogs */
	/* pace through tiers with no direct jump and one kick per wait stays. */
	/* The TOCTOU between the empty hints and the direct insert only */
	/* races a concurrent tier join with no loss, since dispatch still */
	/* drains in fair order with mask wins on the next pass. */
	{
		struct flow_cpu_state *dst = flow_cpu((u32)cpu);
		if (dst && READ_ONCE(dst->running_pid) == 0) {
			u64 own = flow_local_dsq((u32)cpu);
			u32 node = flow_cpu_node((u32)cpu);
			bool node_valid = false;
			u64 node_dsq = 0;
			s32 lq = 0;
			s32 nq = 0;
			s32 mq = 0;
			bool tiers_empty = false;
			bool drain_ok = false;
			if (node < (u32)FLOW_MAX_NODES &&
			    (u64)node < nr_node_ids) {
				node_dsq = flow_node_dsq(node);
				node_valid = true;
			}
			/* Hoist local plus node plus machine once with signed */
			/* hints, so the empty gate plus the drain gate plus the */
			/* tier escalation below share one read with no repoll. */
			lq = scx_bpf_dsq_nr_queued(own);
			mq = scx_bpf_dsq_nr_queued(flow_machine_dsq());
			if (node_valid)
				nq = scx_bpf_dsq_nr_queued(node_dsq);
			if (lq <= 0 && mq <= 0 && (!node_valid || nq <= 0))
				tiers_empty = true;
			/* Drain gate uses the same hoisted combined drain with */
			/* no kfunc, so the bypass tests fair order cheap. */
			drain_ok = flow_cpu_meets_fair_hint(lq, nq, vtime, now);
			if ((tiers_empty || drain_ok) && hoist_elig) {
				scx_bpf_dsq_insert(p,
				    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
				    (u64)FLOW_QUANTUM_NS, enq_flags);
				scx_bpf_test_and_clear_cpu_idle(cpu);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
				flow_count_kick();
				return;
			}
			/* Tier join through the hoisted combined drain escalation */
			/* with no second poll. The local tier takes the task when */
			/* the hoisted drain finishes before the fair key, else the */
			/* node tier when live, else the machine tier, so no task */
			/* waits for a busy CPU while shared room stays open. Queue */
			/* order plus tier choice use the fair time while placement */
			/* tests the deadline, so the slowest sufficient CPU wins. */
			/* Mask wins on dispatch drain with the same order. */
			flow_tier_insert_hint(p, cpu, vtime, now, lq, nq);
			goto kicked;
		}
	}
	/* Tier join through the shared insert with fair order. */
	/* The local queue takes the task when the target drains local plus */
	/* node before the fair key, else the node queue when live, else the */
	/* machine queue, so no task waits for a busy CPU while shared room */
	/* stays open. Queue order plus tier choice use the fair time while */
	/* placement tests the deadline, so the slowest sufficient CPU wins. */
	flow_tier_insert(p, cpu, vtime, now);
kicked:
	/* Idle targets kick at once with strict one kick per wait and no rate */
	/* window. The idle flag clears first so the kick sticks. The pid read */
	/* uses a relaxed load to match the running stores. The direct block */
	/* holds both the idle plus the preempt kick with the idle direct bypass */
	/* as its mate, so all four points keep one kick per wait with no storm. */
	/* Requeues skip the occupant lookup with no task_from_pid cost, so slice */
	/* rotation paces at expiry with no extra kick. Busy preempts count in */
	/* preempt_kicks on success and in preempt_skipped on every hold by strict */
	/* margin plus tail plus eligibility with no missing fill, so the two */
	/* counters track urgency with no extra kick. Strict order uses wrap safe */
	/* time before throughout, so equal arrivals pace with no bounce. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 occ_pid;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		u64 occ_deadline;
		u64 occ_start;
		if (!st)
			return;
		/* Idle kicks gate on the hoisted eligibility, so hogs pace */
		/* through tiers with no idle jump while lagging tasks still */
		/* wake at once. The gate stays with one minimum read per */
		/* wait, and the ineligible corner paces in tiers with no */
		/* kick and one skipped preempt with no storm. */
		if (!hoist_elig) {
			flow_count_preempt_skip();
			return;
		}
		if (READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			flow_count_kick();
			return;
		}
		/* Requeues pace at slice expiry with no occupant preempt, */
		/* so the task_from_pid plus cgroup plus 16 peer cost stays */
		/* out of the hot rotation path. */
		if (is_reenq)
			return;
		/* The running pid names the occupant with no curr read. */
		/* A trusted lookup carries the occupant deadline, and a */
		/* missing occupant fails closed with no kick and no skipped */
		/* count, since no urgency holds to track. The occupant CPU */
		/* validates before the compare, so a migrated occupant never */
		/* kicks the wrong CPU with no count. A zero occupant deadline */
		/* means no order yet, so the arrival paces with no kick and */
		/* no skipped count. Only margin plus tail plus eligibility */
		/* plus fair order holds count as skipped below. */
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
		/* bounce. The shared preempt helper holds the margin plus */
		/* tail with wrap safe order, so only a truly earlier arrival */
		/* with work left preempts at once with one kick per wait. */
		/* Equal or later arrivals pace at slice expiry with one */
		/* skipped preempt. The fair time leads here, so fairness */
		/* plus urgency gate the kick. Eligibility already passed */
		/* above, so the helper checks lead plus tail only. */
		if (!flow_preempt_wants(vtime, occ_deadline, now,
		    occ_start)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			flow_count_preempt_skip();
			return;
		}
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		flow_count_kick();
		flow_count_preempt_kick();
	}
}
