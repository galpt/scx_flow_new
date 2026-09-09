/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Routing and insert, included by main.bpf.c via
 * include.
 *
 * Fresh tasks join with the current mean. Known tasks
 * requeue with a clamped estimate. Tasks with no
 * target wait in the park queue. Inserts use ordered
 * time with the deadline as the key and the mean as
 * the slice. The deadline adds clamped virtual time
 * and scaled estimate with a sleeper cap of one
 * slice. Kicks wake idle targets only.
 */

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 sel;
	s32 cpu = -1;
	bool cpu_valid = false;
	bool is_requeue = false;
	bool is_fresh = false;
	bool need_join = false;
	u64 est = 0;
	u64 tq = (u64)FLOW_TQ_SEED_NS;

	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	if (!tctx) {
		u64 seed = (u64)FLOW_TQ_SEED_NS;
		u64 frontier = 0;
		u64 clamped;
		u64 scaled;
		u64 dl;
		s32 ref_cpu = sel;

		/* Reference frontier keeps the deadline fair. */
		/* Park has no target, so the selected or first */
		/* allowed CPU gives the frontier with no stale */
		/* zero use when a reference exists. */
		if (!flow_cpu_ok(p, ref_cpu)) {
			s32 first;

			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first))
				ref_cpu = first;
			else
				ref_cpu = -1;
		}
		if (ref_cpu >= 0) {
			struct flow_cpu_state *rst;

			rst = flow_cpu((u32)ref_cpu);
			if (rst)
				frontier = rst->frontier;
		}
		clamped = flow_clamp_vruntime(0, frontier,
		    seed);
		scaled = flow_scale_by_weight(
		    flow_clamp_est(seed),
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != 0)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		scx_bpf_dsq_insert_vtime(p, (u64)FLOW_DSQ_PARK,
		    seed, dl, 0);
		return;
	}
	if (tctx->est_ns == 0)
		is_fresh = true;
	if (tctx->grant_ns == (u64)-1)
		need_join = true;
	/* Tasks that cannot move stay on the current CPU. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here)) {
			cpu = here;
			cpu_valid = true;
		}
	}
	if (!cpu_valid) {
		if (flow_cpu_ok(p, sel)) {
			cpu = sel;
			cpu_valid = true;
		} else {
			s32 first;

			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first)) {
				cpu = first;
				cpu_valid = true;
			}
		}
	}
	if (!cpu_valid) {
		u64 seed = (u64)FLOW_TQ_SEED_NS;
		u64 frontier = 0;
		u64 v;
		u64 clamped;
		u64 scaled;
		u64 dl;
		s32 ref_cpu = sel;

		/* No target, park with clamped deadline. */
		/* Reference frontier keeps the deadline fair. */
		/* Park keeps vruntime with no writeback. */
		tq = seed;
		if (is_fresh)
			est = tq;
		else
			est = flow_clamp_est(tctx->est_ns);
		/* Owner change leaves old mean with no leak. */
		/* Blocked wake counts as requeue to match */
		/* the normal path with no diverge. */
		if (!need_join &&
		    tctx->owner != FLOW_OWNER_NONE)
			flow_leave_cpu(tctx->owner,
			    flow_clamp_est(tctx->est_ns));
		tctx->est_ns = est;
		if (is_fresh) {
			tctx->vruntime = 0;
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		} else if (is_requeue || need_join) {
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		}
		v = tctx->vruntime;
		if (!flow_cpu_ok(p, ref_cpu)) {
			s32 first;

			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first))
				ref_cpu = first;
			else
				ref_cpu = -1;
		}
		if (ref_cpu >= 0) {
			struct flow_cpu_state *rst;

			rst = flow_cpu((u32)ref_cpu);
			if (rst)
				frontier = rst->frontier;
		}
		clamped = flow_clamp_vruntime(v, frontier,
		    seed);
		scaled = flow_scale_by_weight(est,
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		tctx->deadline = dl;
		tctx->grant_ns = tq;
		tctx->owner = FLOW_OWNER_NONE;
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != v)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		scx_bpf_dsq_insert_vtime(p, (u64)FLOW_DSQ_PARK,
		    tq, dl, 0);
		return;
	}
	st = flow_cpu((u32)cpu);
	tq = st ? st->tq_ns : (u64)FLOW_TQ_SEED_NS;
	/* Zero guard stays for empty map reads with */
	/* no behavior change in the normal path. */
	if (tq == 0)
		tq = (u64)FLOW_TQ_SEED_NS;
	/* Fair overload shed keeps order in park. */
	/* The deadline still uses the target frontier */
	/* with owner none and no kill and no Pi use. */
	/* The window holds one batch, so only excess */
	/* sheds while the owner stays fair. */
	if ((u64)FLOW_GATE_IEDF &&
	    scx_bpf_dsq_nr_queued(flow_dsq_for_cpu((u32)cpu)) >=
	    (u64)FLOW_DISPATCH_MAX_BATCH) {
		u64 shed_frontier = 0;
		u64 shed_slice = tq;
		u64 shed_v;
		u64 shed_clamped;
		u64 shed_scaled;
		u64 shed_dl;
		struct flow_cpu_state *shed_st;

		if (is_fresh)
			est = tq;
		else
			est = flow_clamp_est(tctx->est_ns);
		/* Fresh tasks start at zero with no stale time. */
		/* Owner change leaves old mean with no leak. */
		/* Blocked wake counts as requeue to match */
		/* the normal path with no diverge. */
		if (is_fresh)
			tctx->vruntime = 0;
		if (!need_join &&
		    tctx->owner != FLOW_OWNER_NONE)
			flow_leave_cpu(tctx->owner,
			    flow_clamp_est(tctx->est_ns));
		tctx->est_ns = est;
		if (is_fresh)
			__sync_fetch_and_add(&flow_stats.inserts, 1);
		else if (is_requeue || need_join)
			__sync_fetch_and_add(&flow_stats.requeues, 1);
		shed_v = tctx->vruntime;
		shed_st = flow_cpu((u32)cpu);
		if (shed_st)
			shed_frontier = shed_st->frontier;
		/* Zero guard stays for empty map reads with */
		/* no behavior change in the normal path. */
		if (shed_slice == 0)
			shed_slice = (u64)FLOW_TQ_SEED_NS;
		shed_clamped = flow_clamp_vruntime(shed_v,
		    shed_frontier, shed_slice);
		shed_scaled = flow_scale_by_weight(est,
		    (u32)FLOW_WEIGHT);
		shed_dl = flow_deadline(shed_clamped,
		    shed_scaled);
		tctx->deadline = shed_dl;
		tctx->grant_ns = tq;
		tctx->owner = FLOW_OWNER_NONE;
		__sync_fetch_and_add(&flow_stats.edf_enqueued, 1);
		if (shed_clamped != shed_v)
			__sync_fetch_and_add(&flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered, 1);
		scx_bpf_dsq_insert_vtime(p, (u64)FLOW_DSQ_PARK,
		    tq, shed_dl, 0);
		return;
	}
	if (is_fresh)
		est = tq;
	else
		est = flow_clamp_est(tctx->est_ns);
	{
		u32 old_owner = tctx->owner;
		u64 old_est = tctx->est_ns;

		if (need_join) {
			flow_join_cpu((u32)cpu, est);
			tctx->owner = (u32)cpu;
			if (is_fresh)
				__sync_fetch_and_add(&flow_stats.inserts,
				    1);
			else
				__sync_fetch_and_add(&flow_stats.requeues,
				    1);
			st = flow_cpu((u32)cpu);
			tq = st ? st->tq_ns : tq;
			/* Zero guard stays for empty map reads with */
			/* no behavior change in the normal path. */
			if (tq == 0)
				tq = (u64)FLOW_TQ_SEED_NS;
		} else {
			/* Migrate accounting when owner changes. */
			/* Leave old mean and join new mean, so */
			/* migration never leaks with no bound. */
			if (old_owner != FLOW_OWNER_NONE &&
			    old_owner != (u32)cpu) {
				flow_leave_cpu(old_owner,
				    flow_clamp_est(old_est));
				flow_join_cpu((u32)cpu, est);
			}
			tctx->owner = (u32)cpu;
			if (is_requeue)
				__sync_fetch_and_add(&flow_stats.requeues,
				    1);
		}
		tctx->est_ns = est;
	}
	tctx->grant_ns = tq;
	/* Ordered queue keeps deadlines first. */
	/* Kicks run only when the queue was empty. */
	{
		u64 frontier = 0;
		u64 slice = tq;
		u64 v = tctx->vruntime;
		u64 clamped;
		u64 scaled;
		u64 dl;
		u64 dsq;

		st = flow_cpu((u32)cpu);
		if (st)
			frontier = st->frontier;
		/* Zero guard stays for empty map reads with */
		/* no behavior change in the normal path. */
		if (slice == 0)
			slice = (u64)FLOW_TQ_SEED_NS;
		clamped = flow_clamp_vruntime(v, frontier,
		    slice);
		scaled = flow_scale_by_weight(est,
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		tctx->vruntime = clamped;
		tctx->deadline = dl;
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != v)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		dsq = flow_dsq_for_cpu((u32)cpu);
		scx_bpf_dsq_insert_vtime(p, dsq, tq, dl, 0);
		if ((u64)FLOW_GATE_CUTS &&
		    scx_bpf_dsq_nr_queued(dsq) > 1)
			return;
		if (flow_cpu_ok(p, cpu)) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
