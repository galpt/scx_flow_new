/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
static __always_inline s32 flow_pick_target(
	const struct task_struct *p, s32 sel)
{
	s32 first;
	if (flow_cpu_ok(p, sel))
		return sel;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return -1;
}
static __always_inline u64 flow_ref_frontier(
	const struct task_struct *p, s32 ref_cpu)
{
	struct flow_cpu_state *rst;
	s32 first;
	if (!flow_cpu_ok(p, ref_cpu)) {
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			ref_cpu = first;
		else
			return 0;
	}
	if (ref_cpu < 0)
		return 0;
	rst = flow_cpu((u32)ref_cpu);
	if (rst)
		return rst->frontier;
	return 0;
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 sel;
	s32 cpu = -1;
	bool is_requeue = false;
	bool is_fresh = false;
	u64 est = 0;
	u64 slice = (u64)FLOW_SLICE_NS;
	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	if (!tctx) {
		u64 frontier;
		u64 clamped;
		u64 scaled;
		u64 dl;
		frontier = flow_ref_frontier(p, sel);
		clamped = flow_clamp_vruntime(0, frontier,
		    slice);
		scaled = flow_scale_by_weight(
		    flow_clamp_est(slice),
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
		    slice, dl, 0);
		return;
	}
	if (tctx->est_ns == 0)
		is_fresh = true;
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			cpu = here;
	}
	if (cpu < 0)
		cpu = flow_pick_target(p, sel);
	if (cpu < 0) {
		u64 frontier;
		u64 v;
		u64 clamped;
		u64 scaled;
		u64 dl;
		if (is_fresh)
			est = slice;
		else
			est = flow_clamp_est(tctx->est_ns);
		tctx->est_ns = est;
		if (is_fresh) {
			tctx->vruntime = 0;
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		} else if (is_requeue) {
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		}
		v = tctx->vruntime;
		frontier = flow_ref_frontier(p, sel);
		clamped = flow_clamp_vruntime(v, frontier,
		    slice);
		scaled = flow_scale_by_weight(est,
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		if (dl == (u64)-1)
			dl = (u64)-2;
		tctx->deadline = dl;
		__sync_fetch_and_add(&flow_stats.edf_enqueued,
		    1);
		if (clamped != v)
			__sync_fetch_and_add(
			    &flow_stats.edf_clamped, 1);
		__sync_fetch_and_add(&flow_stats.edf_ordered,
		    1);
		scx_bpf_dsq_insert_vtime(p, (u64)FLOW_DSQ_PARK,
		    slice, dl, 0);
		return;
	}
	if (is_fresh)
		est = slice;
	else
		est = flow_clamp_est(tctx->est_ns);
	tctx->est_ns = est;
	if (is_fresh)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	else if (is_requeue)
		__sync_fetch_and_add(&flow_stats.requeues, 1);
	{
		u64 frontier = 0;
		u64 v = tctx->vruntime;
		u64 clamped;
		u64 scaled;
		u64 dl;
		u64 dsq;
		st = flow_cpu((u32)cpu);
		if (st)
			frontier = st->frontier;
		clamped = flow_clamp_vruntime(v, frontier,
		    slice);
		scaled = flow_scale_by_weight(est,
		    (u32)FLOW_WEIGHT);
		dl = flow_deadline(clamped, scaled);
		if (dl == (u64)-1)
			dl = (u64)-2;
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
		scx_bpf_dsq_insert_vtime(p, dsq, slice, dl, 0);
		if (scx_bpf_dsq_nr_queued(dsq) > 1)
			return;
		if (flow_cpu_ok(p, cpu)) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
