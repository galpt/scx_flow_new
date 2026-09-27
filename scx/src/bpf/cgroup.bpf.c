// SPDX-License-Identifier: GPL-2.0
/*
 * Hierarchy ops.
 *
 * Each hierarchy entry holds the share plus the bandwidth pool,
 * and each task caches its hierarchy share with generation
 * validation. Init runs sleepable with map create, the rest run
 * without sleep with lookup only. Moves carry the deadline with
 * cache invalidate, weight and bandwidth bumps refresh the
 * generation, and the pool refills lazily on the enqueue path
 * with the single timer waking parks. See intf.h for the pool
 * helpers and enqueue.bpf.c for the share use.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Init one hierarchy entry with share plus pool and full refill. */
/* Sleepable only, so map create runs here. Unlimited maps to zero */
/* with full pool at zero and no cap use. The generation bumps once. */
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
	struct scx_cgroup_init_args *args)
{
	u64 id;
	u64 period;
	u64 quota;
	u64 burst;
	u64 max;
	u64 now;
	struct flow_cgrp_ctx e = {};
	struct flow_cgrp_ctx *old;
	bool was_limited = false;
	bool is_limited;
	if (!cgrp || !args)
		return -EINVAL;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return -EINVAL;
	period = flow_bw_period_floor(args->bw_period_us);
	quota = flow_bw_quota_norm(args->bw_quota_us);
	burst = args->bw_burst_us;
	max = flow_bw_max_ns(quota, burst);
	now = flow_now();
	e.weight = flow_weight_clamp(args->weight);
	e.period_us = period;
	e.quota_us = quota;
	e.burst_us = burst;
	if (flow_bw_unlimited(quota)) {
		e.pool_ns = 0;
	} else {
		e.pool_ns = max;
	}
	e.updated_at = now;
	old = flow_cgrp(id);
	if (old)
		was_limited = !flow_bw_unlimited(old->quota_us);
	is_limited = !flow_bw_unlimited(quota);
	if (bpf_map_update_elem(&cgrp_stor, &id, &e, BPF_ANY) < 0)
		return -ENOMEM;
	if (is_limited && !was_limited)
		__sync_fetch_and_add(&flow_bw_limited, 1);
	if (!is_limited && was_limited)
		__sync_fetch_and_add(&flow_bw_limited, (u64)-1);
	__sync_fetch_and_add(&flow_cgrp_gen, 1);
	return 0;
}
/* Exit one hierarchy entry with limited count fixup. */
/* Deletes the row, so later lookups miss to base share. */
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 id;
	struct flow_cgrp_ctx *e;
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	e = flow_cgrp(id);
	if (e && !flow_bw_unlimited(e->quota_us))
		__sync_fetch_and_add(&flow_bw_limited, (u64)-1);
	bpf_map_delete_elem(&cgrp_stor, &id);
	__sync_fetch_and_add(&flow_cgrp_gen, 1);
}
/* Prepare one hierarchy move with no alloc and no fail. */
/* Always passes, so the move pairs one to one. */
s32 BPF_STRUCT_OPS(flow_cgroup_prep_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
	return 0;
}
/* Commit one hierarchy move with deadline carry and cache drop. */
/* The deadline stays, so order survives the move. The cache */
/* clears, so the next enqueue walks the new ancestors. */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	struct flow_task_ctx *tctx;
	u64 nid;
	(void)from;
	if (!p || !to)
		return;
	nid = flow_cgrp_id(to);
	if (!nid)
		return;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	tctx->cgid = nid;
	tctx->cached = false;
	__sync_fetch_and_add(&flow_stats.bw_moves, 1);
}
/* Cancel one hierarchy move with no state change. */
/* Preparation holds no state, so cancel stays empty. */
void BPF_STRUCT_OPS(flow_cgroup_cancel_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
/* Update one hierarchy share with generation bump. */
/* Creates the row on miss with unlimited pool, so later */
/* walks see the new share at once. */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp,
	u32 weight)
{
	u64 id;
	struct flow_cgrp_ctx *e;
	struct flow_cgrp_ctx n = {};
	u32 w;
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	w = flow_weight_clamp(weight);
	e = flow_cgrp(id);
	if (e) {
		e->weight = w;
		__sync_fetch_and_add(&flow_cgrp_gen, 1);
		return;
	}
	n.weight = w;
	n.period_us = (u64)FLOW_BW_PERIOD_MIN_US;
	n.quota_us = 0;
	n.burst_us = 0;
	n.pool_ns = 0;
	n.updated_at = flow_now();
	if (bpf_map_update_elem(&cgrp_stor, &id, &n, BPF_ANY) < 0)
		return;
	__sync_fetch_and_add(&flow_cgrp_gen, 1);
}
/* Update one hierarchy pool with floor plus burst cap. */
/* Unlimited maps to zero with no cap use. Limited pools cap */
/* at quota plus burst, and the generation bumps once. */
void BPF_STRUCT_OPS(flow_cgroup_set_bandwidth, struct cgroup *cgrp,
	u64 period_us, u64 quota_us, u64 burst_us)
{
	u64 id;
	u64 period;
	u64 quota;
	u64 max;
	struct flow_cgrp_ctx *e;
	struct flow_cgrp_ctx n = {};
	bool was_limited = false;
	bool is_limited;
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	period = flow_bw_period_floor(period_us);
	quota = flow_bw_quota_norm(quota_us);
	max = flow_bw_max_ns(quota, burst_us);
	is_limited = !flow_bw_unlimited(quota);
	e = flow_cgrp(id);
	if (e) {
		was_limited = !flow_bw_unlimited(e->quota_us);
		e->period_us = period;
		e->quota_us = quota;
		e->burst_us = burst_us;
		if (flow_bw_unlimited(quota)) {
			e->pool_ns = 0;
		} else {
			if (e->pool_ns > max)
				e->pool_ns = max;
			if (e->pool_ns == 0 && max)
				e->pool_ns = max;
		}
		e->updated_at = flow_now();
		if (is_limited && !was_limited)
			__sync_fetch_and_add(&flow_bw_limited, 1);
		if (!is_limited && was_limited)
			__sync_fetch_and_add(&flow_bw_limited, (u64)-1);
		__sync_fetch_and_add(&flow_cgrp_gen, 1);
		return;
	}
	n.weight = (u32)FLOW_CGRP_WEIGHT_DFL;
	n.period_us = period;
	n.quota_us = quota;
	n.burst_us = burst_us;
	if (flow_bw_unlimited(quota))
		n.pool_ns = 0;
	else
		n.pool_ns = max;
	n.updated_at = flow_now();
	if (bpf_map_update_elem(&cgrp_stor, &id, &n, BPF_ANY) < 0)
		return;
	if (is_limited)
		__sync_fetch_and_add(&flow_bw_limited, 1);
	__sync_fetch_and_add(&flow_cgrp_gen, 1);
}
/* Update one hierarchy idle state with no pool change. */
/* Idle stays advisory, so the op holds no state. */
void BPF_STRUCT_OPS(flow_cgroup_set_idle, struct cgroup *cgrp,
	bool idle)
{
	(void)cgrp;
	(void)idle;
}
