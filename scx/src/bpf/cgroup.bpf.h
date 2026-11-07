// SPDX-License-Identifier: GPL-2.0
/*
 * Share plus bandwidth handling for the flow scheduler.
 *
 * Shares range from one to ten thousand with one hundred as the
 * default. The group id comes from the cgroup node. Enqueue reads
 * the map on every insert, so a share change applies to the next
 * enqueue. A missing entry reads as the default. Move and init
 * record the id and a hint for later reads. Bandwidth follows the
 * admin cpu max through the shared library. Throttled tasks wait
 * aside and rejoin when the limit opens again.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_CGROUP_BPF_H
#define __FLOW_CGROUP_BPF_H
#include "intf.h"
#include "maps.bpf.h"
static __always_inline u32 flow_cgroup_clamp(u32 w)
{
	if (w == (u32)FLOW_CGROUP_WEIGHT_INVALID || w < (u32)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u32)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return w;
}
static __always_inline u32 flow_cgroup_clamp_u64(u64 w)
{
	if (!w || w < (u64)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u64)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return (u32)w;
}
static __always_inline u64 flow_cgroup_cgid(struct cgroup *cgrp)
{
	if (!cgrp)
		return 0;
	if (!cgrp->kn)
		return 0;
	return cgrp->kn->id;
}
static __always_inline u32 flow_cgroup_lookup(u64 cgid)
{
	u64 *wp;
	if (!cgid)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	wp = bpf_map_lookup_elem(&cgrp_weight_stor, &cgid);
	if (!wp || !*wp)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_cgroup_clamp_u64(*wp);
}
static __always_inline int flow_cgroup_throttled(struct task_struct *p, task_ctx *t,
						 bool put_aside, u64 vtime)
{
	int ret;
	int ret2;
	if (!p || !t)
		return 0;
	if (p->flags & PF_EXITING)
		return 0;
	scx_arena_subprog_init();
	ret = scx_cgroup_bw_throttled(p, (u64)t);
	if (ret == -EAGAIN && put_aside &&
	    !scx_cgroup_bw_is_task_throttled((u64)t)) {
		ret2 = scx_cgroup_bw_put_aside(p, (u64)t, vtime);
		if (ret2)
			return ret2;
	}
	return ret;
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	u64 cgid;
	int ret;
	if (!cgrp)
		return 0;
	cgid = flow_cgroup_cgid(cgrp);
	if (cgid) {
		u64 w = (u64)FLOW_CGROUP_WEIGHT_DFLT;
		bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
	}
	ret = scx_cgroup_bw_init(cgrp, args);
	if (ret == -EOPNOTSUPP)
		return 0;
	if (ret)
		return ret;
	return 0;
}
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (cgid)
		bpf_map_delete_elem(&cgrp_weight_stor, &cgid);
	scx_cgroup_bw_exit(cgrp);
}
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgid;
	u64 w;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	w = (u64)flow_cgroup_clamp(weight);
	bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
}
void BPF_STRUCT_OPS(flow_cgroup_set_bandwidth, struct cgroup *cgrp, u64 period_us, u64 quota_us,
		    u64 burst_us)
{
	int ret;
	if (!cgrp)
		return;
	ret = scx_cgroup_bw_set(cgrp, period_us, quota_us, burst_us);
	if (ret == -EOPNOTSUPP)
		return;
	if (ret)
		scx_bpf_error("bandwidth set failed %d", ret);
}
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	task_ctx *t;
	u64 cgid;
	u32 w;
	int ret;
	if (!p || !to)
		return;
	scx_arena_subprog_init();
	t = flow_find_task(p);
	if (!t)
		return;
	cgid = flow_cgroup_cgid(to);
	if (cgid) {
		t->cgrp_id = cgid;
		w = flow_cgroup_lookup(cgid);
		t->cg_weight = w;
	}
	if (!from)
		return;
	ret = scx_cgroup_bw_move(p, (u64)t, from, to);
	if (ret == -EOPNOTSUPP)
		return;
	if (ret)
		scx_bpf_error("bandwidth move failed %d", ret);
}
#endif
