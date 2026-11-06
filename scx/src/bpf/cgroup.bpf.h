// SPDX-License-Identifier: GPL-2.0
/*
 * Share handling for the flow scheduler.
 *
 * Shares range from one to ten thousand with one hundred as the
 * default. The group id comes from the cgroup node. Enqueue reads
 * the map on every insert, so a share change applies to the next
 * enqueue. A missing entry reads as the default. Move and init
 * record the id and a hint for later reads.
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
s32 BPF_STRUCT_OPS(flow_cgroup_init, struct cgroup *cgrp, struct scx_cgroup_init_args *args)
{
	u64 cgid;
	(void)args;
	if (!cgrp)
		return 0;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return 0;
	{
		u64 w = (u64)FLOW_CGROUP_WEIGHT_DFLT;
		bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	bpf_map_delete_elem(&cgrp_weight_stor, &cgid);
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
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p, struct cgroup *from, struct cgroup *to)
{
	struct flow_task_ctx *t;
	u64 cgid;
	u32 w;
	(void)from;
	if (!p || !to)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	cgid = flow_cgroup_cgid(to);
	if (!cgid)
		return;
	t->cgrp_id = cgid;
	w = flow_cgroup_lookup(cgid);
	t->cg_weight = w;
}
#endif
