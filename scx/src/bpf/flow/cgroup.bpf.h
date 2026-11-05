// SPDX-License-Identifier: GPL-2.0
/*
 * Flow cgroup weight shares.
 *
 * Maps cpu.weight onto vtime charge scaling. Range [1, 10000] default
 * 100 comes from include/linux/cgroup.h CGROUP_WEIGHT_MIN/DFL/MAX plus
 * the cgroup v2 doc "All weights are in the range [1, 10000] with the
 * default at 100" plus flash/forge CGROUP_WEIGHT_DFL 100. Id comes
 * from cgrp->kn->id the same way lavd reads to->kn->id, and kernfs_node
 * carries u64 id in vmlinux. Hooks match the pinned sched_ext_ops
 * field names cgroup_init/cgroup_exit/cgroup_move/cgroup_set_weight
 * plus init_task with args->cgroup, same shapes as flash/forge.
 * Maps plus task storage only with no arena use, so no TOUCH here.
 * Miss plus zero id plus zero weight all read as default, which keeps
 * 5.0.8 behavior whenever shares are unknown. Slice never scales.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_CGROUP_BPF_H
#define __FLOW_CGROUP_BPF_H

#include "../intf.h"
#include "maps.bpf.h"

/* Clamp a weight knob into [1, 10000]. Zero is never valid and falls */
/* back to default, same as a missing entry. Cited above. */
static __always_inline u32 flow_cgroup_clamp(u32 w)
{
	if (w == (u32)FLOW_CGROUP_WEIGHT_INVALID ||
	    w < (u32)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u32)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return w;
}

/* Same clamp for map values, which store the weight as u64. */
static __always_inline u32 flow_cgroup_clamp_u64(u64 w)
{
	if (!w || w < (u64)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u64)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return (u32)w;
}

/* Cgroup id from the kernfs node. Null cgroup plus null node fail */
/* closed to zero, which always reads as default. Only the move plus */
/* init paths need an id; current-only helpers cannot serve them. */
static __always_inline u64 flow_cgroup_cgid(struct cgroup *cgrp)
{
	if (!cgrp)
		return 0;
	if (!cgrp->kn)
		return 0;
	return cgrp->kn->id;
}

/* Weight by id. Miss plus zero id plus zero value read as default. */
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

/* Task cached weight. Zero init plus invalid read as default. */
static __always_inline u32 flow_task_weight(struct flow_task_ctx *t)
{
	if (!t || t->cg_weight == (u32)FLOW_CGROUP_WEIGHT_INVALID)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_cgroup_clamp(t->cg_weight);
}

/* Scaled slice step for a weight. Slice times default over weight, */
/* so 200 charges half and 50 charges double. Default is identity. */
static __always_inline u64 flow_cgroup_step(u32 w)
{
	u32 cw = flow_cgroup_clamp(w);
	if (!cw)
		return (u64)FLOW_SLICE_NS;
	return (u64)FLOW_SLICE_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
}

/* Saturated weight-scaled charge of used nanos onto base vtime. */
/* Splits used into slice units plus rest so the multiply never */
/* overflows, then caps at max. Default weight is exact identity. */
/* Monotonic floor stays with the caller, so starvation is bounded */
/* by the same last plus one rule as before. Slice never scales. */
static __always_inline s64 flow_cgroup_charge(s64 base, u64 used, u32 w)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	u64 st = flow_cgroup_step(w);
	u64 hi;
	u64 lo;
	u64 scaled;
	if (!st)
		st = (u64)FLOW_SLICE_NS;
	hi = used / (u64)FLOW_SLICE_NS;
	lo = used % (u64)FLOW_SLICE_NS;
	if (hi > (u64)vmax / st)
		return vmax;
	scaled = hi * st + lo * st / (u64)FLOW_SLICE_NS;
	if (scaled > (u64)vmax)
		return vmax;
	if (base >= vmax - (s64)scaled)
		return vmax;
	return base + (s64)scaled;
}

#endif
