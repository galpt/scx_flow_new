// SPDX-License-Identifier: GPL-2.0
/*
 * Flow cgroup weight shares.
 *
 * The cpu.weight range is 1 through 10000 with default 100. The id
 * comes from the kernfs node. Enqueue reads the live map by id, so
 * a weight change lands on the next enqueue. The task cache is a
 * hint for move and init only. The slice never scales.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_CGROUP_BPF_H
#define __FLOW_CGROUP_BPF_H

#include "../intf.h"
#include "maps.bpf.h"

/**
 * flow_cgroup_clamp - clamp a weight into range.
 * @w: candidate weight.
 *
 * Zero is not valid and reads as default.
 *
 * Returns: the clamped weight.
 */
static __always_inline u32 flow_cgroup_clamp(u32 w)
{
	if (w == (u32)FLOW_CGROUP_WEIGHT_INVALID ||
	    w < (u32)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u32)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return w;
}

/**
 * flow_cgroup_clamp_u64 - clamp a stored weight into range.
 * @w: candidate weight from the map.
 *
 * Returns: the clamped weight.
 */
static __always_inline u32 flow_cgroup_clamp_u64(u64 w)
{
	if (!w || w < (u64)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (w > (u64)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return (u32)w;
}

/**
 * flow_cgroup_cgid - id for a cgroup.
 * @cgrp: cgroup, may be NULL.
 *
 * Returns: the kernfs id, or zero when unavailable.
 */
static __always_inline u64 flow_cgroup_cgid(struct cgroup *cgrp)
{
	if (!cgrp)
		return 0;
	if (!cgrp->kn)
		return 0;
	return cgrp->kn->id;
}

/**
 * flow_cgroup_lookup - weight for an id.
 * @cgid: kernfs id, with zero meaning none.
 *
 * A miss reads as default.
 *
 * Returns: the weight.
 */
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

/**
 * flow_task_weight - cached weight for a task.
 * @t: task context, may be NULL.
 *
 * Returns: the cached weight, or default when unset.
 */
static __always_inline u32 flow_task_weight(struct flow_task_ctx *t)
{
	if (!t || t->cg_weight == (u32)FLOW_CGROUP_WEIGHT_INVALID)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_cgroup_clamp(t->cg_weight);
}

/**
 * flow_cgroup_step - slice scaled step for a weight.
 * @w: weight.
 *
 * Slice times default over weight, so 200 charges half and 50
 * charges double. Default is identity.
 *
 * Returns: the step in nanos.
 */
static __always_inline u64 flow_cgroup_step(u32 w)
{
	u32 cw = flow_cgroup_clamp(w);
	if (!cw)
		return (u64)FLOW_SLICE_NS;
	return (u64)FLOW_SLICE_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
}

/**
 * flow_cgroup_charge - charge used nanos onto a base time.
 * @base: base virtual time.
 * @used: nanos burnt.
 * @w: weight.
 *
 * Splits used into slice units plus rest so the multiply cannot
 * overflow, then caps at the maximum. Default weight is identity.
 * The caller keeps the monotonic floor.
 *
 * Returns: the charged time.
 */
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
