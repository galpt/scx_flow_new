// SPDX-License-Identifier: GPL-2.0
/*
 * Laxity tracking for the flow scheduler.
 *
 * Each task keeps remain for the current deadline. Remain starts at
 * one slice and burns down as the task runs, clamped to a floor and
 * a span. Deadline adds a fixed span to the enqueue time and is kept
 * until it passes, then a fresh span is added. Slack is deadline
 * minus now minus remain with saturation at the top and bottom.
 * Small slack takes the first queue with larger slack placed further
 * back in fixed bands. Bands use zero plus one slice plus ten slices.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_LST_BPF_H
#define __FLOW_LST_BPF_H
#include "intf.h"
static __always_inline u64 flow_lst_clamp_rem(u64 v)
{
	if (v < (u64)FLOW_LST_FLOOR_NS)
		return (u64)FLOW_LST_FLOOR_NS;
	if (v > (u64)FLOW_LST_REL_NS)
		return (u64)FLOW_LST_REL_NS;
	return v;
}
static __always_inline s64 flow_lst_slack(u64 deadline, u64 now, u64 remain)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	const s64 vmin = -vmax - 1;
	u64 r = flow_lst_clamp_rem(remain);
	if (deadline >= now) {
		u64 d = deadline - now;
		if (d > (u64)vmax)
			return vmax;
		{
			s64 sd = (s64)d;
			s64 sr = (s64)r;
			return sd - sr;
		}
	}
	{
		u64 over = now - deadline;
		u64 total;
		if (over > (u64)vmax - r)
			return vmin;
		total = over + r;
		if (total > (u64)vmax)
			return vmin;
		return -(s64)total;
	}
}
static __always_inline u32 flow_lst_prio(s64 slack)
{
	if (slack <= 0)
		return (u32)FLOW_PRIO_LAT;
	if (slack <= (s64)FLOW_LST_NORM_NS)
		return (u32)FLOW_PRIO_NORM;
	if (slack <= (s64)FLOW_LST_BATCH_NS)
		return (u32)FLOW_PRIO_BATCH;
	return (u32)FLOW_PRIO_IDLE;
}
#endif
