// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline tracking for the flow scheduler.
 *
 * Each task keeps remain for the current deadline. Remain starts at
 * one slice and burns down as the task runs, clamped to a floor and
 * a span. Deadline adds a fixed span to the enqueue time and is kept
 * until it passes, then a fresh span is added. Slack is deadline
 * minus now minus remain with saturation at the top and bottom.
 * Small slack takes the first queue with larger slack placed further
 * back in fixed bands. Bands use zero plus one slice plus ten slices.
 * Burst keeps a filtered used time per task. Short samples lower the
 * filter fast while long samples raise it slow, clamped to a floor
 * and a cap with a one slice seed. The band state needs two short
 * samples to turn short and two long samples to turn back. Full burns
 * count up to a cap while sleeps step down by one. The band label
 * joins slack with the burst state with a ceiling for fresh tasks.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_EDF_BPF_H
#define __FLOW_EDF_BPF_H
#include "intf.h"
static __always_inline u64 flow_edf_clamp_rem(u64 v)
{
	if (v < (u64)FLOW_EDF_FLOOR_NS)
		return (u64)FLOW_EDF_FLOOR_NS;
	if (v > (u64)FLOW_EDF_REL_NS)
		return (u64)FLOW_EDF_REL_NS;
	return v;
}
static __always_inline s64 flow_edf_slack(u64 deadline, u64 now, u64 remain)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	const s64 vmin = -vmax - 1;
	u64 r = flow_edf_clamp_rem(remain);
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
static __always_inline u32 flow_edf_prio(s64 slack)
{
	if (slack <= 0)
		return (u32)FLOW_PRIO_LAT;
	if (slack <= (s64)FLOW_EDF_NORM_NS)
		return (u32)FLOW_PRIO_NORM;
	if (slack <= (s64)FLOW_EDF_BATCH_NS)
		return (u32)FLOW_PRIO_BATCH;
	return (u32)FLOW_PRIO_IDLE;
}
/* Clamp the filtered burst between the floor and the cap. */
static __always_inline u32 flow_est_clamp(u32 v)
{
	if (v < (u32)FLOW_EDF_EST_FLOOR_NS)
		return (u32)FLOW_EDF_EST_FLOOR_NS;
	if (v > (u32)FLOW_EDF_EST_CAP_NS)
		return (u32)FLOW_EDF_EST_CAP_NS;
	return v;
}
/* Asymmetric filter over used time. Short samples drop fast with
 * quarter old plus half sample plus quarter sample. Long samples
 * climb slow with old plus an eighth of the gap. */
static __always_inline u32 flow_est_update(u32 old, u32 sample)
{
	u32 base = old;
	u32 next;
	if (!base)
		base = (u32)FLOW_EDF_INIT_NS;
	if (!sample)
		return flow_est_clamp(base);
	if (sample < base) {
		next = (base >> 2) + (sample >> 1) + (sample >> 2);
	} else {
		next = base + ((sample - base) >> 3);
	}
	return flow_est_clamp(next);
}
/* Halve the filter after a long sleep gap, held at the floor. */
static __always_inline u32 flow_est_halve(u32 old)
{
	u32 base = old;
	u32 next;
	if (!base)
		base = (u32)FLOW_EDF_INIT_NS;
	next = base >> 1;
	if (next < (u32)FLOW_EDF_EST_FLOOR_NS)
		next = (u32)FLOW_EDF_EST_FLOOR_NS;
	return next;
}
/* Band state holds long stable plus short pending plus short stable
 * plus pending clear in that order. Short needs two short samples to
 * set while long needs two long samples to clear. Mid values hold. */
static __always_inline u8 flow_edf_hyst_next(u8 h, u32 est)
{
	u8 cur = h;
	bool is_short;
	bool is_long;
	if (cur > (u8)FLOW_EDF_HYST_N + 1U)
		cur = 0;
	is_short = est <= (u32)FLOW_EDF_LAT_ENTER_NS;
	is_long = est >= (u32)FLOW_EDF_LAT_EXIT_NS;
	if (cur == 0) {
		if (is_short)
			return 1;
		return 0;
	}
	if (cur == 1) {
		if (is_short)
			return 2;
		if (is_long)
			return 0;
		return 1;
	}
	if (cur == 2) {
		if (is_long)
			return 3;
		return 2;
	}
	if (is_long)
		return 0;
	if (is_short)
		return 2;
	return 3;
}
/* Short lat covers stable short plus pending clear. */
static __always_inline bool flow_edf_hyst_is_lat(u8 h)
{
	return h == 2 || h == 3;
}
/* Full burns step up to the cap. Sleeps step down by one toward zero.
 * Runnable partial burns keep the count. */
static __always_inline u8 flow_edf_hog_next(u8 hog, bool is_full, bool slept)
{
	u8 cur = hog;
	if (cur > (u8)FLOW_EDF_HOG_MAX)
		cur = (u8)FLOW_EDF_HOG_MAX;
	if (is_full) {
		if (cur < (u8)FLOW_EDF_HOG_MAX)
			return cur + 1;
		return (u8)FLOW_EDF_HOG_MAX;
	}
	if (slept) {
		if (cur > 0)
			return cur - 1;
		return 0;
	}
	return cur;
}
/* Join slack with burst state. Fresh tasks cap at the second band.
 * Past due stays on the first band. Sustained full burns take the
 * third band without ever jumping straight to the last band. Short
 * filter lifts the last two bands to the second band only. The last
 * band needs a long filter or a sustained count. */
static __always_inline u32 flow_edf_prio_est(s64 slack, u32 est, u8 hyst, u8 hog, u64 gen)
{
	u32 base = flow_edf_prio(slack);
	if (gen == 0) {
		if (base > (u32)FLOW_PRIO_NORM)
			return (u32)FLOW_PRIO_NORM;
		return base;
	}
	if (slack <= 0)
		return (u32)FLOW_PRIO_LAT;
	if ((u32)hog >= (u32)FLOW_EDF_HOG_ENTER && base < (u32)FLOW_PRIO_BATCH)
		return (u32)FLOW_PRIO_BATCH;
	if (flow_edf_hyst_is_lat(hyst) && base > (u32)FLOW_PRIO_NORM)
		return (u32)FLOW_PRIO_NORM;
	if (base == (u32)FLOW_PRIO_IDLE) {
		bool big = est >= (u32)FLOW_EDF_FULL_NS;
		if (big || (u32)hog >= (u32)FLOW_EDF_HOG_EXIT)
			return (u32)FLOW_PRIO_IDLE;
		return (u32)FLOW_PRIO_BATCH;
	}
	return base;
}
#endif
