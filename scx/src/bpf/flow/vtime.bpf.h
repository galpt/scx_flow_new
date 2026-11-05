// SPDX-License-Identifier: GPL-2.0
/*
 * Flow virtual time helpers.
 *
 * Adds stay saturated at the maximum with no wrap. The penalty
 * reuses the fixed slice, so a full burn postpones the task by one
 * quantum per award level. The latency shift moves the queue key
 * one slice ahead with saturation at zero.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_VTIME_BPF_H
#define __FLOW_VTIME_BPF_H

#include "../intf.h"

/**
 * flow_vtime_add_slice - step a time forward by one slice.
 * @v: base time.
 *
 * Caps at the maximum on overflow.
 *
 * Returns: the stepped time.
 */
static __always_inline s64 flow_vtime_add_slice(s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 sl = (s64)FLOW_SLICE_NS;
	if (v > vmax - sl)
		return vmax;
	return v + sl;
}

/**
 * flow_vtime_add_penalty - postpone a time by one slice.
 * @v: base time.
 *
 * Uniform for every weight: the base charge already scales by
 * weight, so a heavy task pays a large relative step while a light
 * task already sits behind on its base charge. Caps at the maximum.
 *
 * Returns: the postponed time.
 */
static __always_inline s64 flow_vtime_add_penalty(s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 sl = (s64)FLOW_SLICE_NS;
	if (v > vmax - sl)
		return vmax;
	return v + sl;
}

/**
 * flow_vtime_boost - shift the queue key for a latency task.
 * @raw: stored time, kept unchanged by the caller.
 * @is_lat: non-zero for a latency task.
 *
 * Moves the key one slice ahead with saturation at zero. Hogs and
 * pinned tasks keep the raw key. Stored time is unaffected, so the
 * shift applies once per enqueue.
 *
 * Returns: the queue key.
 */
static __always_inline s64 flow_vtime_boost(s64 raw, int is_lat)
{
	s64 off = (s64)FLOW_LAT_OFF_NS;
	if (!is_lat)
		return raw;
	if (raw > off)
		return raw - off;
	return 0;
}

#endif
