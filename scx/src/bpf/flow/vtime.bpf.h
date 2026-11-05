// SPDX-License-Identifier: GPL-2.0
/*
 * Flow virtual time helper.
 *
 * Moved from main with no behavior change. Saturates at max on overflow
 * with no knob and no wrap.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_VTIME_BPF_H
#define __FLOW_VTIME_BPF_H

#include "../intf.h"

/* Saturated vtime plus slice. Caps at max on overflow. */
static __always_inline s64 flow_vtime_add_slice(s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 sl = (s64)FLOW_SLICE_NS;
	if (v > vmax - sl)
		return vmax;
	return v + sl;
}

/* Saturated vtime plus one uniform penalty slice. Reuses the fixed */
/* slice with no knob, so a task that burnt the full slice pays one */
/* extra quantum with no wrap and no new tunable. Uniform is the bounded */
/* throttle analogue: the base charge already scales by weight, so */
/* default pays one slice, heavy pays a hundredth and light pays a */
/* hundred. One uniform extra slice then doubles the default step, */
/* multiplies the heavy step a hundredfold to break its head hold, and */
/* adds one percent to the light step that already sits far behind. A */
/* scaled penalty would keep the heavy hog near the head and preserve */
/* the domino, so uniform is the fix. The pair floor plus LLC order */
/* move the postponed vtime behind the head, and the steal walk reclaims */
/* idle time work conserving. No per task period input exists here, so */
/* the implicit period stays one slice with no new map or timer. Caps */
/* at max on overflow. */
static __always_inline s64 flow_vtime_add_penalty(s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 sl = (s64)FLOW_SLICE_NS;
	if (v > vmax - sl)
		return vmax;
	return v + sl;
}

/* One shot latency offset for the queue key. A latency task moves one */
/* fixed slice ahead of the same raw time with saturation at zero, so a */
/* small raw time never wraps. Hogs plus pinned plus exiting keep the */
/* raw key. Stored time plus deadline stay raw, so the offset never */
/* accumulates across enqueues. Only the insert key plus the kick */
/* compare use the offset key. The stamp never shifts with the offset. */
static __always_inline s64 flow_vtime_boost(s64 raw, int is_lat)
{
	s64 off = (s64)FLOW_LAT_OFF_NS;
	if (!is_lat)
		return raw;
	if (raw > off)
		return raw - off;
	return 0;
}

/* Vtime adds one fixed slice with max saturation, no wrap, */
/* no knob. Penalty reuses the same uniform slice as the throttle. */
/* Boost moves the latency key one slice with zero saturation one shot. */
/* Enqueue stamp never shifts vtime. Docs only, no logic change. */

#endif
