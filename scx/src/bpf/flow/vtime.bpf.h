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

/* Vtime adds one fixed slice with max saturation, no wrap, */
/* no knob. Docs only, no logic change. */

#endif
