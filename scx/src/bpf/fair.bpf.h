// SPDX-License-Identifier: GPL-2.0
/*
 * Fair charging for the flow scheduler.
 *
 * The base charge scales with the cgroup share and the extra charge
 * is the same for every task. Values saturate at the top. Fresh
 * times move past the per LLC floor through a short compare and
 * swap loop, so each stored time is unique. If the loop does not
 * win, the last observed value is written back directly. The floor
 * rises over time and never moves backward for a given LLC.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H
#include "intf.h"
#include "maps.bpf.h"
static __always_inline u64 flow_fair_step(u32 w)
{
	u32 cw = w;
	if (cw == (u32)FLOW_CGROUP_WEIGHT_INVALID || cw < (u32)FLOW_CGROUP_WEIGHT_MIN)
		cw = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (cw > (u32)FLOW_CGROUP_WEIGHT_MAX)
		cw = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (!cw)
		return (u64)FLOW_FAIR_BASE_NS;
	return (u64)FLOW_FAIR_BASE_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
}
static __always_inline s64 flow_fair_cap_add(s64 base, u64 add)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	if (add > (u64)vmax)
		return vmax;
	if (base >= vmax - (s64)add)
		return vmax;
	return base + (s64)add;
}
static __always_inline s64 flow_fair_charge(s64 base, u64 used, u32 w)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	u64 st = flow_fair_step(w);
	u64 slice = (u64)FLOW_SLICE_MIN_NS;
	u64 hi;
	u64 lo;
	u64 scaled;
	if (!st)
		st = (u64)FLOW_FAIR_BASE_NS;
	if (!slice)
		slice = (u64)FLOW_SLICE_MIN_NS;
	hi = used / slice;
	lo = used % slice;
	if (hi > (u64)vmax / st)
		return vmax;
	scaled = hi * st + lo * st / slice;
	if (scaled > (u64)vmax)
		return vmax;
	return flow_fair_cap_add(base, scaled);
}
static __always_inline s64 flow_fair_extra(s64 v, u64 n_extra)
{
	u64 i;
	s64 cur = v;
	for (i = 0; i < 2; i++) {
		if (i >= n_extra)
			break;
		cur = flow_fair_cap_add(cur, (u64)FLOW_FAIR_EXTRA_NS);
	}
	return cur;
}
static __always_inline s64 flow_seq_floor(u32 llc, s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	int i;
	if (!flow_llc_ok(llc))
		return v;
	for (i = 0; i < 4; i++) {
		s64 last = READ_ONCE(flow_llc_seq[llc]);
		s64 want = v;
		if (want <= last) {
			if (last == vmax)
				want = last;
			else
				want = last + 1;
		}
		if (__sync_val_compare_and_swap(&flow_llc_seq[llc], last, want) == last)
			return want;
	}
	{
		s64 last = READ_ONCE(flow_llc_seq[llc]);
		s64 want = v;
		if (want <= last) {
			if (last == vmax)
				want = last;
			else
				want = last + 1;
		}
		flow_llc_seq[llc] = want;
		return want;
	}
}
#endif
