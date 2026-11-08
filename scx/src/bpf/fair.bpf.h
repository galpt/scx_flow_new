// SPDX-License-Identifier: GPL-2.0
/*
 * Fair charging for the flow scheduler.
 *
 * The base charge scales with the cgroup share. Values saturate at
 * the top. The task nice weight comes from a small table over minus
 * twenty to nineteen with zero as one hundred, read from the task
 * static priority minus one hundred twenty. Out of range tasks keep
 * the default. The combined share multiplies the cgroup share by the
 * nice weight over one hundred and clamps to the share range, so a
 * zero nice keeps the cgroup share unchanged.
 * Fresh times move past the per LLC floor through a short
 * compare and swap loop, so each stored time is unique. If the loop
 * does not win, the last observed value is written back directly.
 * The floor rises over time and never moves backward for a given
 * LLC. Vd adds the share step to the floored time, so a larger
 * share gives an earlier vd with no extra divide.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H
#include "intf.h"
#include "maps.bpf.h"
/* Nice weight on the cgroup scale from minus twenty to nineteen.
 * Strictly falls from ten thousand to one with one hundred at zero.
 * Fits in read only data with direct indexing and no loop. */
static const u32 flow_nice_table[40] = {
	10000, 7943, 6310, 5012, 3981, 3162, 2512, 1995,
	1585, 1259, 1000, 794, 631, 501, 398, 316,
	251, 200, 158, 126, 100, 78, 62, 48,
	38, 30, 23, 18, 14, 11, 10, 9,
	8, 7, 6, 5, 4, 3, 2, 1,
};
static __always_inline u32 flow_nice_weight(const struct task_struct *p)
{
	s32 prio;
	u32 idx;
	if (!p)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	prio = p->static_prio - 120;
	if (prio < -20 || prio > 19)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	idx = (u32)(prio + 20);
	if (idx >= 40U)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_nice_table[idx];
}
static __always_inline u32 flow_combine(u32 cw, u32 nw)
{
	u64 prod = (u64)cw * (u64)nw;
	u64 q = prod / (u64)100;
	if (!q || q < (u64)FLOW_CGROUP_WEIGHT_MIN)
		return (u32)FLOW_CGROUP_WEIGHT_MIN;
	if (q > (u64)FLOW_CGROUP_WEIGHT_MAX)
		return (u32)FLOW_CGROUP_WEIGHT_MAX;
	return (u32)q;
}
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
static __always_inline s64 flow_vd_for(s64 floored, u32 w)
{
	return flow_fair_cap_add(floored, flow_fair_step(w));
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
