// SPDX-License-Identifier: GPL-2.0
/*
 * Shortest remaining time tracking for the flow scheduler.
 *
 * Each task keeps a remaining time estimate. The estimate mixes the old
 * value with the fresh sample, keeping half of the old value and
 * adding half of the sample. Stopping refines the mix with the wait
 * and the remain through fixed weights. It starts from a fixed seed
 * and is clamped to a floor and a ceiling. Small remaining times select
 * the latency queue and large estimates select the batch queues.
 * The queue choice preempts through the kick path. Waits that grow
 * long halve the estimate, and waits that grow very long reset it
 * and count a rescue. Tasks that burn several full slices in a row
 * move down one queue. All math uses integers.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SRTF_BPF_H
#define __FLOW_SRTF_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
static __always_inline u64 flow_sjf_clamp(u64 v)
{
	if (v < (u64)FLOW_SJF_FLOOR_NS)
		return (u64)FLOW_SJF_FLOOR_NS;
	if (v > (u64)FLOW_SJF_CAP_NS)
		return (u64)FLOW_SJF_CAP_NS;
	return v;
}
static __always_inline u64 flow_sjf_next(u64 old, u64 sample)
{
	u64 s = flow_sjf_clamp(sample ? sample : (u64)FLOW_SJF_INIT_NS);
	u64 o = old ? flow_sjf_clamp(old) : (u64)FLOW_SJF_INIT_NS;
	u64 keep = o - (o >> 1);
	u64 add = s >> 1;
	u64 v = keep + add;
	return flow_sjf_clamp(v);
}
/* Linear burst estimate with fixed weights. Keeps half of the old value
 * and half of the sample, then takes away a small part of the wait and
 * a small part of the remain. Wait and remain arrive in millis and move
 * to nanos with saturation. All weights use eight fractional bits. The
 * sum shifts down by eight and clamps between floor and cap. Any step
 * that would overflow falls back to the half blend. */
static __always_inline u64 flow_pred_next(u64 old, u64 sample, u64 wait_ms, u64 rem_ms)
{
	u64 o = old ? flow_sjf_clamp(old) : (u64)FLOW_SJF_INIT_NS;
	u64 s = flow_sjf_clamp(sample ? sample : (u64)FLOW_SJF_INIT_NS);
	u64 wait_ns;
	u64 rem_ns;
	u64 wpart;
	u64 rpart;
	u64 acc;
	u64 sub;
	u64 v;
	if (wait_ms > (u64)18446744073709ULL)
		return flow_sjf_next(old, sample);
	wait_ns = wait_ms * (u64)1000000ULL;
	if (rem_ms > (u64)18446744073709ULL)
		return flow_sjf_next(old, sample);
	rem_ns = rem_ms * (u64)1000000ULL;
	if (wait_ns > (u64)4611686018427387903ULL)
		return flow_sjf_next(old, sample);
	if (rem_ns > (u64)2305843009213693951ULL)
		return flow_sjf_next(old, sample);
	wpart = wait_ns << 2;
	rpart = rem_ns << 3;
	if (wpart > (u64)0xffffffffffffffffULL - rpart)
		return flow_sjf_next(old, sample);
	acc = (o << 7) + (s << 7);
	sub = wpart + rpart;
	if (sub > acc)
		return (u64)FLOW_SJF_FLOOR_NS;
	v = (acc - sub) >> 8;
	return flow_sjf_clamp(v);
}
static __always_inline u32 flow_sjf_prio(u64 est, u64 wait_ns, u64 now)
{
	u64 age = 0;
	if (now && wait_ns && now > wait_ns)
		age = now - wait_ns;
	if (age >= (u64)FLOW_STARVE_NS)
		return (u32)FLOW_PRIO_LAT;
	if (est <= (u64)FLOW_SJF_INIT_NS)
		return (u32)FLOW_PRIO_LAT;
	if (est <= (u64)FLOW_SLICE_MIN_NS * 3)
		return (u32)FLOW_PRIO_NORM;
	if (est <= (u64)FLOW_AGING_NS)
		return (u32)FLOW_PRIO_BATCH;
	return (u32)FLOW_PRIO_IDLE;
}
static __always_inline u64 flow_sjf_age(u64 est, u64 wait_ns, u64 now, u32 llc, int *rescued)
{
	u64 age = 0;
	if (rescued)
		*rescued = 0;
	if (!now || !wait_ns || now <= wait_ns)
		return est;
	age = now - wait_ns;
	if (age >= (u64)FLOW_STARVE_NS) {
		if (rescued)
			*rescued = 1;
		flow_stat_inc(llc, 18);
		return (u64)FLOW_SJF_INIT_NS;
	}
	if (age >= (u64)FLOW_AGING_NS) {
		u64 v = est - (est >> 1);
		flow_stat_inc(llc, 18);
		return flow_sjf_clamp(v);
	}
	return est;
}
static __always_inline u64 flow_hog_used(u64 len, u64 rem)
{
	if (rem >= len)
		return 0;
	return len - rem;
}
static __always_inline int flow_hog_full(u64 used, u64 len, u64 rem)
{
	if (!len)
		return 0;
	if (rem != 0)
		return 0;
	return used == len;
}
static __always_inline int flow_hog_rounds(u32 streak)
{
	return streak >= (u32)FLOW_STREAK_MAX;
}
static __always_inline u64 flow_hog_demote(u64 extra)
{
	if (extra == 0)
		return 0;
	return extra - 1;
}
#endif
