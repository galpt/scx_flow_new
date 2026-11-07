// SPDX-License-Identifier: GPL-2.0
/*
 * Shortest job tracking for the flow scheduler.
 *
 * Each task keeps a burst estimate. The estimate mixes the old
 * value with the fresh sample, keeping half of the old value and
 * adding half of the sample. It starts from a fixed seed
 * and is clamped to a floor and a ceiling. Estimates under half
 * a millisecond select the latency queue, up to a millisecond the
 * normal queue, up to twenty milliseconds the batch queue, and the
 * rest the idle queue. The queue choice wakes idle targets only with no preempt.
 * Waits that grow long halve the estimate, and waits that grow
 * very long reset it and count a rescue. Remaining takes the aged
 * estimate minus the burnt part with saturation at the floor.
 * All math uses integers.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SJF_BPF_H
#define __FLOW_SJF_BPF_H
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
static __always_inline u64 flow_sjf_remain(u64 aged, u64 used)
{
	u64 a = aged ? flow_sjf_clamp(aged) : (u64)FLOW_SJF_INIT_NS;
	if (used >= a)
		return (u64)FLOW_SJF_FLOOR_NS;
	{
		u64 v = a - used;
		return flow_sjf_clamp(v);
	}
}
static __always_inline u32 flow_sjf_prio(u64 est, u64 wait_ns, u64 now)
{
	u64 age = 0;
	if (now && wait_ns && now > wait_ns)
		age = now - wait_ns;
	if (age >= (u64)FLOW_STARVE_NS)
		return (u32)FLOW_PRIO_LAT;
	if (est < (u64)FLOW_SJF_LAT_NS)
		return (u32)FLOW_PRIO_LAT;
	if (est <= (u64)FLOW_SJF_INIT_NS)
		return (u32)FLOW_PRIO_NORM;
	if (est <= (u64)FLOW_SJF_BATCH_NS)
		return (u32)FLOW_PRIO_BATCH;
	return (u32)FLOW_PRIO_IDLE;
}
static __always_inline u64 flow_sjf_age(u64 est, u64 wait_ns, u64 now, u32 llc)
{
	u64 age = 0;
	if (!now || !wait_ns || now <= wait_ns)
		return est;
	age = now - wait_ns;
	if (age >= (u64)FLOW_STARVE_NS) {
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
#endif
