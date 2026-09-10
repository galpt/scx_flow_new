/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
#ifndef __FLOW_INTF_H
#define __FLOW_INTF_H
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif
#include <stdbool.h>
#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif
/* Fixed slice at 1ms, ordered queues, display only cards. */
enum flow_consts {
	FLOW_EST_MIN_NS = 1ULL,
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	FLOW_SLICE_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_DSQ_BASE = 0x4000ULL,
	FLOW_DSQ_PARK = 0x5000ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_WEIGHT = 1024ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
};
/* Per task state at 32B with no grant and no owner. */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 vruntime;
	u64 deadline;
};
/* Per CPU state at 24B with no mean and no table. */
struct flow_cpu_state {
	u64 frontier;
	u64 running_est;
	u32 running_pid;
	u32 cursor;
};
/* Scheduler counters at 96B with EDF detail. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 park_moves;
	u64 steal_moves;
	u64 kicks;
	u64 enq_no_tctx;
	u64 edf_enqueued;
	u64 edf_clamped;
	u64 edf_ordered;
};
/* Clamp estimate to the estimate range. */
static __always_inline u64 flow_clamp_est(u64 v)
{
	if (v < (u64)FLOW_EST_MIN_NS)
		return (u64)FLOW_EST_MIN_NS;
	if (v > (u64)FLOW_EST_MAX_NS)
		return (u64)FLOW_EST_MAX_NS;
	return v;
}
/* Queue id of one CPU with range check by caller. */
static __always_inline u64 flow_dsq_for_cpu(u32 cpu)
{
	return (u64)FLOW_DSQ_BASE + (u64)cpu;
}
/* Scale estimate by weight with fixed identity. */
static __always_inline u64 flow_scale_by_weight(u64 est,
	u32 weight)
{
	if (weight == 0)
		return est;
	if (weight == (u32)FLOW_WEIGHT)
		return est;
	return (est * 1024ULL) / (u64)weight;
}
/* True when first time is before second with wrap. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Clamp virtual time to one slice behind frontier. */
static __always_inline u64 flow_clamp_vruntime(u64 v,
	u64 frontier, u64 slice)
{
	u64 floor = frontier - slice;
	if (flow_time_before(v, floor))
		return floor;
	return v;
}
/* Deadline from clamped time plus scaled estimate. */
static __always_inline u64 flow_deadline(u64 clamped_v,
	u64 scaled)
{
	return clamped_v + scaled;
}
/* Advance virtual time by scaled runtime with wrap. */
static __always_inline u64 flow_vruntime_add(u64 v,
	u64 delta)
{
	return v + delta;
}
/* Max of two virtual times with wrap safety. */
static __always_inline u64 flow_frontier_max(u64 old,
	u64 next)
{
	if (flow_time_before(old, next))
		return next;
	return old;
}
/* Frontier for idle CPU from waking time with no zero. */
static __always_inline u64 flow_frontier_idle(u64 waking_v)
{
	return waking_v;
}
/* Next peer for steal scan with rotating cursor. */
static __always_inline u32 flow_steal_next(u32 cursor,
	u32 nr_cpus)
{
	if (nr_cpus == 0)
		return 0;
	return (cursor + 1) % nr_cpus;
}
#endif
