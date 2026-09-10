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
/* Fixed slice at 1ms, two groups, ordered queues. */
enum flow_consts {
	FLOW_EST_MIN_NS = 1ULL,
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	FLOW_SLICE_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_DSQ_BASE = 0x4000ULL,
	FLOW_DSQ_PARK = 0x5000ULL,
	FLOW_DSQ_PARK_HOG = 0x5001ULL,
	FLOW_NGROUPS = 2ULL,
	FLOW_GROUP_LIGHT = 0ULL,
	FLOW_GROUP_HOG = 1ULL,
	FLOW_WIN_NS = (32ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURN_NS = (16ULL * 1000ULL * 1000ULL),
	FLOW_DEMOTE_BURST_NS = (4ULL * 1000ULL * 1000ULL),
	FLOW_PROMOTE_BURN_NS = (4ULL * 1000ULL * 1000ULL),
	FLOW_PROMOTE_WINS = 64ULL,
	FLOW_PINNED_INFLATE_NS = (8ULL * 1000ULL * 1000ULL),
	FLOW_PERF_LIGHT = 1024ULL,
	FLOW_PERF_HOG = 512ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_WEIGHT = 1024ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
};
/* Per task state at 48B with group plus window. */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 vruntime;
	u64 deadline;
	u64 win_start;
	u32 burn;
	u8 group;
	u8 low_runs;
};
/* Per CPU state at 24B. */
struct flow_cpu_state {
	u64 frontier;
	u64 running_est;
	u32 running_pid;
	u32 cursor;
};
/* Scheduler counters at 128B with group detail. */
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
	u64 group_demote;
	u64 group_promote;
	u64 pinned_hog_inflated;
	u64 group_steal_skipped;
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
/* Group of one CPU by id halves with extra to hog. */
static __always_inline u8 flow_group_of_cpu(u32 cpu,
	u64 nr)
{
	if (nr <= 1)
		return (u8)FLOW_GROUP_LIGHT;
	if ((u64)cpu < nr / 2)
		return (u8)FLOW_GROUP_LIGHT;
	return (u8)FLOW_GROUP_HOG;
}
/* Park id of one group with light as default. */
static __always_inline u64 flow_park_for_group(u8 group)
{
	if (group == (u8)FLOW_GROUP_HOG)
		return (u64)FLOW_DSQ_PARK_HOG;
	return (u64)FLOW_DSQ_PARK;
}
/* Perf hint of one group with light at max. */
static __always_inline u32 flow_perf_for_group(u8 group)
{
	if (group == (u8)FLOW_GROUP_HOG)
		return (u32)FLOW_PERF_HOG;
	return (u32)FLOW_PERF_LIGHT;
}
/* True when one window of 32ms has passed. */
static __always_inline bool flow_win_ready(u64 now,
	u64 win_start)
{
	if (win_start == 0)
		return false;
	return now - win_start >= (u64)FLOW_WIN_NS;
}
/* True when window burn reaches 16ms for demote. */
static __always_inline bool flow_burn_hot(u32 burn)
{
	return (u64)burn >= (u64)FLOW_DEMOTE_BURN_NS;
}
/* True when one burst reaches 4ms for demote. */
static __always_inline bool flow_burst_hot(u64 delta)
{
	return delta >= (u64)FLOW_DEMOTE_BURST_NS;
}
/* True when window burn stays below 4ms for promote. */
static __always_inline bool flow_burn_low(u32 burn)
{
	return (u64)burn < (u64)FLOW_PROMOTE_BURN_NS;
}
/* Deadline with pinned hog extra of 8ms. */
static __always_inline u64 flow_inflate_deadline(u64 dl)
{
	return dl + (u64)FLOW_PINNED_INFLATE_NS;
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
/* The caller keeps the old frontier when waking is zero, */
/* so zero never disorders the frontier. */
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
