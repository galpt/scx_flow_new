/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Shared constants and helpers for the flow scheduler.
 * This header is shared between the BPF object and the
 * userspace front end through generated bindings.
 */
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

/* Basic time units used across the scheduler. */
enum flow_consts {
	NSEC_PER_USEC = 1000ULL,
	NSEC_PER_MSEC = (1000ULL * 1000ULL),
	NSEC_PER_SEC = (1000ULL * 1000ULL * 1000ULL),
	/* Count of tiers kept by the scheduler. */
	FLOW_NTIERS = 2ULL,
	/* Tier index of the interactive tier. */
	FLOW_TIER_INTERACTIVE = 0ULL,
	/* Tier index of the batch tier. */
	FLOW_TIER_BATCH = 1ULL,
	/* Fixed slice of the interactive tier. */
	FLOW_QUANTUM_TIER0_NS = (500ULL * 1000ULL),
	/* Fixed slice of the batch tier. */
	FLOW_QUANTUM_TIER1_NS = (8ULL * 1000ULL * 1000ULL),
	/* Burst length that counts as short. */
	FLOW_SHORT_BOUND_NS = (1ULL * 1000ULL * 1000ULL),
	/* Short blocks that earn a move up. */
	FLOW_PROMOTE_STREAK = 3ULL,
	/* Upper bound of the block streak. */
	FLOW_STREAK_CAP = 7ULL,
	/* Interactive serves per batch serve. */
	FLOW_DEFICIT_SERVES = 8ULL,
	/* Shared DSQ of the batch tier. */
	FLOW_DSQ_BATCH = 0x2000ULL,
	/* Park DSQ for tasks with no target. */
	FLOW_DSQ_PARK = 0x2001ULL,
	/* Compile time bound of supported CPUs. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Lower bound of a per task estimate. */
	FLOW_EST_MIN_NS = 1ULL,
	/* Upper bound of a per task estimate. */
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	/* Minimum gap between busy preemptions. */
	FLOW_PREEMPT_GAP_NS = (1ULL * 1000ULL * 1000ULL),
	/* CPU hint of the interactive tier. */
	FLOW_CPUPERF_TIER0 = 1024ULL,
	/* CPU hint of the batch tier. */
	FLOW_CPUPERF_TIER1 = 0ULL,
	/* Bound of the moved tasks in one pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Unknown LLC id. Marks an empty table entry. */
	FLOW_LLC_UNKNOWN = 0xFFFFFFFFULL,
	/* Watchdog limit in milliseconds. */
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
};

/*
 * Per task state kept in task storage. The estimate
 * holds the last burst clamped to the estimate range
 * with no smoothing. The run stamp marks the start of
 * the current run. The grant holds the slice given at
 * insert time and is used to detect a full burn. The
 * vruntime orders batch tasks by service received. The
 * tier holds the current tier index. The streak counts
 * consecutive short voluntary blocks with saturation.
 */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 grant_ns;
	u64 vruntime;
	u32 tier;
	u32 streak;
};

/*
 * Per-CPU state kept in an array map. The running
 * estimate describes the task now on the CPU. The
 * running pid names the task now on the CPU. The
 * running tier names the tier of the task now on the
 * CPU. The served count tracks interactive serves
 * since the last batch serve for deficit control. The
 * preempt stamp gates busy preemptions to one per
 * gap.
 */
struct flow_cpu_state {
	u64 running_est;
	u32 running_pid;
	u32 running_tier;
	u64 served0;
	u64 last_preempt_at;
};

/*
 * Scheduler wide counters reported to userspace. The
 * insert counters count inserts per tier. The move
 * counters count tier changes in either direction. The
 * serve counters count runs per tier. The deficit
 * counter counts batch serves taken through the gated
 * path. The kick counter counts idle wakeups. The
 * preempt counter counts busy preemptions.
 */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 enq_tier0;
	u64 enq_tier1;
	u64 demotions;
	u64 promotions;
	u64 serves_tier0;
	u64 serves_tier1;
	u64 deficit_serves;
	u64 kicks;
	u64 preempts;
	u64 enq_no_tctx;
};

/*
 * Check that a tier index names a real tier. Used to
 * guard per tier array access.
 */
static __always_inline bool flow_tier_ok(u32 tier)
{
	return tier < (u32)FLOW_NTIERS;
}

/*
 * Fixed slice of one tier. Unknown tiers fall back to
 * the interactive slice, so the result stays usable.
 */
static __always_inline u64 flow_quantum_tier(u32 tier)
{
	if (tier == (u32)FLOW_TIER_BATCH)
		return (u64)FLOW_QUANTUM_TIER1_NS;
	return (u64)FLOW_QUANTUM_TIER0_NS;
}

/*
 * Clamp a per task estimate to the estimate range. The
 * floor keeps the value positive. The ceiling keeps a
 * single long run from shaping later choice.
 */
static __always_inline u64 flow_clamp_est(u64 v)
{
	if (v < (u64)FLOW_EST_MIN_NS)
		return (u64)FLOW_EST_MIN_NS;
	if (v > (u64)FLOW_EST_MAX_NS)
		return (u64)FLOW_EST_MAX_NS;
	return v;
}

/*
 * Check that a burst burned the full grant. A zero
 * grant never counts as burned, so a missing grant
 * holds the tier.
 */
static __always_inline bool flow_burned(u64 grant, u64 delta)
{
	if (grant == 0)
		return false;
	return delta >= grant;
}

/*
 * Check that a burst counts as short. Bursts below
 * the bound earn the streak. Bursts at or past the
 * bound reset the streak.
 */
static __always_inline bool flow_short(u64 delta)
{
	return delta < (u64)FLOW_SHORT_BOUND_NS;
}

/*
 * Next streak after one voluntary block. Short blocks
 * step forward with saturation at the cap. Long blocks
 * reset to zero.
 */
static __always_inline u32 flow_streak_next(u32 streak,
	u64 delta)
{
	if (!flow_short(delta))
		return 0;
	if (streak >= (u32)FLOW_STREAK_CAP)
		return (u32)FLOW_STREAK_CAP;
	return streak + 1;
}

/*
 * Check that a streak earns a move up. Streaks at or
 * past the bound earn the reward. Younger streaks
 * hold.
 */
static __always_inline bool flow_should_promote(u32 streak)
{
	return streak >= (u32)FLOW_PROMOTE_STREAK;
}

/*
 * Next tier after a run. A runnable task that burned
 * the full grant moves from interactive to batch. All
 * other tasks hold the tier.
 */
static __always_inline u32 flow_next_on_burn(u32 tier,
	bool runnable, bool burned)
{
	if (!runnable)
		return tier;
	if (!burned)
		return tier;
	if (tier == (u32)FLOW_TIER_INTERACTIVE)
		return (u32)FLOW_TIER_BATCH;
	return tier;
}

/*
 * Check that the batch tier may be served now. An
 * empty batch tier never serves. An empty interactive
 * tier serves batch at once. A busy interactive tier
 * serves batch only after enough interactive serves.
 */
static __always_inline bool flow_deficit_should_serve(
	u64 served0, bool tier0_backlog, bool tier1_backlog)
{
	if (!tier1_backlog)
		return false;
	if (!tier0_backlog)
		return true;
	return served0 >= (u64)FLOW_DEFICIT_SERVES;
}

/*
 * Next deficit count after one run. Batch runs reset
 * to zero. Interactive runs step forward with
 * saturation at the bound.
 */
static __always_inline u64 flow_deficit_next(u64 served0,
	u32 served_tier)
{
	if (served_tier == (u32)FLOW_TIER_BATCH)
		return 0;
	if (served0 >= (u64)FLOW_DEFICIT_SERVES)
		return (u64)FLOW_DEFICIT_SERVES;
	return served0 + 1;
}

/*
 * Check that one vruntime sorts before another. Used
 * to advance the floor with the smallest waiting
 * value.
 */
static __always_inline bool flow_vruntime_before(u64 a,
	u64 b)
{
	return a < b;
}

/*
 * Advance a vruntime by one burst with saturation. The
 * top value sticks, so a burst cannot wrap the order.
 */
static __always_inline u64 flow_vruntime_advance(u64 base,
	u64 delta)
{
	if (base > (u64)-1 - delta)
		return (u64)-1;
	return base + delta;
}

/*
 * Check that a busy preemption may be sent now. Gaps
 * at or past the bound allow the kick. Shorter gaps
 * hold the kick. A clock step back allows the kick, so
 * a skew never blocks progress for long.
 */
static __always_inline bool flow_preempt_gap_ok(u64 now,
	u64 last)
{
	u64 gap;

	if (now < last)
		return true;
	gap = now - last;
	return gap >= (u64)FLOW_PREEMPT_GAP_NS;
}

/*
 * CPU hint of one tier. Interactive asks for the
 * max level. Batch restores the default, so a
 * batch run never keeps the max hint. The hint is
 * fixed per tier and never uses frequency.
 */
static __always_inline u32 flow_cpuperf_tier(u32 tier)
{
	if (tier == (u32)FLOW_TIER_BATCH)
		return (u32)FLOW_CPUPERF_TIER1;
	return (u32)FLOW_CPUPERF_TIER0;
}

/*
 * Check that an LLC id names a real domain. The
 * unknown value marks an empty table entry and
 * fails open with no LLC step.
 */
static __always_inline bool flow_llc_known(u32 id)
{
	return id != (u32)FLOW_LLC_UNKNOWN;
}

/*
 * Check that the LLC step may run. Needs more than
 * one domain, so single and unknown hosts stay
 * plain with no extra scan.
 */
static __always_inline bool flow_llc_ok(u64 nr)
{
	return nr >= 2;
}

#endif
