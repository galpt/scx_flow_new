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

/* Time and queue bounds used across the scheduler. */
enum flow_consts {
	/* Lower bound of a per task estimate. */
	FLOW_EST_MIN_NS = 1ULL,
	/* Upper bound of a per task estimate. */
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	/* Seed of a per CPU mean when no task is present. */
	FLOW_TQ_SEED_NS = (8ULL * 1000ULL * 1000ULL),
	/* Floor of a per CPU mean. */
	FLOW_TQ_MIN_NS = (500ULL * 1000ULL),
	/* Ceiling of a per CPU mean. */
	FLOW_TQ_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Compile time bound of supported CPUs. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Base id of the per CPU ordered queues. */
	FLOW_DSQ_BASE = 0x4000ULL,
	/* Park id for tasks with no allowed CPU. */
	FLOW_DSQ_PARK = 0x5000ULL,
	/* Bound of moved tasks in one pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Bound of peers visited by one steal scan. */
	FLOW_STEAL_BOUND = 8ULL,
	/* Unknown LLC id. Marks an empty table entry. */
	FLOW_LLC_UNKNOWN = 0xFFFFFFFFULL,
	/* Watchdog limit in milliseconds. */
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	/* Hint used for short estimates. */
	FLOW_CPUPERF_SHORT = 1024ULL,
	/* Hint used for long estimates. */
	FLOW_CPUPERF_LONG = 0ULL,
};

/*
 * Per task state kept in task storage. The estimate
 * holds the last burst clamped to the estimate range
 * with no smoothing. The run stamp marks the start of
 * the current run. The grant holds the slice given at
 * insert time. The owner names the CPU that accounts
 * the task in its mean.
 */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 grant_ns;
	u32 owner;
	u32 pad;
};

/*
 * Per CPU state kept in an array map. The mean holds
 * the current slice for the CPU. The sum and the count
 * hold the unfinished work including the running task.
 * The cursor rotates the steal scan. The running view
 * describes the task now on the CPU.
 */
struct flow_cpu_state {
	u64 tq_ns;
	u64 sum_est;
	u64 nr;
	u64 cursor;
	u64 running_est;
	u32 running_pid;
	u32 pad;
};

/*
 * Scheduler wide counters reported to userspace. The
 * insert count covers fresh joins. The requeue count
 * covers runnable completions of a slice. The done
 * count covers voluntary blocks and exits. The park
 * count covers moves from the park queue. The steal
 * count covers moves from a peer queue. The kick count
 * covers idle wakeups.
 */
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
};

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
 * Clamp a per CPU mean to the mean range. The floor
 * keeps short means usable. The ceiling keeps long
 * means bounded.
 */
static __always_inline u64 flow_clamp_tq(u64 v)
{
	if (v < (u64)FLOW_TQ_MIN_NS)
		return (u64)FLOW_TQ_MIN_NS;
	if (v > (u64)FLOW_TQ_MAX_NS)
		return (u64)FLOW_TQ_MAX_NS;
	return v;
}

/*
 * Mean of one CPU from sum and count. An empty CPU
 * uses the seed. A populated CPU uses the quotient
 * clamped to the mean range.
 */
static __always_inline u64 flow_mean_tq(u64 sum, u64 nr)
{
	u64 mean;

	if (nr == 0)
		return (u64)FLOW_TQ_SEED_NS;
	mean = sum / nr;
	return flow_clamp_tq(mean);
}

/*
 * Queue id of one CPU. Callers check the id range
 * before use, so out of range ids stay local.
 */
static __always_inline u64 flow_dsq_for_cpu(u32 cpu)
{
	return (u64)FLOW_DSQ_BASE + (u64)cpu;
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

/*
 * Hint for one estimate against the mean. Short
 * estimates ask for the high hint. Long estimates
 * restore the low hint. The choice uses only the
 * estimate and the mean.
 */
static __always_inline u32 flow_cpuperf_for_est(u64 est,
	u64 tq)
{
	if (est <= tq)
		return (u32)FLOW_CPUPERF_SHORT;
	return (u32)FLOW_CPUPERF_LONG;
}

/*
 * Next peer for a steal scan. The cursor rotates, so
 * repeated scans spread across peers.
 */
static __always_inline u32 flow_steal_next(u32 cursor,
	u32 nr_cpus)
{
	if (nr_cpus == 0)
		return 0;
	return (cursor + 1) % nr_cpus;
}

#endif
