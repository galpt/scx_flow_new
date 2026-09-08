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
	/* Number of feedback levels in the scheduler. */
	FLOW_NR_LEVELS = 3ULL,
	/* Base id of the per cpu per level queues. */
	FLOW_DSQ_BASE = 0x1000ULL,
	/* Stride between the queues of one cpu. */
	FLOW_DSQ_STRIDE = 3ULL,
	/* Seed quantum of each level. */
	FLOW_L0_QUANTUM_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_L1_QUANTUM_NS = (2ULL * 1000ULL * 1000ULL),
	FLOW_L2_QUANTUM_NS = (8ULL * 1000ULL * 1000ULL),
	/* Allowed range of a level quantum. */
	FLOW_QUANTUM_MIN_NS = (500ULL * 1000ULL),
	FLOW_QUANTUM_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Short name of the quantum floor. */
	FLOW_Q_MIN_NS = (500ULL * 1000ULL),
	/* Short name of the quantum ceiling. */
	FLOW_Q_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Lower bound of a per task estimate. */
	FLOW_EST_MIN_NS = 1ULL,
	/* Upper bound of a per task estimate. */
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	/* Bound of the remote scan in one dispatch pass. */
	FLOW_STEAL_SCAN_MAX = 64ULL,
	/* Bound of the top level steal checks. */
	FLOW_STEAL_L0 = 22ULL,
	/* Bound of the middle level steal checks. */
	FLOW_STEAL_L1 = 21ULL,
	/* Bound of the bottom level steal checks. */
	FLOW_STEAL_L2 = 21ULL,
	/* Bound of the moved tasks in one dispatch pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Bottom gets a slot every sixteen moves. */
	/* Paper order is batch static, online arrivals need guard. */
	FLOW_GUARANTEE_EVERY = 16ULL,
	/* Watchdog limit in milliseconds. */
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	/* Compile time bound of supported cpus. */
	FLOW_MAX_CPUS = 1024ULL,
};

/*
 * Per task state kept in task storage. The level is the
 * current feedback level. The estimate is the last run
 * length clamped to the estimate range. The run stamp
 * marks the start of the current run. The slice holds
 * the grant given at insert time. The accounted level
 * and estimate describe the current mean entry. The
 * valid flag shows an entry is present.
 */
struct flow_task_ctx {
	u32 level;
	u32 acct_level;
	u64 est_ns;
	u64 run_at;
	u64 slice_ns;
	u64 acct_est;
	u32 acct_valid;
	u32 pad;
};

/*
 * Per cpu state kept in an array map. The running level
 * and pid describe the task now on the cpu. The scan
 * offset rotates the steal scan start between passes.
 */
struct flow_cpu_state {
	s32 running_level;
	u32 running_pid;
	u32 scan_off;
	u32 pad;
};

/*
 * Scheduler wide counters reported to userspace. The
 * placement counters count inserts per level. The
 * demotion counter counts level moves down. The steal
 * counter counts remote moves. The dispatch counter
 * counts local and remote moves.
 */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 l0_placements;
	u64 l1_placements;
	u64 l2_placements;
	u64 demotions;
	u64 steals;
	u64 dispatches;
	u64 enq_no_tctx;
};

/*
 * Queue id of a cpu and level pair. The layout is base
 * plus cpu times stride plus level, so the owning cpu
 * and the level decode with plain arithmetic.
 */
static __always_inline u64 flow_dsq_id(u32 cpu, u32 level)
{
	return (u64)FLOW_DSQ_BASE +
	    (u64)cpu * (u64)FLOW_DSQ_STRIDE + (u64)level;
}

/*
 * Check that a level value names a real level. Used at
 * insert and dispatch time to guard map arithmetic.
 */
static __always_inline bool flow_level_ok(u32 level)
{
	return level < (u32)FLOW_NR_LEVELS;
}

/*
 * Clamp a quantum to the allowed range. Values below the
 * floor rise to the floor. Values above the ceiling fall
 * to the ceiling.
 */
static __always_inline u64 flow_clamp_quantum(u64 v)
{
	if (v < (u64)FLOW_QUANTUM_MIN_NS)
		return (u64)FLOW_QUANTUM_MIN_NS;
	if (v > (u64)FLOW_QUANTUM_MAX_NS)
		return (u64)FLOW_QUANTUM_MAX_NS;
	return v;
}

/*
 * Clamp a per task estimate to the estimate range. The
 * floor keeps the value positive. The ceiling keeps a
 * single long run from dominating later decisions.
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
 * Seed quantum of a level. The seeds sit inside the
 * allowed range, so the clamp keeps them unchanged
 * while it guards later values.
 */
static __always_inline u64 flow_seed_for_level(u32 level)
{
	u64 v;

	if (level == 0)
		v = (u64)FLOW_L0_QUANTUM_NS;
	else if (level == 1)
		v = (u64)FLOW_L1_QUANTUM_NS;
	else
		v = (u64)FLOW_L2_QUANTUM_NS;
	return flow_clamp_quantum(v);
}

/*
 * Mean quantum of a level. An empty level keeps the
 * last value. A zero last value falls back to the
 * seed, so the result is never zero.
 */
static __always_inline u64 flow_mean_quantum(u32 level,
    u64 sum, u64 nr, u64 last)
{
	u64 mean;

	if (nr == 0) {
		if (last == 0)
			return flow_seed_for_level(level);
		return flow_clamp_quantum(last);
	}
	mean = sum / nr;
	return flow_clamp_quantum(mean);
}

/*
 * Live quantum of a level. The value comes from the
 * caller supplied means, so grants track the live
 * means. A zero entry falls back to the seed.
 */
static __always_inline u64 flow_quantum_for_level(u32 level,
    const volatile u64 *means)
{
	u64 v;

	if (!flow_level_ok(level))
		level = 0;
	if (!means)
		return flow_seed_for_level(level);
	v = means[level];
	if (v == 0)
		return flow_seed_for_level(level);
	return flow_clamp_quantum(v);
}

/*
 * Pick a level from an estimate. Unknown estimates go
 * to the top. Known estimates use the first level with
 * a live mean at or above the estimate. Large estimates
 * fall to the bottom.
 */
static __always_inline u32 flow_pick_level(u64 est,
    const volatile u64 *means)
{
	u64 q0;
	u64 q1;

	if (est == 0)
		return 0;
	est = flow_clamp_est(est);
	q0 = flow_quantum_for_level(0, means);
	if (est <= q0)
		return 0;
	q1 = flow_quantum_for_level(1, means);
	if (est <= q1)
		return 1;
	return 2;
}

/*
 * Initial level of a new task. Every task starts at the
 * top level and moves down only.
 */
static __always_inline u32 flow_initial_level(void)
{
	return 0;
}

/*
 * Next level after a full slice was consumed. The bottom
 * level stays at the bottom. There is no move up.
 */
static __always_inline u32 flow_next_level(u32 level)
{
	if (level >= (u32)FLOW_NR_LEVELS - 1)
		return (u32)FLOW_NR_LEVELS - 1;
	return level + 1;
}

#endif
