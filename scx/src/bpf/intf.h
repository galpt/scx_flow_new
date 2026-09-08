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
	/* Count of queues kept for each cpu. */
	FLOW_NQUEUES = 3ULL,
	/* Base id of the per cpu queues. */
	FLOW_DSQ_BASE = 0x1000ULL,
	/* Stride between the queues of one cpu. */
	FLOW_DSQ_STRIDE = 3ULL,
	/* Compile time bound of supported cpus. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Base id of the park queues, one per queue. */
	FLOW_PARK_BASE = (0x1000ULL + 1024ULL * 3ULL),
	/* Floor of the first queue quantum. */
	FLOW_QUANTUM_MIN0_NS = (500ULL * 1000ULL),
	/* Ceiling of the first queue quantum. */
	FLOW_QUANTUM_MAX0_NS = (4ULL * 1000ULL * 1000ULL),
	/* Seed of the first queue quantum. */
	FLOW_QUANTUM_SEED0_NS = (1ULL * 1000ULL * 1000ULL),
	/* Floor of the second queue quantum. */
	FLOW_QUANTUM_MIN1_NS = (1ULL * 1000ULL * 1000ULL),
	/* Ceiling of the second queue quantum. */
	FLOW_QUANTUM_MAX1_NS = (8ULL * 1000ULL * 1000ULL),
	/* Seed of the second queue quantum. */
	FLOW_QUANTUM_SEED1_NS = (2ULL * 1000ULL * 1000ULL),
	/* Floor of the third queue quantum. */
	FLOW_QUANTUM_MIN2_NS = (4ULL * 1000ULL * 1000ULL),
	/* Ceiling of the third queue quantum. */
	FLOW_QUANTUM_MAX2_NS = (32ULL * 1000ULL * 1000ULL),
	/* Seed of the third queue quantum. */
	FLOW_QUANTUM_SEED2_NS = (8ULL * 1000ULL * 1000ULL),
	/* Lower bound of a per task estimate. */
	FLOW_EST_MIN_NS = 1ULL,
	/* Upper bound of a per task estimate. */
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	/* Head age that lifts a queue past strict order. */
	FLOW_PROMOTE_AGE_NS = (500ULL * 1000ULL * 1000ULL),
	/* Bound of the remote scan in one dispatch pass. */
	FLOW_STEAL_SCAN_MAX = 64ULL,
	/* Bound of the moved tasks in one dispatch pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Watchdog limit in milliseconds. */
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
};

/*
 * Per task state kept in task storage. The estimate
 * holds the last burst clamped to the estimate range
 * with no smoothing. The run stamp marks the start of
 * the current run. The slice holds the granted quantum
 * used to detect a full burn. The queue holds the
 * current queue index. The accounted fields describe
 * the live mean entry. The valid flag shows an entry
 * is present.
 */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 slice_ns;
	u64 acct_est;
	u32 queue;
	u32 acct_cpu;
	u32 acct_queue;
	u32 acct_valid;
};

/*
 * Per cpu state kept in an array map. The running
 * estimate describes the task now on the cpu. The
 * running pid names the task now on the cpu. The
 * running queue names the queue of the task now on
 * the cpu. The scan offset rotates the steal scan
 * start between passes.
 */
struct flow_cpu_state {
	u64 running_est;
	u32 running_pid;
	u32 running_queue;
	u32 scan_off;
	u32 __pad;
};

/*
 * Scheduler wide counters reported to userspace. The
 * placement arrays count first inserts per queue. The
 * demotion arrays count moves down from one queue. The
 * promotion arrays count moves up from one queue. The
 * requeue counter counts runnable requeues. The steal
 * counter counts remote moves. The dispatch counter
 * counts local and remote moves. The kick counter
 * counts idle wakeup kicks sent after insert.
 */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 placements[3];
	u64 demotions[3];
	u64 promotions[3];
	u64 requeues;
	u64 steals;
	u64 dispatches;
	u64 kicks;
	u64 enq_no_tctx;
};

/*
 * Queue id of a cpu and queue pair. The layout is base
 * plus cpu times stride plus queue, so the owning cpu
 * and the queue decode with plain arithmetic.
 */
static __always_inline u64 flow_dsq_id(u32 cpu,
    u32 queue)
{
	return (u64)FLOW_DSQ_BASE + (u64)cpu *
	    (u64)FLOW_DSQ_STRIDE + (u64)queue;
}

/*
 * Queue id of a park queue. The park holds tasks with
 * no allowed cpu. One park queue exists per queue.
 */
static __always_inline u64 flow_park_id(u32 queue)
{
	return (u64)FLOW_PARK_BASE + (u64)queue;
}

/*
 * Check that a queue index names a real queue. Used to
 * guard per queue array access.
 */
static __always_inline bool flow_queue_ok(u32 queue)
{
	return queue < (u32)FLOW_NQUEUES;
}

/*
 * Floor of one queue quantum. Unknown queues fall back
 * to the first floor, so the result is never zero.
 */
static __always_inline u64 flow_quantum_min(u32 queue)
{
	if (queue == 1)
		return (u64)FLOW_QUANTUM_MIN1_NS;
	if (queue == 2)
		return (u64)FLOW_QUANTUM_MIN2_NS;
	return (u64)FLOW_QUANTUM_MIN0_NS;
}

/*
 * Ceiling of one queue quantum. Unknown queues fall
 * back to the first ceiling, so the result stays sane.
 */
static __always_inline u64 flow_quantum_max(u32 queue)
{
	if (queue == 1)
		return (u64)FLOW_QUANTUM_MAX1_NS;
	if (queue == 2)
		return (u64)FLOW_QUANTUM_MAX2_NS;
	return (u64)FLOW_QUANTUM_MAX0_NS;
}

/*
 * Seed of one queue quantum. Unknown queues fall back
 * to the first seed, so the result stays in range.
 */
static __always_inline u64 flow_quantum_seed(u32 queue)
{
	if (queue == 1)
		return (u64)FLOW_QUANTUM_SEED1_NS;
	if (queue == 2)
		return (u64)FLOW_QUANTUM_SEED2_NS;
	return (u64)FLOW_QUANTUM_SEED0_NS;
}

/*
 * Clamp a quantum of one queue to the queue range. Low
 * values rise to the floor. High values fall to the
 * ceiling.
 */
static __always_inline u64 flow_clamp_quantum(u32 queue,
    u64 v)
{
	u64 lo = flow_quantum_min(queue);
	u64 hi = flow_quantum_max(queue);

	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
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
 * Seed quantum of one queue. The seed sits inside the
 * queue range, so the clamp keeps it unchanged while
 * it guards later values.
 */
static __always_inline u64 flow_seed_quantum(u32 queue)
{
	return flow_clamp_quantum(queue,
	    flow_quantum_seed(queue));
}

/*
 * Mean quantum of one queue over accounted tasks. An
 * empty set keeps the last value. A zero last value
 * falls back to the seed, so the result is never zero.
 */
static __always_inline u64 flow_mean_quantum(u32 queue,
    u64 sum, u64 nr, u64 last)
{
	u64 mean;

	if (nr == 0) {
		if (last == 0)
			return flow_seed_quantum(queue);
		return flow_clamp_quantum(queue, last);
	}
	mean = sum / nr;
	return flow_clamp_quantum(queue, mean);
}

/*
 * Live quantum of one queue from its mean. A zero mean
 * falls back to the seed, so grants track the live
 * mean while the result stays in range.
 */
static __always_inline u64 flow_live_quantum(u32 queue,
    u64 mean)
{
	if (mean == 0)
		return flow_seed_quantum(queue);
	return flow_clamp_quantum(queue, mean);
}

/*
 * Check that a burst burned the full slice. A zero
 * slice never counts as burned, so a missing grant
 * holds the queue.
 */
static __always_inline bool flow_burned(u64 slice,
    u64 delta)
{
	if (slice == 0)
		return false;
	return delta >= slice;
}

/*
 * Next queue after a run. A runnable task that burned
 * the full slice moves down one queue. All other tasks
 * hold the queue. The bottom queue holds as well.
 */
static __always_inline u32 flow_next_on_burn(u32 queue,
    bool runnable, bool burned)
{
	if (!runnable)
		return queue;
	if (!burned)
		return queue;
	if (queue + 1 < (u32)FLOW_NQUEUES)
		return queue + 1;
	return queue;
}

/*
 * Check that a head age earns a move up. Ages at or
 * past the bound earn the reward. Younger ages hold.
 */
static __always_inline bool flow_should_promote(u64 age)
{
	return age >= (u64)FLOW_PROMOTE_AGE_NS;
}

/*
 * Next queue after the age check. An aged queue moves
 * up one queue. All other queues hold. The first queue
 * holds as well.
 */
static __always_inline u32 flow_promote_if_aged(u32 queue,
    u64 age)
{
	if (!flow_should_promote(age))
		return queue;
	if (queue == 0)
		return queue;
	return queue - 1;
}

#endif
