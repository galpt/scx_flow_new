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
	/* Base id of the per cpu queues. */
	FLOW_DSQ_BASE = 0x1000ULL,
	/* Stride between the queues of one cpu. */
	FLOW_DSQ_STRIDE = 1ULL,
	/* Seed quantum of the global mean. */
	FLOW_QUANTUM_SEED_NS = (2ULL * 1000ULL * 1000ULL),
	/* Allowed range of the global quantum. */
	FLOW_QUANTUM_MIN_NS = (500ULL * 1000ULL),
	FLOW_QUANTUM_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Lower bound of a per task estimate. */
	FLOW_EST_MIN_NS = 1ULL,
	/* Upper bound of a per task estimate. */
	FLOW_EST_MAX_NS = (1ULL * 1000ULL * 1000ULL * 1000ULL),
	/* Bound of the remote scan in one dispatch pass. */
	FLOW_STEAL_SCAN_MAX = 64ULL,
	/* Bound of the moved tasks in one dispatch pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Watchdog limit in milliseconds. */
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	/* Compile time bound of supported cpus. */
	FLOW_MAX_CPUS = 1024ULL,
};

/*
 * Per task state kept in task storage. The estimate
 * is the last run length clamped to the estimate
 * range. The run stamp marks the start of the current
 * run. The accounted estimate describes the current
 * mean entry. The valid flag shows an entry is
 * present. The accounted cpu names the queue that
 * holds the depth count for the entry.
 */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 acct_est;
	u32 acct_valid;
	u32 acct_cpu;
};

/*
 * Per cpu state kept in an array map. The running
 * estimate describes the task now on the cpu. The
 * running pid names the task now on the cpu. The scan
 * offset rotates the steal scan start between passes.
 */
struct flow_cpu_state {
	u64 running_est;
	u32 running_pid;
	u32 scan_off;
};

/*
 * Scheduler wide counters reported to userspace. The
 * placement counter counts first inserts. The requeue
 * counter counts runnable requeues. The steal counter
 * counts remote moves. The dispatch counter counts
 * local and remote moves.
 */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 placements;
	u64 requeues;
	u64 steals;
	u64 dispatches;
	u64 enq_no_tctx;
};

/*
 * Queue id of a cpu. The layout is base plus cpu, so
 * the owning cpu decodes with plain arithmetic.
 */
static __always_inline u64 flow_dsq_id(u32 cpu)
{
	return (u64)FLOW_DSQ_BASE + (u64)cpu *
	    (u64)FLOW_DSQ_STRIDE;
}

/*
 * Clamp a quantum to the allowed range. Values below
 * the floor rise to the floor. Values above the
 * ceiling fall to the ceiling.
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
 * Seed quantum of the scheduler. The seed sits inside
 * the allowed range, so the clamp keeps it unchanged
 * while it guards later values.
 */
static __always_inline u64 flow_seed_quantum(void)
{
	return flow_clamp_quantum(
	    (u64)FLOW_QUANTUM_SEED_NS);
}

/*
 * Mean quantum over all accounted tasks. An empty set
 * keeps the last value. A zero last value falls back
 * to the seed, so the result is never zero.
 */
static __always_inline u64 flow_mean_quantum(u64 sum,
    u64 nr, u64 last)
{
	u64 mean;

	if (nr == 0) {
		if (last == 0)
			return flow_seed_quantum();
		return flow_clamp_quantum(last);
	}
	mean = sum / nr;
	return flow_clamp_quantum(mean);
}

/*
 * Live quantum from the global mean. A zero mean falls
 * back to the seed, so grants track the live mean
 * while the result stays in range.
 */
static __always_inline u64 flow_live_quantum(u64 mean)
{
	if (mean == 0)
		return flow_seed_quantum();
	return flow_clamp_quantum(mean);
}

/*
 * Ordered key from an estimate. Unknown estimates map
 * to the floor key and sort at the front. Known
 * estimates map to the clamped estimate and sort in
 * ascending order. Equal estimates share a key and
 * keep insert order.
 */
static __always_inline u64 flow_insert_key(u64 est)
{
	if (est == 0)
		return 0;
	return flow_clamp_est(est);
}

#endif
