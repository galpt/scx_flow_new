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
	/* Seed of a per-CPU mean when no task is present. */
	FLOW_TQ_SEED_NS = (8ULL * 1000ULL * 1000ULL),
	/* Floor of a per-CPU mean. */
	FLOW_TQ_MIN_NS = (500ULL * 1000ULL),
	/* Ceiling of a per-CPU mean. */
	FLOW_TQ_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Compile time bound of supported CPUs. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Base id of the per-CPU ordered queues. */
	FLOW_DSQ_BASE = 0x4000ULL,
	/* Park id for tasks with no allowed CPU. */
	FLOW_DSQ_PARK = 0x5000ULL,
	/* Bound of moved tasks in one pass. */
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	/* Cap of shed tasks in park at twice one batch. */
	FLOW_SHED_PARK_MAX = 64ULL,
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
	/* Cap of one sample in mean accounting. */
	FLOW_ACCT_MAX_NS = (32ULL * 1000ULL * 1000ULL),
	/* Fixed weight used for virtual time scaling. */
	FLOW_WEIGHT = 1024ULL,
	/* Least donor depth that allows a steal. */
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	/* Batch window for sticky batching in nanos. */
	FLOW_IEDF_BATCH_EPS_NS = (96ULL * 1000ULL),
	/* Grace after deadline in nanos for accounting. */
	FLOW_IEDF_GRACE_NS = (50ULL * 1000ULL),
};

/*
 * Gating flags for the new paths. Each flag keeps one
 * path enabled when set. Setting a flag to zero
 * reverts that path alone with no effect on the rest.
 */
enum flow_gates {
	/* Tighter per sample cap for accounting. */
	FLOW_GATE_CLAMP = 1ULL,
	/* Sticky placement with guarded steals. */
	FLOW_GATE_STICKY = 1ULL,
	/* Idle gated kicks with equal skip. */
	FLOW_GATE_CUTS = 1ULL,
	/* Incremental EDF batching with grace and shed. */
	FLOW_GATE_IEDF = 1ULL,
};

/*
 * Per task state kept in task storage. The estimate
 * holds the last burst clamped to the estimate range
 * with no smoothing. The run stamp marks the start of
 * the current run. The grant holds the slice given at
 * insert time. The owner names the CPU that accounts
 * the task in its mean. The virtual time orders fair
 * sharing across sleeps with a bounded lag. The
 * deadline orders the kernel queue with no extra heap.
 */
struct flow_task_ctx {
	u64 est_ns;
	u64 run_at;
	u64 grant_ns;
	u32 owner;
	u32 pad;
	u64 vruntime;
	u64 deadline;
};

/*
 * Per-CPU state kept in an array map. The mean holds
 * the current slice for the CPU. The sum and the count
 * hold the unfinished work including the running task.
 * The cursor rotates the steal scan. The running view
 * describes the task now on the CPU. The frontier
 * tracks virtual time with monotonic growth while work
 * stays queued.
 */
struct flow_cpu_state {
	u64 tq_ns;
	u64 sum_est;
	u64 nr;
	u64 cursor;
	u64 running_est;
	u32 running_pid;
	u32 pad;
	u64 frontier;
};

/*
 * Scheduler wide counters reported to userspace. The
 * insert count covers fresh joins. The requeue count
 * covers runnable completions of a slice. The done
 * count covers voluntary blocks and exits. The park
 * count covers moves from the park queue. The steal
 * count covers moves from a peer queue. The kick count
 * covers idle wakeups. The fast count stays zero for
 * compat with no fast path. The linger count stays
 * zero for compat with no linger path. The reuse count
 * stays zero for compat with no reuse count. The EDF
 * counts cover ordered inserts with clamp detail.
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
	u64 fast_hits;
	u64 linger_boosts;
	u64 reuse_hits;
	u64 edf_enqueued;
	u64 edf_clamped;
	u64 edf_ordered;
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
 * Cap one sample for mean accounting. The deadline
 * keeps the full clamped estimate. The accounting
 * value keeps the tighter cap, so a single long run
 * never moves the mean by more than the cap.
 */
static __always_inline u64 flow_clamp_acct(u64 v)
{
	u64 e = flow_clamp_est(v);

	if (e > (u64)FLOW_ACCT_MAX_NS)
		return (u64)FLOW_ACCT_MAX_NS;
	return e;
}

/*
 * Clamp a per-CPU mean to the mean range. The floor
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
 * Scale an estimate by weight for virtual time. The
 * fixed weight keeps the value unchanged while the
 * signature allows future weights with no call change.
 */
static __always_inline u64 flow_scale_by_weight(u64 est,
	u32 weight)
{
	if (weight == 0)
		return est;
	if (weight == (u32)FLOW_WEIGHT)
		return est;
	return (est * 1024ULL) / (u64)weight;
}

/*
 * True when the first time is before the second with
 * wrap safety. The signed diff keeps order across the
 * u64 wrap with no extra branch.
 */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}

/*
 * Clamp virtual time to a bounded lag behind the
 * frontier. The floor is the frontier minus one slice
 * with wrap. A lagging value moves forward to the
 * floor with a clamp count. A fresh value stays.
 */
static __always_inline u64 flow_clamp_vruntime(u64 v,
	u64 frontier, u64 slice)
{
	u64 floor = frontier - slice;

	if (flow_time_before(v, floor))
		return floor;
	return v;
}

/*
 * Deadline from clamped virtual time and scaled
 * estimate. The sum wraps with the clock with no
 * extra check, so order stays correct across wrap.
 */
static __always_inline u64 flow_deadline(u64 clamped_v,
	u64 scaled)
{
	return clamped_v + scaled;
}

/*
 * Advance virtual time by scaled runtime. The sum
 * wraps with the clock, so long runs stay ordered
 * across wrap with no extra check.
 */
static __always_inline u64 flow_vruntime_add(u64 v,
	u64 delta)
{
	return v + delta;
}

/*
 * Max of two virtual times with wrap safety. The later
 * time wins, so the frontier never moves backward
 * while work stays queued.
 */
static __always_inline u64 flow_frontier_max(u64 old,
	u64 next)
{
	if (flow_time_before(old, next))
		return next;
	return old;
}

/*
 * Frontier for an idle CPU from the waking virtual
 * time. The waking value bounds the reset with no
 * zero use, so a new arrival never inherits stale
 * time while queued work never moves backward.
 */
static __always_inline u64 flow_frontier_idle(u64 waking_v)
{
	return waking_v;
}

/*
 * True when two deadlines fall in one batch window.
 * The window is tiny against the mean floor, so a
 * batch keeps cache warmth with no fair loss. Wrap
 * safe with unsigned distance and no signed negate.
 */
static __always_inline bool flow_batch_within(u64 a,
	u64 b)
{
	u64 d = a >= b ? a - b : b - a;

	return d <= (u64)FLOW_IEDF_BATCH_EPS_NS;
}

/*
 * True when now is still within grace past deadline.
 * Grace is tiny against the least period, so late
 * accounting stays prompt with no kill. The harness
 * cancels, the scheduler never kills. Wrap safe with
 * no extra branch beyond the before check.
 */
static __always_inline bool flow_grace_ok(u64 now,
	u64 deadline)
{
	u64 limit = deadline + (u64)FLOW_IEDF_GRACE_NS;

	if (now == limit)
		return true;
	return flow_time_before(now, limit);
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
