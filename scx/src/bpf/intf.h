// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each LLC has four queues ordered by virtual time. Ties leave in
 * insertion order. One fallback queue holds tasks that have no
 * usable CPU. Pinned tasks run on their local queue. Shares are
 * read from the cgroup map on each enqueue. A task pays for the
 * time it burns, scaled by its share, with a small extra amount
 * added per quantum. Fresh virtual times move past a per LLC floor
 * so two tasks never share the same value. Tasks judged latency
 * sensitive queue slightly earlier, while the stored time is left
 * unchanged. A burst estimate tracks recent run time and selects
 * the queue. Slices hold one fixed quantum. Tasks
 * that wait long have their estimate halved. The graphics
 * hint keeps tasks near their previous CPU. It does not change
 * ordering by itself. Wait history keeps per CPU queue waits by
 * kind and bucket with slice based edges. Kinds cover shared
 * queues plus pinned plus exiting plus fallback plus early plus
 * unknown. Buckets split waits by length with slice fractions
 * and multiples. The task tail holds the wait kind for the next
 * observe step. The wait table is sized for every CPU with run
 * plus dispatch halves.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
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
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif
enum flow_consts {
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_MAX_LLCS = 64ULL,
	FLOW_MAX_NODES = 8ULL,
	FLOW_PRIO_COUNT = 4ULL,
	FLOW_PRIO_LAT = 0ULL,
	FLOW_PRIO_NORM = 1ULL,
	FLOW_PRIO_BATCH = 2ULL,
	FLOW_PRIO_IDLE = 3ULL,
	FLOW_SLICE_MIN_NS = 3000000ULL,
	FLOW_EXIT_SLICE_NS = 1000ULL,
	FLOW_FAIR_BASE_NS = 20000ULL,
	FLOW_FAIR_EXTRA_NS = 1000ULL,
	FLOW_LAT_OFF_NS = 3000000ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_SJF_INIT_NS = 3000000ULL,
	FLOW_SJF_FLOOR_NS = 5000ULL,
	FLOW_SJF_CAP_NS = 1000000000ULL,
	FLOW_AGING_NS = 100000000ULL,
	FLOW_STARVE_NS = 200000000ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_LLC_BASE = 0x6000ULL,
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	FLOW_FLAG_QUEUED = 1ULL,
	FLOW_LAT_KINDS = 9ULL,
	FLOW_LAT_BUCKETS = 8ULL,
	FLOW_HIST_LEN = 144ULL,
	FLOW_LAT_LAT = 0ULL,
	FLOW_LAT_NORM = 1ULL,
	FLOW_LAT_BATCH = 2ULL,
	FLOW_LAT_IDLE = 3ULL,
	FLOW_LAT_PINNED = 4ULL,
	FLOW_LAT_EXITING = 5ULL,
	FLOW_LAT_FALLBACK = 6ULL,
	FLOW_LAT_OTHER = 7ULL,
	FLOW_LAT_UNKNOWN = 8ULL,
};
/* Per task state. Vtime is charged service. Slice holds the time
 * left in the current quantum. Gen identifies the running instance.
 * Llc records the last enqueue target. Flags holds the queued bit.
 * Prio holds the selected queue. Burst holds the recent run time
 * estimate. Enq holds the last enqueue time. Cgrp holds the group
 * id and share hint. A zero id means no group was recorded. Gpu
 * holds a placement hint. Lat holds the wait kind for history. */
struct flow_task_ctx {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	u32 prio;
	u32 cg_weight;
	u64 cgrp_id;
	u64 burst_ns;
	u64 enq_ns;
	u32 gpu_hint;
	u32 lat_kind;
};
/* Wait history for one CPU. Cells hold run waits then dispatch
 * waits by kind times bucket. The length covers two halves of
 * kinds times buckets. */
struct flow_lat_hist {
	u64 cells[FLOW_HIST_LEN];
};
/* Per CPU running view. Gen counts runs. Reserved stays
 * zero. Prio mirrors the running task. */
struct flow_running_state {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 prio;
	u32 reserved;
	u32 pad;
};
/* Per CPU seed from userspace. Holds the CPU id and the LLC and
 * node indices assigned at startup. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 pad;
};
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts idle and skipped wakes with the preempt count staying
 * zero. Overrun counts full
 * slice burns. Penalty and extra record the charge for those burns,
 * and total records the quanta granted. Blocked counts stops that
 * leave the task runnable. Escape stays zero. Orphan
 * counts mask change kicks. Forward counts heads passed to their
 * owner. Boost and hold describe the queue choice. The latency win
 * count stays zero. Rescue counts aged waits. */
struct flow_llc_stats {
	u64 queued;
	u64 dispatched;
	u64 fallback;
	u64 steal;
	u64 fb_duplicate;
	u64 steal_llc;
	u64 kick_preempt;
	u64 kick_idle;
	u64 kick_skip;
	u64 overrun;
	u64 domino_penalty;
	u64 blocked;
	u64 hog_escape;
	u64 orphan_kick;
	u64 hol_forward;
	u64 lat_boost;
	u64 hog_hold;
	u64 lat_preempt;
	u64 age_rescue;
	u64 extra_award;
	u64 total_quanta;
};
#ifdef __BPF__
static __always_inline u64 flow_llc_dsq_prio(u32 llc, u32 prio)
{
	return (u64)FLOW_LLC_BASE + (u64)llc * (u64)FLOW_PRIO_COUNT + (u64)prio;
}
static __always_inline bool flow_llc_ok(u32 llc)
{
	return llc < (u32)FLOW_MAX_LLCS;
}
static __always_inline bool flow_cpu_ok(u32 cpu)
{
	return cpu < (u32)FLOW_MAX_CPUS;
}
static __always_inline bool flow_node_ok(u32 node)
{
	return node < (u32)FLOW_MAX_NODES;
}
static __always_inline bool flow_prio_ok(u32 prio)
{
	return prio < (u32)FLOW_PRIO_COUNT;
}
static __always_inline bool flow_dsq_ok(u64 dsq)
{
	return (dsq >= (u64)FLOW_LLC_BASE &&
		dsq < (u64)FLOW_LLC_BASE + (u64)FLOW_MAX_LLCS * (u64)FLOW_PRIO_COUNT) ||
	       dsq == (u64)FLOW_FALLBACK_DSQ;
}
#endif
#endif
