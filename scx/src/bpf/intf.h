// SPDX-License-Identifier: GPL-2.0
/*
 * Shared ABI for the flow scheduler.
 *
 * Queues are one per LLC plus one fallback queue. The kernel orders
 * each queue by virtual time, with equal times leaving in insertion
 * order. Stats are per LLC counters read by the userspace monitor.
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
#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#endif
enum flow_consts {
	/* Array bound for tables keyed by CPU. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Array bound for tables keyed by LLC. */
	FLOW_MAX_LLCS = 64ULL,
	/* Array bound for tables keyed by node. */
	FLOW_MAX_NODES = 8ULL,
	/* Fixed time slice in nanos. */
	FLOW_SLICE_NS = 1000000ULL,
	/* Slice for exiting tasks in nanos. Exit only releases */
	/* resources, so a small slice keeps teardown cheap. */
	FLOW_EXIT_SLICE_NS = 1000ULL,
	/* Streak length that turns an idle wake into a preempt. */
	FLOW_STREAK_MAX = 4ULL,
	/* Preempt gap in nanos. */
	FLOW_PREEMPT_THRESH = 500000ULL,
	/* Preempt tail guard in nanos. A target with less slice */
	/* left than this is left alone. */
	FLOW_PREEMPT_TAIL = 125000ULL,
	/* Latency offset in nanos. A latency task is queued one */
	/* slice ahead of the same raw time. Stored time is */
	/* unaffected, so the shift applies once per enqueue. */
	FLOW_LAT_OFF_NS = 1000000ULL,
	/* Ops timeout in ms for the watchdog. */
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Base DSQ id for per LLC queues. The LLC index adds to the base. */
	FLOW_LLC_BASE = 0x6000ULL,
	/* Fallback DSQ id used when no LLC target is available. */
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	/* Queued bit in task flags. Set on enqueue, cleared on running */
	/* and dequeue. A set bit drops a second enqueue of the same task. */
	FLOW_FLAG_QUEUED = 1ULL,
	/* Cgroup weight range. Zero is not a valid weight and reads */
	/* as the default. */
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	/* Extra quanta bound. A run lasts one base quantum plus */
	/* zero through two extra quanta. */
	FLOW_MAX_QUANTA = 3ULL,
	FLOW_MAX_EXTRA = 2ULL,
	/* Score bands. Four bands of width twenty five cover the */
	/* zero through one hundred scale. The raw burn hint has five */
	/* steps, with only the top step counting as a full burn. */
	FLOW_SCORE_BANDS = 4ULL,
	FLOW_SCORE_WIDTH = 25ULL,
	FLOW_SCORE_LEVELS = 3ULL,
	FLOW_SCORE_RAW_MAX = 4ULL,
	/* Score scale top. The top band engages at seventy five and */
	/* releases below fifty. The wide cap bounds the blend sum */
	/* before clamping. */
	FLOW_SCORE_HMAX = 100ULL,
	FLOW_SCORE_Q = 25ULL,
	FLOW_SCORE_ENGAGE = 75ULL,
	FLOW_SCORE_RELEASE = 50ULL,
	FLOW_SCORE_N = 8ULL,
	FLOW_SCORE_MAX = 400ULL,
};
/* Per task state held for the life of the task. Hist keeps the last */
/* three stop outcomes, with a set bit for an early yield and a clear */
/* bit for a full burn. Pad carries the last award length and the hold */
/* level. Cgrp carries the weight share hint. Enq holds the last */
/* enqueue time, with zero meaning never queued. */
struct flow_task_ctx {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	u8 hist3;
	u8 pad[3];
	u64 cgrp_id;
	u32 cg_weight;
	u32 pad2;
	u64 enq_ns;
};
/* Per CPU running snapshot used for the preempt compare. Hog streak */
/* counts consecutive full burns on this CPU. Lat marks a latency */
/* task with one, else zero. Zero generation means empty. */
struct flow_running_state {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u32 llc_id;
	u32 pad;
	u64 gen;
	u32 hog_streak;
	u8 lat;
	u8 __rsvd[3];
};
/* Per CPU frequency hint state. Last holds the prior sample time. */
/* Level holds the smoothed ratio. Hist keeps the last four raw */
/* samples for post mortem sizing. The hint never steers placement. */
struct flow_freq_state {
	u64 last;
	u64 level;
	u64 hist[4];
};
/* Per CPU burn score. Score spans zero through one hundred. Prev */
/* holds the last award level. Growth and decay counts are kept */
/* apart so each path stays visible. Each CPU keeps its own row. */
struct flow_extra_state {
	u64 score;
	u64 prev_extra;
	u64 n_growth;
	u64 n_decay;
};
/* Per CPU view seeded once from userspace. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 pad;
};
/* Per LLC counters. Queued counts inserts, dispatched counts moves */
/* to the local queue, fallback counts fallback queue inserts plus */
/* duplicate drops, steal counts remote LLC moves. Duplicate counts */
/* requeues dropped by the queued guard. Steal split counts remote */
/* moves again on the thief. Kick split counts preempt, idle, and */
/* skipped wakes. Overrun counts full slice burns, penalty counts */
/* the extra slice charged for each. Blocked counts stops that leave */
/* the task runnable. Escape counts streak preempts. Orphan counts */
/* mask change kicks. Forward counts head forwards to the owner. */
/* Boost counts latency takes, hold counts hog keeps, preempt counts */
/* latency preempt wins, rescue counts aged out holds. Extra holds */
/* q minus one, total holds q. Twenty one counters, 168 bytes. */
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
/* Band relations checked at compile time. Bands times width meets */
/* the top, levels meet max extra plus one, engage spans three */
/* widths, release spans two, the wide cap bounds the blend sum. */
_Static_assert((unsigned long long)FLOW_SCORE_BANDS * (unsigned long long)FLOW_SCORE_WIDTH == (unsigned long long)FLOW_SCORE_HMAX,
	       "bands times width equals top");
_Static_assert((unsigned long long)FLOW_SCORE_LEVELS == (unsigned long long)FLOW_MAX_EXTRA + 1ULL,
	       "levels equal max extra plus one");
_Static_assert((unsigned long long)FLOW_SCORE_Q == (unsigned long long)FLOW_SCORE_WIDTH,
	       "middle edge equals width");
_Static_assert((unsigned long long)FLOW_SCORE_ENGAGE == 3ULL * (unsigned long long)FLOW_SCORE_WIDTH,
	       "engage is three widths");
_Static_assert((unsigned long long)FLOW_SCORE_RELEASE == 2ULL * (unsigned long long)FLOW_SCORE_WIDTH,
	       "release is two widths");
_Static_assert((unsigned long long)FLOW_SCORE_MAX == 3ULL * (unsigned long long)FLOW_SCORE_HMAX + 100ULL,
	       "wide cap bounds the blend sum");
_Static_assert((unsigned long long)FLOW_SCORE_RAW_MAX == 4ULL,
	       "raw max bounds the burn steps");
_Static_assert((unsigned long long)FLOW_SCORE_N == 8ULL,
	       "sample bound covers the window");
static __always_inline u64 flow_llc_dsq(u32 llc)
{
	return (u64)FLOW_LLC_BASE + (u64)llc;
}
static __always_inline bool flow_llc_ok(u32 llc)
{
	return llc < (u32)FLOW_MAX_LLCS;
}
/* Bound check only. The live range adds the discovered CPU count, */
/* so offline CPUs past it need a restart. */
static __always_inline bool flow_cpu_ok(u32 cpu)
{
	return cpu < (u32)FLOW_MAX_CPUS;
}
static __always_inline bool flow_node_ok(u32 node)
{
	return node < (u32)FLOW_MAX_NODES;
}
static __always_inline bool flow_dsq_ok(u64 dsq)
{
	return dsq >= (u64)FLOW_LLC_BASE &&
	       dsq < (u64)FLOW_LLC_BASE + (u64)FLOW_MAX_LLCS;
}
#endif
#endif
