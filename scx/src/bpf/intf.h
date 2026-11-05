// SPDX-License-Identifier: GPL-2.0
/*
 * Shared ABI for the flow scheduler.
 *
 * DSQs are one per LLC plus one fallback safety net. Pair queues are upstream arena DHQs.
 * Stats are per LLC counters with a stable head plus an append-only tail.
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
	/* Hard CPU bound for all BPF arrays keyed by CPU. */
	FLOW_MAX_CPUS = 1024ULL,
	/* Hard LLC bound for all BPF arrays keyed by LLC. */
	FLOW_MAX_LLCS = 64ULL,
	/* Hard node bound for all BPF arrays keyed by node. */
	FLOW_MAX_NODES = 8ULL,
	/* Pair count is half the LLC bound. */
	FLOW_MAX_PAIRS = 32ULL,
	/* Fixed slice in nanos with no knob. */
	FLOW_SLICE_NS = 1000000ULL,
	/* Minimal slice for exiting tasks in nanos with no knob. */
	/* One microsecond is 1000x smaller than the normal slice. Exit */
	/* needs only enough runtime to release resources and never */
	/* preempts, so a tiny slice keeps exit progress cheap without */
	/* stalling normal tasks. Used for every exiting insert. */
	FLOW_EXIT_SLICE_NS = 1000ULL,
	/* Bounded pop retries per dispatch with no knob. Four covers a */
	/* burst of stale plus exiting entries without stalling dispatch. */
	/* Each attempt is one pop plus one lookup, so worst cost is four */
	/* lookups per dispatch, negligible next to the normal path. */
	FLOW_POP_RETRY_MAX = 4ULL,
	/* Preempt gap in nanos with no knob. */
	FLOW_PREEMPT_THRESH = 500000ULL,
	/* Preempt tail guard in nanos with no knob. */
	FLOW_PREEMPT_TAIL = 125000ULL,
	/* Ops timeout in ms for the watchdog. */
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Strand balance bound on enqueue with no knob. */
	FLOW_DHQ_MAX_IMBALANCE = 3ULL,
	/* Base DSQ id for per LLC queues. LLC id adds to the base. */
	FLOW_LLC_BASE = 0x6000ULL,
	/* Single fallback DSQ id used only when LLC id fails validation. Safety only. */
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	/* Strand fixed A. */
	FLOW_STRAND_A = 0ULL,
	/* Strand fixed B. */
	FLOW_STRAND_B = 1ULL,
	/* Queued bit in task flags. Set on enqueue, cleared on running and dequeue. */
	FLOW_FLAG_QUEUED = 1ULL,
	/* Cgroup weight default. Matches CGROUP_WEIGHT_DFL in */
	/* include/linux/cgroup.h plus the v2 range doc [1, 10000] */
	/* default 100 plus flash/forge CGROUP_WEIGHT_DFL 100. Zero */
	/* is never a valid weight and fails closed to default. */
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
};
/* Per task state for the life of the task. Flags holds the queued bit. */
/* Tail cgrp_id plus cg_weight carry the cpu.weight share. Zero init */
/* means no cgroup seen and reads as default through the clamp. Stats */
/* stay untouched with no new counter for shares. */
struct flow_task_ctx {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u64 gen;
	u32 strand;
	u32 llc_id;
	u32 flags;
	u32 pad;
	u64 cgrp_id;
	u32 cg_weight;
	u32 pad2;
};
/* Per CPU running snapshot for preempt compare. Zero means empty. */
struct flow_running_state {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u32 llc_id;
	u32 strand;
	u64 gen;
};
/* Per CPU hint state for speed requests. Zero means empty. Last holds */
/* the prior sample time in nanos. Level holds the smoothed load in the */
/* same scale as the kernel speed scale. Persisted across events. */
struct flow_freq_state {
	u64 last;
	u64 level;
};
/* Per CPU view seeded once from userspace. Small with no frozen row. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 pad;
};
/* Per LLC counters. Offsets 0:queued 1:dispatched 2:fallback 3:steal */
/* 4:fb_pair_full 5:fb_duplicate 6:fb_stale 7:dhq_depth 8:dhq_cap stay */
/* stable for compat. Tail is append-only with no bound change. */
/* 14 by u64 is 112 bytes. Fallback stays the aggregate of pair-full */
/* plus duplicate plus stale, so fallback equals 4 plus 5 plus 6. */
/* Steal stays the aggregate of pair plus LLC, so steal equals 9 plus 10. */
/* fb_pair_full counts pair DHQ full spills to the LLC DSQ. fb_duplicate */
/* counts queued-guard duplicate drops. fb_stale counts stale DHQ pops */
/* with no task. dhq_depth is a gauge of last observed pair depth and */
/* dhq_cap the paired capacity for sizing. Single LLC has no pair, so */
/* depth plus cap stay zero there. steal_pair counts pair steals in */
/* dispatch. steal_llc counts remote LLC queue steals in dispatch. */
/* kick_preempt counts preempt kicks on enqueue. kick_idle counts idle */
/* kicks on enqueue. kick_skip counts enqueue kicks skipped with no wake. */
struct flow_llc_stats {
	u64 queued;
	u64 dispatched;
	u64 fallback;
	u64 steal;
	u64 fb_pair_full;
	u64 fb_duplicate;
	u64 fb_stale;
	u64 dhq_depth;
	u64 dhq_cap;
	u64 steal_pair;
	u64 steal_llc;
	u64 kick_preempt;
	u64 kick_idle;
	u64 kick_skip;
};
#ifdef __BPF__
static __always_inline u64 flow_llc_dsq(u32 llc)
{
	return (u64)FLOW_LLC_BASE + (u64)llc;
}
static __always_inline bool flow_llc_ok(u32 llc)
{
	return llc < (u32)FLOW_MAX_LLCS;
}
/* Bound check only. Practical scope adds the init count range, so live */
/* needs this plus below the discovered count. Offline inside the range */
/* also needs restart and stays scoped there. */
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
/* ABI stays frozen with fixed slice, preempt, pop retry, */
/* strand, DSQ, and cgroup weight constants plus frozen offsets 0-8 and */
/* append only tail. Docs only, no logic change. */
#endif
#endif
