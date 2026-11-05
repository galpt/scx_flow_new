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
	/* Latency offset in nanos with no knob. One fixed slice that */
	/* moves a latency task ahead of a hog at the same raw time. */
	/* Only the queue key plus the kick compare use the offset. */
	/* Stored time plus deadline plus stamp stay raw. */
	FLOW_LAT_OFF_NS = 1000000ULL,
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
	/* Bounded extra quanta with no knob. Total runs one base plus */
	/* zero through two extra for one through three quanta. */
	FLOW_MAX_QUANTA = 3ULL,
	FLOW_MAX_EXTRA = 2ULL,
	/* Score bands with no knob. Four bands each span twenty five. */
	/* Three levels name extra zero plus one plus two. Raw hint has */
	/* five steps zero through four with only the top step at full. */
	/* Lower steps merge into the same blend with no second path. */
	/* Band count times width equals the top, levels equal max extra */
	/* plus one, raw max bounds the burn steps, sample bound covers */
	/* the blend window, wide cap covers the blend sum before clamp. */
	FLOW_SCORE_BANDS = 4ULL,
	FLOW_SCORE_WIDTH = 25ULL,
	FLOW_SCORE_LEVELS = 3ULL,
	FLOW_SCORE_RAW_MAX = 4ULL,
	/* Score scale top with no knob. Band width plus engage plus */
	/* release plus sample bound plus wide cap stay fixed. Engage */
	/* takes the top from below, release keeps the hold from above. */
	/* Sample bound covers the blend window, wide cap covers the */
	/* blend sum before the clamp with floor on both paths. */
	FLOW_SCORE_HMAX = 100ULL,
	FLOW_SCORE_Q = 25ULL,
	FLOW_SCORE_ENGAGE = 75ULL,
	FLOW_SCORE_RELEASE = 50ULL,
	FLOW_SCORE_N = 8ULL,
	FLOW_SCORE_MAX = 400ULL,
};
/* Per task state for the life of the task. Flags holds the queued bit. */
/* Hist holds the last three yield bits in bits zero through two with */
/* zero init fresh neutral as a hog. A stop with remain records one, a */
/* full burn records zero, and two of three ones reads as latency. Tail */
/* cgrp_id plus cg_weight carry the cpu.weight share. Zero init means */
/* no cgroup seen and reads as default through the clamp. Tail enq_ns */
/* holds the last enqueue time in nanos from the monotonic clock. Zero */
/* means never queued. It ages waits with no vtime shift and never */
/* changes placement. Nine by eight plus tail is 72 bytes with no size */
/* change from the history byte reuse of the pad. */
struct flow_task_ctx {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u64 gen;
	u32 strand;
	u32 llc_id;
	u32 flags;
	u8 hist3;
	u8 pad[3];
	u64 cgrp_id;
	u32 cg_weight;
	u32 pad2;
	u64 enq_ns;
};
/* Per CPU running snapshot for preempt compare. Zero means empty. */
/* Tail hog_streak counts consecutive full burns seen on this CPU. It */
/* grows on stops that burnt the full slice capped at twice the pop */
/* retry bound with no new knob, decays one step on clean stops and on */
/* old waits, cleared when a pinned wait reaches the CPU. Saturated */
/* with no wrap so a hold ends but never sticks. Lat tells whether the */
/* running task reads as latency with one else zero, seeded at start */
/* from the history with pinned always zero, so the kick can boost both */
/* sides with no extra lookup. Reserved keeps alignment and stays zero */
/* past the flag. Six by eight plus tail is 48 bytes with no size */
/* change from the flag reuse of the reserved word. */
struct flow_running_state {
	s64 vtime;
	s64 deadline;
	u64 slice_rem;
	u32 llc_id;
	u32 strand;
	u64 gen;
	u32 hog_streak;
	u8 lat;
	u8 __rsvd[3];
};
/* Per CPU hint state for speed requests. Zero means empty. Last holds */
/* the prior sample time in nanos. Level holds the smoothed load in the */
/* same scale as the kernel speed scale. Hist holds the last four raw */
/* samples as a shift ring for sizing with integer math only. Persisted */
/* across events. Two by eight plus four by eight is 48 bytes. */
struct flow_freq_state {
	u64 last;
	u64 level;
	u64 hist[4];
};
/* Per CPU extra score with zero init and no cross use. Score holds zero */
/* through one hundred. Prev holds zero through two for the last award. */
/* Growth plus decay counts stay separate for proof with no shared path. */
/* Each CPU keeps its own row with no average across CPUs. Persisted */
/* across events. Four by eight is 32 bytes. */
struct flow_extra_state {
	u64 score;
	u64 prev_extra;
	u64 n_growth;
	u64 n_decay;
};
/* Per CPU view seeded once from userspace. Small with no frozen row. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 pad;
};
/* Per LLC counters. Offsets 0:queued 1:dispatched 2:fallback 3:steal */
/* 4:fb_pair_full 5:fb_duplicate 6:fb_stale 7:dhq_depth 8:dhq_cap */
/* 9:steal_pair 10:steal_llc 11:kick_preempt 12:kick_idle 13:kick_skip */
/* 14:overrun 15:domino_penalty 16:blocked 17:hog_escape 18:orphan_kick */
/* 19:hol_forward 20:lat_boost 21:hog_hold 22:lat_preempt 23:age_rescue */
/* stay stable for compat. Tail is append-only with no bound change. */
/* 24:extra_award 25:total_quanta only append with zero through twenty */
/* three frozen. Twenty six by u64 is 208 bytes. Twenty five by u64 is */
/* 200 bytes with twenty four present. Fallback */
/* stays the aggregate of pair-full plus duplicate plus stale, so fallback */
/* equals 4 plus 5 plus 6. Steal stays the aggregate of pair plus LLC, so */
/* steal equals 9 plus 10. fb_pair_full counts pair DHQ full spills to the */
/* LLC DSQ. fb_duplicate counts queued-guard duplicate drops. fb_stale */
/* counts stale DHQ pops with no task. dhq_depth is a gauge of last */
/* observed pair depth and dhq_cap the paired capacity for sizing. Single */
/* LLC has no pair, so depth plus cap stay zero there. steal_pair counts */
/* pair steals in dispatch. steal_llc counts remote LLC queue steals in */
/* dispatch. kick_preempt counts preempt kicks on enqueue. kick_idle counts */
/* idle kicks on enqueue. kick_skip counts enqueue kicks skipped with no */
/* wake. overrun counts carry tasks that burnt the full slice with no */
/* remain. domino_penalty counts the extra slice charged on such an overrun */
/* one to one with overrun by design, event versus cost, so a task that */
/* always burns the full slice cannot hold the head. Saturated at max the */
/* vtime stays capped while the count still grows for visibility. blocked */
/* counts stops that leave the task still runnable, which covers preemptions */
/* plus slice expiry plus migrations with no vtime penalty so blocking never */
/* shifts the deadline. An invalid cached LLC falls back to zero with no */
/* loss. Gauges stay set only. hog_escape counts escalated preempts where a */
/* streak forced an idle wake to preempt so a hog hold ends. orphan_kick */
/* counts mask change kicks for queued tasks with no queue rewrite. */
/* hol_forward counts forwards where the head cannot run on the thief with */
/* no move no loss. lat_boost counts enqueues that take the latency key. */
/* hog_hold counts enqueues that keep the raw key as hogs. lat_preempt */
/* counts preempts won by a latency task on the boosted gap. age_rescue */
/* counts old waits that step the hold down. Extra award holds q minus */
/* one beyond the first. Total quanta holds q for the run. The total is */
/* the sum of the old penalty plus the new extra with one addition per */
/* award and again on deltas. Pinned fast path never awards extra. */
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
/* Band locks hold at compile time with no runtime cost and no knob. */
/* Bands times width equals the top, levels equal max extra plus one, */
/* width equals the middle band edge, engage is three widths, release */
/* is two widths, raw max bounds the burn steps, wide cap bounds three */
/* times top plus full. Sample bound covers the blend window. */
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
/* ABI stays frozen with fixed slice, latency offset, preempt, pop retry, */
/* strand, DSQ, and cgroup weight constants plus frozen offsets 0 through 23 */
/* and append only tail 24 through 25. History plus running flag reuse spare */
/* bytes with no size change. Extra tails hold q minus one plus q with the */
/* sum checkable per award. Per CPU extra rows stay zero init with no cross */
/* average. Docs only, no logic change. */
#endif
#endif
