// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each CPU has two queues ordered by virtual time. Ties leave in
 * insertion order. One fallback queue holds tasks that have no
 * usable CPU. Pinned tasks run on their local queue. Shares are
 * read from the cgroup map on each enqueue. A task pays for the
 * time it burns, scaled by its share, with a small extra amount
 * added per quantum. Fresh virtual times move past a per LLC floor
 * so two tasks never share the same value. Remain tracks the time
 * left for the current deadline with a fresh value of one slice
 * clamped to a floor. Deadline adds a fixed span to the enqueue
 * time and is kept until it passes, then a fresh span is added and
 * an overdue count grows with an escape count for the fresh span.
 * Overdue tasks stay on the first strand. Long waiting batch and
 * idle heads drain before normal. Slack is deadline minus now minus
 * remain with saturation. Small
 * slack takes the first strand with larger slack placed further back
 * in fixed bands. Bands keep four labels for urgent plus normal
 * plus batch plus idle. Slices hold one fixed quantum. A shared
 * enqueue with slack ahead of the running slack by a gap kicks for
 * preempt with idle wakes otherwise. Holds gate gap wins. Idle targets
 * take idle wakes. Each running instance kicks at most once. A runnable
 * yield with no burnt time still moves the stored
 * time forward by one. Wait history keeps per CPU queue waits by
 * kind and bucket with slice based edges. Kinds cover shared
 * queues plus pinned plus exiting plus fallback plus early plus
 * unknown. Buckets split waits by length with slice fractions
 * and multiples. The task tail holds the wait kind for the next
 * observe step. The wait table is sized for every CPU with run
 * plus dispatch halves. Each per CPU queue holds at most two
 * hundred fifty six tasks with the fallback holding at most one
 * thousand twenty four. Strands stay balanced with at most eight
 * more tasks on one side than the other. Steal moves in topology
 * order with local first then same node then remote. Balanced mode
 * drains the larger strand first with a long batch head promoted
 * on ties.
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
	FLOW_DHQ_STRAND_A = 0ULL,
	FLOW_DHQ_STRAND_B = 1ULL,
	FLOW_DHQ_STRAND_AUTO = 2ULL,
	FLOW_DHQ_MODE_ALTERNATING = 0ULL,
	FLOW_DHQ_MODE_PRIORITY = 1ULL,
	FLOW_DHQ_MODE_BALANCED = 2ULL,
	FLOW_DHQ_PERCPU_CAP = 256ULL,
	FLOW_FALLBACK_CAP = 1024ULL,
	FLOW_DHQ_MAX_IMBALANCE = 8ULL,
	FLOW_SLICE_MIN_NS = 1000000ULL,
	FLOW_EXIT_SLICE_NS = 1000ULL,
	FLOW_FAIR_BASE_NS = 20000ULL,
	FLOW_FAIR_EXTRA_NS = 1000ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_LST_REL_NS = 20000000ULL,
	FLOW_LST_INIT_NS = 1000000ULL,
	FLOW_LST_FLOOR_NS = 5000ULL,
	FLOW_LST_PREEMPT_GAP_NS = 1000000ULL,
	FLOW_LST_NORM_NS = 1000000ULL,
	FLOW_LST_BATCH_NS = 10000000ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_DHQ_BASE = 0x6200ULL,
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
 * Prio holds the band label. Remain holds the time left for
 * the current deadline. Enq holds the last enqueue time. Cgrp holds
 * the group id and share hint. A zero id means no group was recorded.
 * Lat holds the wait kind for history. Home holds the first CPU that
 * ran the task with minus one when unset. Deadline holds the time by
 * which remain should run with zero meaning unset. */
struct flow_task_ctx {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	u32 prio;
	u32 cg_weight;
	u64 cgrp_id;
	u64 remain_ns;
	u64 enq_ns;
	u32 lat_kind;
	s32 home_cpu;
	u64 deadline_ns;
};
/* Wait history for one CPU. Cells hold run waits then dispatch
 * waits by kind times bucket. The length covers two halves of
 * kinds times buckets. */
struct flow_lat_hist {
	u64 cells[FLOW_HIST_LEN];
};
/* Per CPU running view. Gen counts runs. Reserved stays
 * zero. Prio mirrors the running task. Pad holds the last kicked
 * generation, so each run kicks at most once. Slack holds the task
 * slack at running time for gap checks. */
struct flow_running_state {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 prio;
	u32 reserved;
	u32 pad;
	s64 slack;
};
/* Per CPU seed from userspace. Holds the CPU id plus the LLC plus
 * node plus cluster indices assigned at startup. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 ccx_id;
};
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts preempt plus idle and skipped wakes. Overrun counts full
 * slice burns. Penalty and extra record the charge for those burns,
 * and total records the quanta granted. Blocked counts stops that
 * leave the task runnable. Escape counts fresh spans after an
 * overdue deadline. Orphan
 * counts mask change kicks. Forward counts heads passed to their
 * owner. Urgent and hold describe the queue choice. Preempt counts
 * gap wins on enqueue. Overdue counts deadlines seen past now. */
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
	u64 lst_escape;
	u64 orphan_kick;
	u64 hol_forward;
	u64 lst_urgent;
	u64 lst_hold;
	u64 lst_preempt;
	u64 lst_overdue;
	u64 extra_award;
	u64 total_quanta;
};
#ifdef __BPF__
static __always_inline u64 flow_dhq_id(u32 cpu, u32 strand)
{
	return (u64)FLOW_DHQ_BASE + (u64)cpu * 2ULL + (u64)strand;
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
static __always_inline bool flow_strand_ok(u32 strand)
{
	return strand <= (u32)FLOW_DHQ_STRAND_B;
}
static __always_inline bool flow_dhq_ok(u32 cpu, u32 strand)
{
	return flow_cpu_ok(cpu) && flow_strand_ok(strand);
}
static __always_inline bool flow_dsq_ok(u64 dsq)
{
	return (dsq >= (u64)FLOW_DHQ_BASE &&
		dsq < (u64)FLOW_DHQ_BASE + (u64)FLOW_MAX_CPUS * 2ULL) ||
	       dsq == (u64)FLOW_FALLBACK_DSQ;
}
#endif
#endif
