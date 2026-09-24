// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
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
/* Fixed slice at 1ms with one queue per CPU plus one overflow tail. */
enum flow_consts {
	FLOW_SLICE_NS = (1ULL * 1000ULL * 1000ULL),
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_SLOT_BASE = 0x6000ULL,
	FLOW_SLOT_OVERFLOW = 0x6800ULL,
	FLOW_SLOT_MAX_DSQS = 1025ULL,
	FLOW_SLOT_D = 4ULL,
	FLOW_SLOT_BUDGET = 32ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_WEIGHT = 1024ULL,
	FLOW_LIFO_K = 8ULL,
	FLOW_LIFO_PERIOD = 9ULL,
};
/* Per task state at 16B with start time and virtual time. */
struct flow_task_ctx {
	u64 run_at;
	u64 vruntime;
};
/* Per CPU state at 16B with frontier, running pid, and steal cursor. */
struct flow_cpu_state {
	u64 frontier;
	u32 running_pid;
	u32 cursor;
};
/* Scheduler counters with inserts, moves, kicks, and LIFO detail. */
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
	u64 preempt_kicks;
	u64 preempt_skipped;
	u64 slot_moves;
	u64 lifo_heads;
	u64 lifo_bound_hits;
};
/* Task state holds start time plus virtual time in 16 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 16,
    "task state stays at 16B");
/* CPU state holds frontier plus pid plus cursor in 16 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 16,
    "cpu state stays at 16B");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Max of two virtual times with wrap safety. */
/* The later time wins so the frontier never moves backward. */
static __always_inline u64 flow_frontier_max(u64 old,
	u64 next)
{
	if (flow_time_before(old, next))
		return next;
	return old;
}
/* Frontier for an idle CPU from the waking virtual time. */
/* The caller keeps the old frontier when waking is zero. */
static __always_inline u64 flow_frontier_idle(u64 waking_v)
{
	return waking_v;
}
/* Slot id of the overflow tail shared by every CPU. */
/* One tail keeps pinned and homeless tasks visible to steal. */
static __always_inline u64 flow_slot_overflow_dsq(void)
{
	return (u64)FLOW_SLOT_OVERFLOW;
}
/* Slot id of one CPU queue from base plus id. */
/* One queue per CPU keeps enqueue and dispatch O(1). */
static __always_inline u64 flow_slot_cpu_dsq(u32 cpu)
{
	return (u64)FLOW_SLOT_BASE + (u64)cpu;
}
/* True when one insert takes head with bounded LIFO at K 8. */
/* Takes head for 8 of 9 with one tail plus one forced tail at max. */
/* Fresh work wins fast while the tail keeps the starve bound at 9. */
static __always_inline bool flow_lifo_take_head(u32 seq)
{
	if (seq == 0xffffffffU)
		return false;
	return (seq % (u32)FLOW_LIFO_PERIOD) !=
	    (u32)FLOW_LIFO_K;
}
/* Index of one LIFO sequence with per CPU plus overflow at 1025. */
/* Per CPU holds the id and overflow holds 1024 with no share. */
static __always_inline u32 flow_lifo_idx(bool over,
	u32 cpu)
{
	if (over)
		return 1024U;
	return cpu;
}
/* Least donor depth for one steal with idle empty fast path. */
/* Holds 1 when idle empty else 2 so idle owners take the last task. */
static __always_inline u64 flow_steal_need(bool idle_empty)
{
	if (idle_empty)
		return 1ULL;
	return (u64)FLOW_STEAL_MIN_DEPTH;
}
/* Cap of one trip at D under the dispatch budget. */
/* Returns the min of budget and 4 so one queue moves at most 4. */
static __always_inline u32 flow_slot_cap(u32 budget)
{
	if (budget > (u32)FLOW_SLOT_D)
		return (u32)FLOW_SLOT_D;
	return budget;
}
/* Own cap of one dispatch at budget minus one. */
/* Holds 31 with budget 32 so overflow and steal keep one slot. */
static __always_inline u32 flow_slot_own_cap(u32 budget)
{
	if (budget == 0)
		return 0;
	return budget - 1U;
}
#endif
