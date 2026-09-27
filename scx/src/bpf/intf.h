// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one deadline queue per CPU plus one shared
 * overflow tail, and it uses the kernel global queue for homeless
 * work. Every task carries a deadline shaped by nice through the
 * kernel weight, and each queue orders by that deadline. Service
 * runs one fixed quantum, so placement and steal stay independent
 * of weight except through deadline order. See enqueue.bpf.c for
 * the deadline choice, lifecycle.bpf.c for the runtime count,
 * dispatch.bpf.c for the drain order, and select_cpu.bpf.c for
 * placement.
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
/* Fixed quantum of 1ms with no knob. Every insert uses this slice. */
enum flow_consts {
	FLOW_QUANTUM_NS = 1000000ULL,
	FLOW_WEIGHT_BASE = 100ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_MAX = 10000ULL,
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_VTIME_BASE = 0x6800ULL,
	FLOW_OVERFLOW = 0x7000ULL,
	FLOW_MAX_DSQS = 1025ULL,
	FLOW_SLOT_BUDGET = 32ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_OWN_VTIME_CAP = 12ULL,
	FLOW_OVER_CAP = 4ULL,
	FLOW_GATED_CAP = 4ULL,
	FLOW_MISS_CAP = 4ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_STARVE_NS = 2000000ULL,
	FLOW_POL_NORMAL = 0ULL,
	FLOW_POL_BATCH = 3ULL,
	FLOW_POL_IDLE = 5ULL,
};
/* Per task state at 24B with deadline plus wait plus run. */
/* Deadline holds the last assigned deadline for the next max. */
/* Wait holds the last enqueue time for the starvation check. */
/* Run holds the segment start while on CPU else zero, so nonzero */
/* pairs the on CPU gauge with the stopping charge. */
struct flow_task_ctx {
	u64 deadline;
	u64 wait_at;
	u64 run_at;
};
/* Per CPU state at 8B with running pid plus steal cursor. */
/* Pid holds the task now on the CPU else zero. Cursor spreads */
/* the placement and steal scans with no hotspot. */
struct flow_cpu_state {
	u32 running_pid;
	u32 cursor;
};
/* Per CPU topology view at 8B with sibling plus domain. */
/* Smt sib holds the thread sibling or all ones when unknown. */
/* Llc holds the cache domain used by placement and steal. */
struct flow_topo {
	u32 smt_sib;
	u32 llc;
};
/* Scheduler counters with 13 live fields. */
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
	u64 global_moves;
};
/* Task state holds deadline plus wait plus run in 24 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 24,
    "task state stays at 24B");
/* CPU state holds pid plus cursor in 8 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 8,
    "cpu state stays at 8B");
/* Topology view holds sibling plus domain in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
    "topology view stays at 8B");
/* Stats hold 13 counters in 104 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 104,
    "stats stay at 104B");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Later of two times with wrap safety. */
/* The later time wins, so a fresh deadline never trails the clock. */
static __always_inline u64 flow_time_max(u64 a,
	u64 b)
{
	if (flow_time_before(a, b))
		return b;
	return a;
}
/* Clamped weight in 1 to 10000 with base 100. */
/* Zero or oversize weights fail closed to the nearer bound. */
/* The kernel already folds nice into this weight, and flow reads */
/* no cgroup state, so only nice shapes the deadline step. */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/* Deadline step for one weight as quantum times base over weight. */
/* Base weight waits one quantum, heavy weights wait less, light */
/* weights wait more, so shares stay proportional through order. */
static __always_inline u64 flow_deadline_step(u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	return (u64)FLOW_QUANTUM_NS * (u64)FLOW_WEIGHT_BASE /
	    (u64)w;
}
/* Next deadline from the later of now and the last deadline. */
/* A long sleep never earns credit, and a back to back arrival */
/* queues behind its own last deadline with one step per arrival. */
static __always_inline u64 flow_deadline_next(u64 last,
	u64 now, u32 weight)
{
	return flow_time_max(last, now) + flow_deadline_step(weight);
}
/* Deadline queue id of one CPU from base plus id. */
/* One ordered queue per CPU keeps deadline order local. */
static __always_inline u64 flow_vtime_dsq(u32 cpu)
{
	return (u64)FLOW_VTIME_BASE + (u64)cpu;
}
/* Id of the overflow tail shared by every CPU. */
/* Pinned and foreign tasks rest here with mask wins on drain. */
static __always_inline u64 flow_overflow_dsq(void)
{
	return (u64)FLOW_OVERFLOW;
}
/* True when one queued task waited past the starvation floor. */
/* Unknown stamps never count, so fresh tasks miss past. */
static __always_inline bool flow_starved(u64 wait_at,
	u64 now)
{
	if (wait_at == 0)
		return false;
	if (flow_time_before(now, wait_at))
		return false;
	return now - wait_at > (u64)FLOW_STARVE_NS;
}
/* Own deadline queue cap at 12 under budget 32. */
/* Holds 12 with budget 32 so overflow and steal keep room. */
static __always_inline u32 flow_own_cap(u32 budget)
{
	if (budget > 12U)
		return 12U;
	return budget;
}
/* Shared tail cap at 4 under the dispatch budget. */
/* Returns the min of budget and 4 with no head stall. */
static __always_inline u32 flow_tail_cap(u32 budget)
{
	if (budget > (u32)FLOW_OVER_CAP)
		return (u32)FLOW_OVER_CAP;
	return budget;
}
#endif
