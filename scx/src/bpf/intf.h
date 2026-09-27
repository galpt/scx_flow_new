// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one shallow FIFO per CPU for sleepy tasks, one
 * deadline queue per CPU for steady tasks, one shared overflow tail, and
 * the kernel global queue for homeless work. Slices grow with weight and
 * shrink with pressure, so no knob is needed. Virtual time is charged on
 * every segment with weight scaling, and each CPU keeps a high water mark
 * that anchors newcomers. Duty tracks voluntary sleep with a slow average,
 * and only sleepy tasks may use the fast lane. See enqueue.bpf.c for the
 * admission order, lifecycle.bpf.c for the ledger, dispatch.bpf.c for the
 * drain order, and select_cpu.bpf.c for placement.
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
/* Dynamic slice bounds with no knob. Slices span 250us to 15ms. */
enum flow_consts {
	FLOW_QMIN_NS = 250000ULL,
	FLOW_QMAX_NS = 15000000ULL,
	FLOW_LTARGET_NS = 5000000ULL,
	FLOW_MICRO_QUANTUM_NS = 500000ULL,
	FLOW_WEIGHT_BASE = 100ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_MAX = 10000ULL,
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_FAST_BASE = 0x6000ULL,
	FLOW_VTIME_BASE = 0x6800ULL,
	FLOW_OVERFLOW = 0x7000ULL,
	FLOW_MAX_DSQS = 2049ULL,
	FLOW_FAST_D = 4ULL,
	FLOW_SLOT_BUDGET = 32ULL,
	FLOW_DISPATCH_MAX_BATCH = 32ULL,
	FLOW_OWN_VTIME_CAP = 12ULL,
	FLOW_OVER_CAP = 4ULL,
	FLOW_GATED_CAP = 4ULL,
	FLOW_MISS_CAP = 4ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_PREEMPT_RATE_NS = 2000000ULL,
	FLOW_PREEMPT_FLOOR_NS = 100000ULL,
	FLOW_STARVE_NS = 1500000ULL,
	FLOW_DUTY_SHIFT = 3ULL,
	FLOW_DUTY_FAST = 38ULL,
	FLOW_DUTY_BATCH = 128ULL,
	FLOW_DUTY_BURST_INST = 64ULL,
	FLOW_PROB_CYCLES = 2ULL,
	FLOW_PROB_VOL = 0x80ULL,
	FLOW_PI_WINDOW_NS = 1000000ULL,
	FLOW_PI_SLICE_NS = 500000ULL,
	FLOW_STEAL_PENALTY_NS = 500000ULL,
	FLOW_STEAL_PENALTY_ON = 1ULL,
	FLOW_CLS_INTERACTIVE = 0ULL,
	FLOW_CLS_BATCH = 1ULL,
	FLOW_POL_NORMAL = 0ULL,
	FLOW_POL_BATCH = 3ULL,
	FLOW_POL_IDLE = 5ULL,
};
/* Per task state at 40B with ledger, duty, probation, and elevation. */
/* Vruntine holds weight scaled service. Run at holds the segment start. */
/* Wait at holds the last enqueue time for starvation. Slice holds the */
/* last dynamic slice. Elev at holds the low bits of the elevation time. */
/* Duty holds intensity at 0 to 255. Prob holds wake cycles plus a sleep */
/* flag at bit 7. On CPU pairs the gauge with stopping. Elevated marks */
/* one PI boost per owner. Cls holds the preemption class. */
struct flow_task_ctx {
	u64 vruntime;
	u64 run_at;
	u64 wait_at;
	u32 slice_ns;
	u32 elev_at;
	u8 duty;
	u8 prob;
	u8 on_cpu;
	u8 elevated;
	u8 cls;
	u8 _pad[3];
};
/* Per CPU state at 16B with minimum plus running pid plus cursor. */
/* Min holds the high water virtual time. Cursor spreads steal passes. */
struct flow_cpu_state {
	u64 min_vruntime;
	u32 running_pid;
	u32 cursor;
};
/* Per CPU waiter record at 16B for the PI approximation. */
/* Pid holds the last voluntary sleeper. At holds the stop time. */
struct flow_pi_wait {
	u32 pid;
	u32 _pad;
	u64 at;
};
/* Per CPU topology view at 16B with sibling plus domain plus slice. */
/* Smt sib holds the thread sibling or all ones when unknown. Llc holds */
/* the cache domain. Last slice holds the newest dynamic slice. */
struct flow_topo {
	u32 smt_sib;
	u32 llc;
	u64 last_slice;
};
/* Scheduler counters with admission, ledger, preempt, and steal detail. */
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
	u64 fast_admits;
	u64 fast_bounds;
	u64 vtime_admits;
	u64 duty_gates;
	u64 prob_holds;
	u64 elev_moves;
	u64 steal_penalties;
	u64 global_moves;
};
/* Task state holds ledger plus duty plus probation in 40 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 40,
    "task state stays at 40B");
/* CPU state holds minimum plus pid plus cursor in 16 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 16,
    "cpu state stays at 16B");
/* Waiter record holds pid plus time in 16 bytes. */
_Static_assert(sizeof(struct flow_pi_wait) == 16,
    "waiter record stays at 16B");
/* Topology view holds sibling plus domain plus slice in 16 bytes. */
_Static_assert(sizeof(struct flow_topo) == 16,
    "topology view stays at 16B");
/* Stats hold 20 counters in 160 bytes with no removal. */
_Static_assert(sizeof(struct flow_sched_stats) == 160,
    "stats stay at 160B");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Max of two virtual times with wrap safety. */
/* The later time wins so the minimum never moves backward. */
static __always_inline u64 flow_min_max(u64 old,
	u64 next)
{
	if (flow_time_before(old, next))
		return next;
	return old;
}
/* Guarded idle minimum refresh with wrap safety. */
/* Moves forward only when the CPU is idle and empty, so enqueue and */
/* stopping share one funnel with the high water mark below. */
static __always_inline u64 flow_min_idle_refresh(u64 old,
	u64 cand, bool idle_empty)
{
	if (!idle_empty)
		return old;
	return flow_min_max(old, cand);
}
/* Clamped weight in 1 to 10000 with base 100. */
/* Zero or oversize weights fail closed to the nearer bound. */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/* Scaled charge of one run segment for the ledger. */
/* Heavy weights accrue less virtual time per nanosecond. */
static __always_inline u64 flow_scaled_delta(u64 delta,
	u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	return delta * (u64)FLOW_WEIGHT_BASE / (u64)w;
}
/* Dynamic slice from weight and queue pressure with no knob. */
/* L is the larger of the 5ms target and N times the 250us minimum. */
/* Fair is L times weight over N times base, clamped to the bounds. */
static __always_inline u64 flow_dyn_slice(u32 weight,
	u64 queued)
{
	u64 n = queued ? queued : 1ULL;
	u64 L = (u64)FLOW_LTARGET_NS;
	u64 fair;
	u32 w = flow_weight_clamp(weight);
	if (n > (u64)FLOW_MAX_CPUS)
		n = (u64)FLOW_MAX_CPUS;
	if (n * (u64)FLOW_QMIN_NS > L)
		L = n * (u64)FLOW_QMIN_NS;
	fair = L * (u64)w / (n * (u64)FLOW_WEIGHT_BASE);
	if (fair < (u64)FLOW_QMIN_NS)
		return (u64)FLOW_QMIN_NS;
	if (fair > (u64)FLOW_QMAX_NS)
		return (u64)FLOW_QMAX_NS;
	return fair;
}
/* Lag cap for one weight at 5ms times base over weight. */
/* Light tasks may lag further behind the minimum than heavy ones. */
static __always_inline u64 flow_lag_cap(u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	return (u64)FLOW_LTARGET_NS * (u64)FLOW_WEIGHT_BASE /
	    (u64)w;
}
/* Clamped entry virtual time against the CPU minimum. */
/* Fresh tasks anchor at minimum minus lag cap with wrap safety. */
static __always_inline u64 flow_clamp_entry(u64 task_v,
	u64 min_v, u64 cap)
{
	u64 floor = min_v - cap;
	if (flow_time_before(task_v, floor))
		return floor;
	return task_v;
}
/* Duty step with alpha 1 over 8 and a burst allowance. */
/* Voluntary stops decay toward zero. Short runnable bursts climb */
/* gently toward 64, and long runnable segments climb toward 255. */
static __always_inline u8 flow_duty_step(u8 duty,
	bool runnable, u64 delta_ns)
{
	u32 inst;
	u32 d = duty;
	if (!runnable) {
		inst = 0;
	} else if (delta_ns <= (u64)FLOW_STARVE_NS) {
		inst = (u32)FLOW_DUTY_BURST_INST;
	} else {
		inst = 255U;
	}
	if (inst >= d)
		return (u8)(d + ((inst - d) >> (u32)FLOW_DUTY_SHIFT));
	return (u8)(d - ((d - inst) >> (u32)FLOW_DUTY_SHIFT));
}
/* Preemption class from policy and duty. */
/* Idle and batch policies always rest in batch. Other non normal */
/* policies stay out of the fast lane with batch class. Normal tasks */
/* split at half duty, so steady spinners cannot preempt sleepers. */
static __always_inline u32 flow_class_of(int policy,
	u8 duty)
{
	if (policy == (int)FLOW_POL_IDLE)
		return (u32)FLOW_CLS_BATCH;
	if (policy == (int)FLOW_POL_BATCH)
		return (u32)FLOW_CLS_BATCH;
	if (policy != (int)FLOW_POL_NORMAL)
		return (u32)FLOW_CLS_BATCH;
	if (duty >= (u32)FLOW_DUTY_BATCH)
		return (u32)FLOW_CLS_BATCH;
	return (u32)FLOW_CLS_INTERACTIVE;
}
/* True when one policy may use the fast lane at all. */
/* Only SCHED_OTHER tasks enter, so realtime and idle stay ordered. */
static __always_inline bool flow_fast_lane_ok(int policy)
{
	return policy == (int)FLOW_POL_NORMAL;
}
/* FIFO id of one CPU fast queue from base plus id. */
/* One shallow queue per CPU keeps sleepy wakeups local. */
static __always_inline u64 flow_fast_dsq(u32 cpu)
{
	return (u64)FLOW_FAST_BASE + (u64)cpu;
}
/* Deadline queue id of one CPU from base plus id. */
/* One ordered queue per CPU keeps steady work fair. */
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
/* Least donor depth for one steal with idle empty fast path. */
/* Holds 1 when idle empty else 2 so idle owners take the last task. */
static __always_inline u64 flow_steal_need(bool idle_empty)
{
	if (idle_empty)
		return 1ULL;
	return (u64)FLOW_STEAL_MIN_DEPTH;
}
/* Cap of one fast trip at depth 4 under the dispatch budget. */
/* Returns the min of budget and 4 so one queue moves at most 4. */
static __always_inline u32 flow_fast_cap(u32 budget)
{
	if (budget > (u32)FLOW_FAST_D)
		return (u32)FLOW_FAST_D;
	return budget;
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
/* Synthetic vruntime penalty for one stolen task when enabled. */
/* The 500us add is weight scaled, so heavy tasks pay less time. */
static __always_inline u64 flow_steal_penalty(u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	return (u64)FLOW_STEAL_PENALTY_NS * (u64)FLOW_WEIGHT_BASE /
	    (u64)w;
}
/* Wake cycles left in one probation byte with the sleep flag masked out. */
/* Fresh tasks hold two cycles, and each low duty wake spends one. */
static __always_inline u32 flow_prob_count(u8 prob)
{
	return (u32)(prob & 0x03U);
}
/* True when the last stop was a voluntary sleep. */
/* Bit 7 carries the signal with no extra field. */
static __always_inline bool flow_prob_vol(u8 prob)
{
	return (prob & (u8)FLOW_PROB_VOL) != 0;
}
/* Probation byte from cycles plus sleep flag. */
/* Counts stay in the low bits with the flag kept apart. */
static __always_inline u8 flow_prob_make(u32 count,
	bool vol)
{
	u8 v = (u8)(count & 0x03U);
	if (vol)
		v |= (u8)FLOW_PROB_VOL;
	return v;
}
#endif
