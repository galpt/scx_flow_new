// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one deadline queue per CPU plus one shared
 * overflow tail, and it uses the kernel global queue for homeless
 * work. Every task carries a deadline shaped by the task weight
 * through the effective share, and each queue orders by that
 * deadline. Every task also carries virtual runtime advanced by
 * scaled execution at stop, and each CPU tracks a floor of served
 * runtime. Open inserts key past the later of runtime and floor
 * with a slack capped at twice the quantum, so a long sleep never
 * earns credit and a light task never leaps in one arrival. The
 * effective share folds the task weight with the hierarchy weights
 * along the ancestors, so a task under a light parent waits longer.
 * Bandwidth pools cap runtime per period with lazy refill, and throttled work parks in overflow. Service runs
 * one fixed quantum, so placement and steal stay independent of
 * weight except through deadline order. See enqueue.bpf.c for the
 * deadline choice, cgroup.bpf.c for the hierarchy state,
 * lifecycle.bpf.c for the runtime count, dispatch.bpf.c for the
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
#ifndef READ_ONCE
#define READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
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
	/* Gated starvation cap at 6 under the dispatch budget. Runs bounded */
	/* but larger than the shared tail, so old tasks behind young heads */
	/* still surface with a finite scan. */
	FLOW_GATED_CAP = 6ULL,
	FLOW_MISS_CAP = 4ULL,
	FLOW_STEAL_BOUND = 8ULL,
	FLOW_STEAL_MIN_DEPTH = 2ULL,
	FLOW_OPS_TIMEOUT_MS = 30000ULL,
	FLOW_STARVE_NS = 2000000ULL,
	FLOW_POL_NORMAL = 0ULL,
	FLOW_POL_BATCH = 3ULL,
	FLOW_POL_IDLE = 5ULL,
	FLOW_CGRP_MAX = 2048ULL,
	FLOW_CGRP_DEPTH_MAX = 8ULL,
	FLOW_CGRP_WEIGHT_DFL = 100ULL,
	FLOW_BW_PERIOD_MIN_US = 1000ULL,
	FLOW_BW_TIMER_NS = 10000000ULL,
	/* Parked chain ring slots at 64. Each slot holds one park chain */
	/* of 8 ancestor ids with the leaf first. The timer refills each */
	/* listed pool, and enqueue refills cover active groups past it. */
	FLOW_PARK_HINT_NR = 64ULL,
	/* Throttle bit in the hierarchy flags. Set means gated skip. */
	FLOW_CGRP_THROTTLED = 1ULL,
	/* CPU performance levels at half plus max. More than one */
	/* runnable picks max else half with no knob and no extra walk. */
	FLOW_CPU_PERF_HALF = 512ULL,
	FLOW_CPU_PERF_MAX = 1024ULL,
};
/* Unlimited quota value with no cap use and zero pool. */
#define FLOW_RUNTIME_INF (~0ULL)
/* Per task state at 48B with deadline plus runtime plus stamps plus share cache. */
/* Deadline holds the last assigned deadline for the next key. A zero */
/* deadline means no order yet, so preempt compares skip with no kick. */
/* Vruntime holds the scaled runtime served so far for the next key. */
/* A zero runtime means no service yet, so fresh tasks key past now. */
/* Wait holds the last enqueue time for the starvation check. Pinned */
/* parks set wait too, so the gated backstop sees them. */
/* Run holds the segment start while on CPU else zero, so a claimed */
/* start pairs the on CPU gauge with the stopping charge. Running */
/* claims from zero only with a compare and swap, so a second running */
/* without a stop keeps the first start with no second count. */
/* Stopping versus disable or exit claims once with atomics, so each */
/* counted start meets exactly one gauge drop with no owner gate. Cgid holds */
/* the last hierarchy id for the cache, eweight holds the hierarchy */
/* share with base 100, cached marks a valid entry, and generation */
/* holds the u16 low bits of the global generation for validation. */
/* The u16 wraps every 65536 bumps, so a false hit needs 65536 bumps */
/* with no move. Moves clear the cache, so the window stays huge. Stamps stay */
/* per task owned with no atomics except the run claim, only counters */
/* plus pool plus pid rows use atomics. Cursor, miss, and steal scans */
/* stay best effort with no atomic order. */
struct flow_task_ctx {
	u64 deadline;
	u64 vruntime;
	u64 wait_at;
	u64 run_at;
	u64 cgid;
	u32 eweight;
	bool cached;
	u8 __pad;
	u16 generation;
};
/* Per CPU state at 8B with running pid plus steal cursor. */
/* Pid holds the task now on the CPU else zero. Owner clears use a */
/* compare and swap, so a stale exit never clears a new owner. */
/* Release clears with a compare and swap loop, so concurrent runs */
/* pair without a torn zero. Cursor spreads */
/* the placement and steal scans with no hotspot. The cursor races */
/* best effort with no atomic order. */
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
/* Per hierarchy state at 48B with share plus bandwidth pool. */
/* Weight holds the share in 1 to 10000 with base 100. */
/* Flags holds the throttle bit with atomic updates, so parks never */
/* bypass a drained ancestor. Bit 0 set means throttled with a gated */
/* skip, clear means admittable. Full walks plus consume set it, full */
/* passes plus the timer chain refill clear it. */
/* Period holds the floor clamped period in microseconds. */
/* Quota holds zero for unlimited else the quota in microseconds. */
/* Burst holds the burst in microseconds for the pool cap. */
/* Pool holds the remaining runtime in nanos, zero when drained. Pool */
/* plus updated use atomic updates, so refill versus consume versus */
/* bandwidth set never tears. */
/* Updated holds the last refill time in nanos for lazy refill. */
struct flow_cgrp_ctx {
	u32 weight;
	u32 flags;
	u64 period_us;
	u64 quota_us;
	u64 burst_us;
	u64 pool_ns;
	u64 updated_at;
};
/* Scheduler counters with 17 live fields. */
/* enq_no_tctx counts missing state plus homeless with no route, */
/* the name stays for the wire with no split. Throttled ns counts */
/* quanta at 1ms per hit with no wall use, nr throttled plus parked */
/* count the same hits with the names kept for the wire. Parked */
/* counts the overflow parks from bandwidth, and bw moves */
/* counts the hierarchy moves. */
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
	u64 throttled_ns;
	u64 nr_throttled;
	u64 parked;
	u64 bw_moves;
};
/* Task state holds deadline plus runtime plus stamps plus cache in 48 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 48,
    "task state stays at 48B");
/* CPU state holds pid plus cursor in 8 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 8,
    "cpu state stays at 8B");
/* Topology view holds sibling plus domain in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
    "topology view stays at 8B");
/* Hierarchy state holds share plus pool in 48 bytes. */
_Static_assert(sizeof(struct flow_cgrp_ctx) == 48,
    "hierarchy state stays at 48B");
/* Stats hold 17 counters in 136 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 136,
    "stats stay at 136B");
/* Timer ticks at 10ms, always covering the 1ms floor. */
_Static_assert(FLOW_BW_TIMER_NS == 10000000ULL,
    "timer stays at 10ms");
/* Parked chain holds 8 ancestor ids with the leaf first. */
struct flow_park_chain {
	u64 ids[8];
};
_Static_assert(sizeof(struct flow_park_chain) == 64,
    "park chain stays at 64B");
/* One deadline queue per CPU plus one overflow tail. */
_Static_assert(FLOW_MAX_DSQS == FLOW_MAX_CPUS + 1,
    "dsq count stays nr plus one");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Clamped weight in 1 to 10000 with base 100. */
/* Zero or oversize weights fail closed to the nearer bound. */
/* The kernel already folds nice into the task weight, and the */
/* hierarchy share folds above through the effective helper. */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/* Effective weight from task weight and hierarchy share. */
/* Both inputs clamp to range, and the product scales by base 100. */
/* A missing hierarchy entry uses base, so the task weight stands. */
static __always_inline u32 flow_eff_weight(u32 task_w,
	u32 hier_w)
{
	u64 t = (u64)flow_weight_clamp(task_w);
	u64 h = (u64)flow_weight_clamp(hier_w);
	u64 eff = t * h / (u64)FLOW_WEIGHT_BASE;
	if (eff < (u64)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (eff > (u64)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return (u32)eff;
}
/* Deadline step for one weight as quantum times base over weight. */
/* Base weight waits one quantum, heavy weights wait less, light */
/* weights wait more, so shares stay proportional through order. */
/* The step feeds the slack only; the saturated key below is live. */
static __always_inline u64 flow_deadline_step(u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	return (u64)FLOW_QUANTUM_NS * (u64)FLOW_WEIGHT_BASE /
	    (u64)w;
}
/* Advanced runtime after one execution segment. */
/* Scales raw time by base over the effective share with a split */
/* divide, so heavy shares advance slowly and light shares advance */
/* fast. The split keeps every intermediate small for real segments, */
/* a segment past the scale bound saturates at once, and both adds */
/* saturate too, so huge inputs clamp instead of wrapping. One stop */
/* per quantum keeps the two divides cheap beside the slice. */
static __always_inline u64 flow_vruntime_advance(u64 vruntime,
	u64 delta, u32 eff)
{
	u64 w = (u64)flow_weight_clamp(eff);
	u64 q = delta / w;
	u64 head;
	u64 tail;
	u64 adv;
	u64 out;
	if (q > (u64)~0ULL / (u64)FLOW_WEIGHT_BASE)
		return (u64)~0ULL;
	head = q * (u64)FLOW_WEIGHT_BASE;
	tail = delta % w * (u64)FLOW_WEIGHT_BASE / w;
	adv = head + tail;
	if (adv < head)
		return (u64)~0ULL;
	out = vruntime + adv;
	if (out < vruntime)
		return (u64)~0ULL;
	return out;
}
/* Slack for one open insert as the step capped at 2ms. */
/* Base weight keeps one quantum, heavy weights keep less, and light */
/* weights stop at twice the quantum, so a light task never leaps */
/* past the starvation floor in one arrival. */
static __always_inline u64 flow_deadline_slack(u32 weight)
{
	u64 step = flow_deadline_step(weight);
	if (step > (u64)FLOW_STARVE_NS)
		return (u64)FLOW_STARVE_NS;
	return step;
}
/* Later of two saturated times with a plain compare. */
/* Saturated values never wrap, so the plain order keeps the */
/* largest value with no signed diff use. Real times far below */
/* the bound order the same either way. The wrap max retired here, */
/* the saturated key below is the live path. */
static __always_inline u64 flow_later(u64 a,
	u64 b)
{
	if (a >= b)
		return a;
	return b;
}
/* Key deadline from a base past the floor with slack. */
/* The later of base and floor wins, so a long sleep never earns */
/* credit past served work, and the add saturates, so a huge floor */
/* clamps instead of wrapping to the front. */
static __always_inline u64 flow_deadline_key(u64 base,
	u64 floor, u64 slack)
{
	u64 at = flow_later(base, floor);
	u64 out = at + slack;
	if (out < at)
		return (u64)~0ULL;
	return out;
}
/* Floored period in microseconds with a 1ms floor. */
/* Short periods fail closed to the floor with no trap. */
static __always_inline u64 flow_bw_period_floor(u64 period_us)
{
	if (period_us < (u64)FLOW_BW_PERIOD_MIN_US)
		return (u64)FLOW_BW_PERIOD_MIN_US;
	return period_us;
}
/* Normalized quota with unlimited mapped to zero. */
/* The unlimited value means no cap, so zero means no check. */
static __always_inline u64 flow_bw_quota_norm(u64 quota_us)
{
	if (quota_us == (u64)FLOW_RUNTIME_INF)
		return 0;
	return quota_us;
}
/* True when one pool has no cap and never throttles. */
/* Zero quota means unlimited with no pool use. */
static __always_inline bool flow_bw_unlimited(u64 quota_us)
{
	return quota_us == 0;
}
/* Pool cap in nanos from quota plus burst with burst cap. */
/* Unlimited pools hold zero with no cap use, limited pools cap */
/* at quota plus burst converted to nanos with saturating math, */
/* so huge inputs clamp instead of wrapping to a small cap. */
/* Mirrors the Rust saturating helper with no wrap. */
static __always_inline u64 flow_bw_max_ns(u64 quota_us,
	u64 burst_us)
{
	u64 total;
	if (flow_bw_unlimited(quota_us))
		return 0;
	if (quota_us > 18446744073709551ULL ||
	    burst_us > 18446744073709551ULL)
		return (u64)~0ULL;
	total = quota_us + burst_us;
	if (total < quota_us)
		return (u64)~0ULL;
	if (total > 18446744073709551ULL)
		return (u64)~0ULL;
	return total * 1000ULL;
}
/* Deadline queue id of one CPU from base plus id. */
/* One ordered queue per CPU keeps deadline order local. */
static __always_inline u64 flow_vtime_dsq(u32 cpu)
{
	return (u64)FLOW_VTIME_BASE + (u64)cpu;
}
/* Id of the overflow tail shared by every CPU. */
/* Pinned and foreign tasks rest here with mask wins on drain. */
/* Throttled tasks park here too with no kick and lazy refill. */
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
/* Own deadline queue cap under budget 32. */
/* Holds the header cap so overflow and steal keep room. */
static __always_inline u32 flow_own_cap(u32 budget)
{
	if (budget > (u32)FLOW_OWN_VTIME_CAP)
		return (u32)FLOW_OWN_VTIME_CAP;
	return budget;
}
/* Shared tail cap under the dispatch budget. */
/* Returns the min of budget and the header cap with no head stall. */
static __always_inline u32 flow_tail_cap(u32 budget)
{
	if (budget > (u32)FLOW_OVER_CAP)
		return (u32)FLOW_OVER_CAP;
	return budget;
}
/* Gated starvation cap under the dispatch budget. */
/* Returns the min of budget and the header cap with no head stall. */
static __always_inline u32 flow_gated_cap(u32 budget)
{
	if (budget > (u32)FLOW_GATED_CAP)
		return (u32)FLOW_GATED_CAP;
	return budget;
}
#endif
