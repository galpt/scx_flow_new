// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one global deadline tree ordered by deadline
 * then sequence, and it uses the kernel global queue for homeless
 * work. Every task carries virtual runtime advanced by scaled
 * execution, and each insert keys past the later of that runtime
 * and a floor that tracks the last dispatched deadline, so a long
 * sleep never earns credit. The effective share folds the task
 * weight with the hierarchy weights along the ancestors, so a task
 * under a light parent waits longer. Bandwidth pools cap runtime
 * per period with lazy refill, and throttled work parks in a first
 * in first out ring. A single lock guards the tree plus the ring,
 * the key forms before the lock, and kicks plus frequency plus
 * pool drain run after the unlock. Frequency moves at most one
 * cache domain per timer tick with a minimum gap, so transitions
 * stay coalesced. See enqueue.bpf.c for the key choice,
 * cgroup.bpf.c for the hierarchy state, lifecycle.bpf.c for the
 * runtime count, dispatch.bpf.c for the drain order, and
 * select_cpu.bpf.c for the hint only placement.
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
/* Shared scheduling constants with no service quantum. */
/* Dispatch moves at most one batch per pass with no per queue caps. */
/* The batch stays small, so one pass verifies fast and a deep tree */
/* cannot stall a CPU past a short bound. */
/* Nodes cap at 32768 live tasks with exact removal by pid. */
/* The park ring holds 4096 parked pids in arrival order. */
/* Frequency keeps 64 cache slots with a 16ms minimum gap inside */
/* the 10ms to 32ms window, so boosts coalesce per domain. */
enum flow_consts {
	FLOW_WEIGHT_BASE = 100ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_MAX = 10000ULL,
	FLOW_MAX_CPUS = 1024ULL,
	FLOW_DISPATCH_BATCH = 16ULL,
	FLOW_PARK_BATCH = 4ULL,
	/* Park recycle visits at most 4 per pass. Parks are exceptional */
	/* beside the tree flow, so a short bound keeps the jump chains */
	/* loadable with no head stall past the bound. */
	/* Homeless scan visits at most 4 per pass. Homeless tasks are */
	/* exceptional, so a short iterator bound keeps the pass small */
	/* with no head stall past the bound. */
	FLOW_GLOBAL_SCAN = 4ULL,
	FLOW_NODE_MAX = 32768ULL,
	FLOW_PARK_NR = 4096ULL,
	FLOW_LLC_MAX = 64ULL,
	FLOW_CPUFREQ_MIN_NS = 16000000ULL,
	FLOW_SCAN_BOUND = 8ULL,
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
	/* Fixed point scale for the paper share math at 1024. */
	/* Utilization plus density keep one unit here, so a value */
	/* past 1024 means overload with no extra table. */
	FLOW_SSF_SCALE = 1024ULL,
	/* Parked chain ring slots at 64. Each slot holds one park chain */
	/* of 8 ancestor ids with the leaf first. The timer refills each */
	/* listed pool, and enqueue refills cover active groups past it. */
	FLOW_PARK_HINT_NR = 64ULL,
	/* Throttle bit in the hierarchy flags. Set means park gate. */
	FLOW_CGRP_THROTTLED = 1ULL,
};
/* Unlimited quota value with no cap use and zero pool. */
#define FLOW_RUNTIME_INF (~0ULL)
/* Per task state at 56B with runtime plus key plus share cache. */
/* Deadline holds the last assigned key deadline for the next clamp */
/* and for the preempt compare. A zero deadline means no order yet, */
/* so preempt compares skip with no kick. Vruntime advances by */
/* scaled execution only while on CPU, so order carries weight with */
/* no fixed service step. Wait holds the last enqueue time for */
/* diagnostics with no dispatch gate. Run holds the segment start */
/* zero, so a claimed start pairs the on CPU gauge with the stopping */
/* charge. Running claims from zero only with a compare and swap, so */
/* a second running without a stop keeps the first start with no */
/* second count. Stopping versus disable or exit claims once with */
/* atomics, so each counted start meets exactly one gauge drop with */
/* no owner gate. Cgid holds the last hierarchy id for the cache, */
/* eweight holds the hierarchy share with base 100, cached marks a */
/* valid entry, and generation holds the low bits of the global */
/* generation for validation. The low bits wrap past 64k bumps, so */
/* a wrap needs 64k bumps with no move to falsely hit. Moves clear */
/* the cache, so the window stays huge. Queued holds two for a parked */
/* node, one for a node on the tree, else zero, so the park drain */
/* serves parked nodes only with no double serve from a stale ring */
/* pid. Seq */
/* holds the last assigned key sequence, so a popped node with a */
/* mismatched sequence reads stale from pid reuse with no harm. Run */
/* llc holds the domain counted at the claimed start, so the stop */
/* withdraws from the same domain after a migration with no drift. */
struct flow_task_ctx {
	u64 deadline;
	u64 vruntime;
	u64 wait_at;
	u64 run_at;
	u64 cgid;
	u64 seq;
	u32 eweight;
	u32 run_llc;
	u16 generation;
	u8 cached;
	u8 queued;
};
/* One deadline tree node per live task with key plus owner pid. */
/* Lives in main.bpf.c with kernel types, since the bindings parse */
/* this header standalone. Deadline plus seq form the key with */
/* sequence unique per insert, so equal deadlines order by arrival. */
/* Pid names the owner for the resolve after the unlock. Nodes move */
/* between the stash slot and the tree with take before add, so the */
/* tree never shares a node with the map while linked. Stash slots */
/* hold the off tree node with map ownership, and null means the */
/* node is on the tree or in flight through a pop. */
/* Per CPU state at 8B with running pid plus placement cursor. */
/* Pid holds the task now on the CPU else zero. Owner clears use a */
/* compare and swap, so a stale exit never clears a new owner. */
/* Release clears with a compare and swap loop, so concurrent runs */
/* pair without a torn zero. Cursor spreads the placement scan with */
/* no hotspot. The cursor races best effort with no atomic order. */
struct flow_cpu_state {
	u32 running_pid;
	u32 cursor;
};
/* Per CPU topology view at 8B with sibling plus domain. */
/* Smt sib holds the thread sibling or all ones when unknown. */
/* Llc holds the cache domain used by placement and frequency. */
struct flow_topo {
	u32 smt_sib;
	u32 llc;
};
/* Per hierarchy state at 48B with share plus bandwidth pool. */
/* Weight holds the share in 1 to 10000 with base 100. */
/* Flags holds the throttle bit with atomic updates, so parks never */
/* bypass a drained ancestor. Bit 0 set means throttled with a park */
/* gate, clear means admittable. Full walks plus consume set it, full */
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
/* Per cache frequency state at 24B with tag plus busy plus level. */
/* Tag holds the domain id plus one with zero meaning empty, so */
/* domain zero never reads empty. Busy counts running tasks from */
/* the pid view with atomics, so wakeups need no scan. Boosted */
/* holds the applied level with one at full and zero at rest. Last */
/* holds the last transition time, so transitions keep the minimum */
/* gap with hysteresis on both edges. */
struct flow_llc_perf {
	u32 tag;
	u32 busy;
	u32 boosted;
	u32 __pad;
	u64 last;
};
/* Scheduler counters with 16 live fields. */
/* enq_no_tctx counts missing state plus homeless with no route, */
/* the name stays for the wire with no split. Tree moves counts */
/* dispatch pops from the deadline tree. Park moves counts park */
/* ring drains. Nr throttled counts throttle hits, and parked counts */
/* every ring arrival with the names kept for the wire. Cpuperf sets */
/* counts applied frequency transitions at domain scope. Bw moves */
/* counts the hierarchy moves. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 park_moves;
	u64 tree_moves;
	u64 kicks;
	u64 enq_no_tctx;
	u64 preempt_kicks;
	u64 preempt_skipped;
	u64 global_moves;
	u64 nr_throttled;
	u64 parked;
	u64 bw_moves;
	u64 cpuperf_sets;
};
/* Task state holds runtime plus key plus cache in 64 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 64,
    "task state stays at 64B");
/* CPU state holds pid plus cursor in 8 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 8,
    "cpu state stays at 8B");
/* Topology view holds sibling plus domain in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
    "topology view stays at 8B");
/* Hierarchy state holds share plus pool in 48 bytes. */
_Static_assert(sizeof(struct flow_cgrp_ctx) == 48,
    "hierarchy state stays at 48B");
/* Frequency state holds tag plus busy plus level in 24 bytes. */
_Static_assert(sizeof(struct flow_llc_perf) == 24,
    "frequency state stays at 24B");
/* Stats hold 16 counters in 128 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 128,
    "stats stay at 128B");
/* Timer ticks at 10ms, always covering the 1ms floor. */
_Static_assert(FLOW_BW_TIMER_NS == 10000000ULL,
    "timer stays at 10ms");
/* Share scale stays at 1024 with no knob. */
_Static_assert(FLOW_SSF_SCALE == 1024ULL,
    "share scale stays at 1024");
/* Frequency gap stays inside the 10ms to 32ms window. */
_Static_assert(FLOW_CPUFREQ_MIN_NS >= 10000000ULL &&
    FLOW_CPUFREQ_MIN_NS <= 32000000ULL,
    "frequency gap stays in window");
/* Parked chain holds 8 ancestor ids with the leaf first. */
struct flow_park_chain {
	u64 ids[8];
};
_Static_assert(sizeof(struct flow_park_chain) == 64,
    "park chain stays at 64B");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Later of two times with wrap safety. */
/* The later time wins, so a fresh key never trails the clock. */
static __always_inline u64 flow_time_max(u64 a,
	u64 b)
{
	if (flow_time_before(a, b))
		return b;
	return a;
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
/* Advanced virtual runtime after one execution segment. */
/* Scales raw time by base over effective weight with no overflow, */
/* so heavy shares advance slowly and light shares advance fast. */
/* The split divide keeps every intermediate below one million, so */
/* a long segment never wraps past the sum. Zero weight never */
/* divides, since the clamp keeps one as the least share. */
static __always_inline u64 flow_vruntime_advance(u64 vruntime,
	u64 delta, u32 eff_w)
{
	u32 w = flow_weight_clamp(eff_w);
	u64 base = (u64)FLOW_WEIGHT_BASE;
	u64 adv;
	adv = delta / (u64)w * base + delta % (u64)w * base /
	    (u64)w;
	if (adv > (u64)~0ULL - vruntime)
		return (u64)~0ULL;
	return vruntime + adv;
}
/* Key deadline from runtime with the floor clamp. */
/* The later of runtime and floor wins, so a long sleep never earns */
/* credit and a back to back arrival queues past its own runtime. */
static __always_inline u64 flow_deadline_clamp(u64 vruntime,
	u64 floor)
{
	return flow_time_max(vruntime, floor);
}
/* True when the first key orders before the second key. */
/* Pure signed diffs on both fields with no other input, so equal */
/* deadlines fall back to arrival sequence with no tie stall. */
static __always_inline bool flow_edf_less(u64 a_deadline,
	u64 a_seq, u64 b_deadline, u64 b_seq)
{
	if (a_deadline != b_deadline)
		return (s64)(a_deadline - b_deadline) < 0;
	return (s64)(a_seq - b_seq) < 0;
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
/* Paper share math in the live path with the rest out of scope. */
/* Demand bound plus load with lambda, mu, and beta need per task */
/* period plus deadline plus suspension terms with loops and extra */
/* dividers that do not fit the verifier budget yet, so they stay */
/* out of scope for this slice with no frozen stubs. The live subset */
/* keeps one share plus slack plus deadline with at most one divider, */
/* and the share runs once on the enqueue path. The window serves as */
/* both period and span, so one share covers both with no second call. */
/* The estimate scales the window by weight once, so the single share */
/* carries weight with no second bias. */
/* Share of one period used by execution in scale units. */
/* Zero period fails closed to full with no divide, huge execution */
/* saturates with no wrap, so overload reads past scale. One divider. */
/* The live path calls once with the starvation window as both period */
/* and span, so density stays as the span variant for tests with no */
/* second live call. */
static __always_inline u32 flow_ssf_util(u64 exec,
	u64 period)
{
	u64 scaled;
	if (period == 0)
		return (u32)FLOW_SSF_SCALE;
	if (exec > 18014398509481983ULL)
		return 0xffffffffU;
	scaled = exec * (u64)FLOW_SSF_SCALE / period;
	if (scaled > 0xffffffffULL)
		return 0xffffffffU;
	return (u32)scaled;
}
/* Share of one span used by execution in scale units. */
/* Zero span fails closed to full with no divide, huge execution */
/* saturates with no wrap, so overload reads past scale. One divider. */
static __always_inline u32 flow_ssf_density(u64 exec,
	u64 span)
{
	u64 scaled;
	if (span == 0)
		return (u32)FLOW_SSF_SCALE;
	if (exec > 18014398509481983ULL)
		return 0xffffffffU;
	scaled = exec * (u64)FLOW_SSF_SCALE / span;
	if (scaled > 0xffffffffULL)
		return 0xffffffffU;
	return (u32)scaled;
}
/* Remaining span past execution with floor at zero. */
/* A short span fails closed to zero with no divide, so overload */
/* carries no slack and the key holds the base. */
static __always_inline u64 flow_ssf_slack(u64 span,
	u64 exec)
{
	if (span > exec)
		return span - exec;
	return 0;
}
/* Key deadline past the later of base and now with slack. */
/* The later time wins with wrap safety, then slack adds with */
/* saturation, so a long sleep never earns credit and overload */
/* holds the base with no wrap. No divider. */
static __always_inline u64 flow_ssf_deadline(u64 base,
	u64 now, u64 slack)
{
	u64 at = flow_time_max(base, now);
	if (slack > (u64)~0ULL - at)
		return (u64)~0ULL;
	return at + slack;
}
#endif
