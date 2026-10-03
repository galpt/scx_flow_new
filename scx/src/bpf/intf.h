// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow scheduler.
 *
 * The scheduler keeps one local queue per CPU plus one shared queue
 * per node plus one shared queue per machine with no overflow tail.
 * Homeless work waits in the machine queue with all other shared work.
 * Every task carries a release plus a period plus an absolute
 * deadline, and each queue orders by that deadline through the kernel
 * priority queue. Every task joins a queue with no admission bound,
 * so the earliest deadline always runs next. A miss counts when wall
 * time passes the deadline, and the miss rejoins a tier queue with
 * a fresh deadline plus a direct kick and no wait. Placement takes
 * the slowest sufficient CPU among the allowed set that can meet
 * the deadline, so light work never takes a fast CPU that other work
 * needs. Hints from the flat view tune the period only, and no group
 * or pool shapes order. Each stop feeds the burst predictor average
 * plus deviation with shift updates, so later deadlines track recent
 * bursts with no table walk. See select_cpu.bpf.c for placement and
 * enqueue.bpf.c for the deadline choice plus dispatch.bpf.c for the
 * tier scans and lifecycle.bpf.c for the miss count and timer.bpf.c
 * for the leftover charge plus the miss count.
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
/* Fixed slice of 1ms with no knob. Every insert uses this slice. */
/* One ms matches the cheapest wakeup granularity, so one slice */
/* always spans one wakeup with no extra hold. */
enum flow_consts {
	FLOW_QUANTUM_NS = 1000000ULL,
	/* Default period of 16ms with no knob. Holds sixteen slices, */
	/* so a fully used task still leaves room for one wait plus */
	/* one retry inside the period. */
	FLOW_PERIOD_NS = 16000000ULL,
	/* Predictor bounds with no knob. Holds 1ns to 1s, so a huge */
	/* burst clamps instead of wrapping to a short deadline. */
	FLOW_PRED_MIN_NS = 1ULL,
	FLOW_PRED_MAX_NS = 1000000000ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_BASE = 128ULL,
	FLOW_WEIGHT_MAX = 16384ULL,
	/* CPU bound of 512 rows with no knob. Covers the largest test */
	/* host with wide margin while halving array memory. */
	FLOW_MAX_CPUS = 512ULL,
	/* Node bound of 8 rows with no knob. Covers the largest test */
	/* host with wide margin while keeping the node scan small. */
	FLOW_MAX_NODES = 8ULL,
	/* Hint bound of 4096 rows with no knob. Keys are hierarchy ids */
	/* with no dense use, so the table holds large hosts with room */
	/* for churn. Full tables fail closed to the default period */
	/* with no eviction and no stall. */
	FLOW_HINT_MAX = 4096ULL,
	/* Local queue region base. Holds 512 ids, one per CPU. */
	FLOW_LOCAL_BASE = 0x5100ULL,
	/* Node queue region base. Holds 8 ids, one per node. */
	FLOW_NODE_BASE = 0x5900ULL,
	/* Machine queue id shared by every CPU. */
	FLOW_MACHINE = 0x5A00ULL,
	/* Queue count of 521. Holds 512 local plus 8 node plus one */
	/* machine with no overflow. */
	FLOW_MAX_DSQS = 521ULL,
	/* Dispatch visit cap of 64 entries per pass with no knob. Caps */
	/* visited entries per pass regardless of moves, so one pass never */
	/* holds RCU across the whole queue on mask misses. Moves stay */
	/* uncapped to remaining dispatch slots, and leftover work resumes */
	/* next pass, so the pass stays work conserving across passes. */
	FLOW_DISPATCH_MAX_VISIT = 64ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Base capacity of 1024 units with no knob. Every CPU on a */
	/* symmetric host offers the same units, so the slowest */
	/* sufficient pick falls to the lowest sufficient id. */
	FLOW_CAP_BASE = 1024ULL,
	/* CPU performance levels at half plus max with no knob. Any own */
	/* plus local plus running picks max else half with no shared use. */
	FLOW_CPU_PERF_HALF = 512ULL,
	FLOW_CPU_PERF_MAX = 1024ULL,
	/* Preempt leads by 100us with no knob, so near ties never bounce */
	/* while urgent gaps still preempt at once. The floor stays at */
	/* 100us with one kick per wait. */
	FLOW_PREEMPT_MARGIN_NS = 100000ULL,
	/* Preempt waits out a 100us tail with no knob, so a nearly done */
	/* owner finishes instead of taking a kick. The floor stays at */
	/* 100us with one kick per wait. */
	FLOW_PREEMPT_TAIL_NS = 100000ULL,
	/* Allowed lag bound of 2ms with no knob. Newly woken tasks clamp */
	/* within this distance of the CPU minimum, so sleepers gain no */
	/* more than one extra slice of boost with no storm. */
	FLOW_VLAG_MAX_NS = 2000000ULL,
};
/* Static dispatch tier order with no reorder. Local plus node plus */
/* machine drain in deadline order through the kernel priority queue */
/* with no overflow tail. Every pass follows this order with no load */
/* based swap, so the verifier sees one fixed path. Dead enum with no */
/* code use, kept doc only since dispatch calls the tier moves */
/* directly with no index switch. */
enum flow_tier {
	FLOW_TIER_LOCAL = 0,
	FLOW_TIER_NODE = 1,
	FLOW_TIER_MACHINE = 2,
};
/* Per task state at 64B with vruntime plus deadline plus stamps plus */
/* predictor plus lag plus weight plus slice plus hint plus misses. */
/* Vruntime holds the scaled service in nanos with zero for no history. */
/* A zero vruntime means no service yet, so the first virtual deadline */
/* falls near now with no boost past the lag bound. Deadline holds the */
/* absolute EDF deadline for queue order and the miss check. A zero */
/* deadline means no order yet, so preempt compares skip with no kick */
/* and the miss check skips with no count. Wait holds the last enqueue */
/* time. A zero wait means the task never queued. Every queue join */
/* stamps the task, so queued work always carries a stamp. Run holds */
/* the segment start while on CPU else zero, so a claimed start pairs */
/* the stopping charge with no BPF gauge. The on CPU gauge lives in */
/* the snapshot with no BPF count. Running claims from zero only with */
/* a compare and swap, so a second running without a stop keeps the */
/* first start with no second use. Stopping versus disable or exit */
/* claims once with atomics, so each claimed start meets exactly one */
/* charge with no owner gate. Period holds the relative period in nanos */
/* for the next deadline in 32 bits with zero for no hint. Avg holds */
/* the burst average in nanos in 32 bits with zero for no history. Dev */
/* holds the burst deviation in nanos in 32 bits with zero for no */
/* history. Values clamp to 1ns to 1s, so a huge burst never wraps. */
/* Vlag holds the allowed lag in nanos as a signed bound with zero for */
/* no slack. Weight holds the scheduling share clamped to range with */
/* 128 for neutral. Slice holds the per task slice in nanos with the */
/* quantum as the default. Hint holds the flat period hint in micros */
/* for the deadline. A zero hint means no hint, so the default period */
/* applies. Misses holds the count of deadline misses for the life of */
/* the task with saturating adds, so a huge miss count clamps instead */
/* of wrapping. Stamps stay per task owned with no atomics except the */
/* run claim, only counters use atomics. Cursor and miss scans stay */
/* best effort with no atomic order. */
struct flow_task_ctx {
	u64 vruntime;
	u64 deadline;
	u64 wait_at;
	u64 run_at;
	u32 period;
	u32 avg_ns;
	u32 dev_ns;
	s32 vlag;
	u32 weight;
	u32 slice_ns;
	u32 hint_us;
	u32 misses;
};
/* Per CPU state at 16B with running pid plus placement cursor plus */
/* minimum vruntime. Pid holds the task now on the CPU else zero. */
/* Owner clears use a compare and swap, so a stale exit never clears a */
/* new owner. Cursor spreads the placement scans with no hotspot. The */
/* cursor races best effort with no atomic order. Min vruntime tracks */
/* the smallest served vruntime on the CPU with zero for no history, */
/* so newly woken tasks clamp without gaining past the lag bound. */
/* Dispatch uses a fixed tier order with no cursor use. */
struct flow_cpu_state {
	u32 running_pid;
	u32 cursor;
	u64 min_vruntime;
};
/* Per CPU topology view at 8B with sibling plus node. */
/* Smt sib holds the thread sibling or all ones when unknown. */
/* Node holds the node id used by placement and dispatch. */
struct flow_topo {
	u32 smt_sib;
	u32 node;
};
/* Per CPU capacity view at 4B with one units row. */
/* Units hold the capacity in base units for the slowest sufficient */
/* pick. A zero row means unknown, so the base applies. */
struct flow_cpu_cap {
	u32 units;
};
/* Flat period plus weight hint at 8B with one row per id. */
/* Period holds the period in micros with zero for no hint, and weight */
/* holds the scheduling share with 128 for neutral. The flat view tunes */
/* the period plus the weight only, and no group or pool shapes order. */
struct flow_hint {
	u32 period_us;
	u32 weight;
};
/* Scheduler counters with 13 fields. Homeless work counts in the */
/* machine moves, so every tier move has a live counter. Rejects stay */
/* dead at zero for wire compat only with no writer, while real rejects */
/* count in gate_rejects. Readers must use gate_rejects for drops. */
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 local_moves;
	u64 node_moves;
	u64 machine_moves;
	u64 kicks;
	u64 admits;
	u64 rejects;
	u64 misses;
	u64 gate_rejects;
};
/* Task state holds vruntime plus deadline plus stamps plus predictor */
/* plus lag plus weight plus slice plus hint plus misses in 64 bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 64,
	"task state stays at 64B");
/* CPU state holds pid plus cursor plus minimum vruntime in 16 bytes. */
_Static_assert(sizeof(struct flow_cpu_state) == 16,
	"cpu state stays at 16B");
/* Topology view holds sibling plus node in 8 bytes. */
_Static_assert(sizeof(struct flow_topo) == 8,
	"topology view stays at 8B");
/* Stats hold 13 counters in 104 bytes. */
_Static_assert(sizeof(struct flow_sched_stats) == 104,
	"stats stay at 104B");
/* Queue count holds local plus node plus machine with no overflow. */
_Static_assert(FLOW_MAX_DSQS ==
	FLOW_MAX_CPUS + FLOW_MAX_NODES + 1,
	"dsq count stays local plus node plus one");
/* True when the first time is before the second with wrap safety. */
/* The signed diff keeps order across the u64 wrap with no branch. */
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
/* Saturated add of two times with clamp on wrap. */
/* A wrap clamps to max, so a huge sum never falls to the front. */
static __always_inline u64 flow_sat_add(u64 a,
	u64 b)
{
	u64 out = a + b;
	if (out < a)
		return (u64)~0ULL;
	return out;
}
/* Weight of one hint level clamped into range. */
/* Zero or oversize weights fail closed to the nearer bound. */
static __always_inline u32 flow_weight_clamp(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
/* Scaled service for one delta at one weight with no divide. */
/* The neutral weight of 128 keeps the delta unchanged, lighter tasks */
/* shift left for more charge while heavier tasks shift right for less */
/* charge. Bands follow powers of two with saturation on shift, so the */
/* verifier sees no divide and a huge shift clamps instead of wrapping. */
static __always_inline u64 flow_scaled_delta(u64 delta,
	u32 weight)
{
	u32 w = flow_weight_clamp(weight);
	u64 out;
	if (w < 16U) {
		if (delta > ((u64)~0ULL >> 4))
			return (u64)~0ULL;
		return delta << 4;
	}
	if (w < 32U) {
		if (delta > ((u64)~0ULL >> 3))
			return (u64)~0ULL;
		return delta << 3;
	}
	if (w < 64U) {
		if (delta > ((u64)~0ULL >> 2))
			return (u64)~0ULL;
		return delta << 2;
	}
	if (w < 96U) {
		if (delta > ((u64)~0ULL >> 1))
			return (u64)~0ULL;
		return delta << 1;
	}
	if (w < 192U)
		return delta;
	if (w < 384U)
		return delta >> 1;
	if (w < 768U)
		return delta >> 2;
	if (w < 1536U)
		return delta >> 3;
	if (w < 3072U)
		return delta >> 4;
	if (w < 6144U)
		return delta >> 5;
	out = delta >> 6;
	if (out == 0 && delta != 0)
		return 1;
	return out;
}
/* Advanced vruntime after one delta at one weight with saturation. */
/* Adds the scaled service to the base, so heavy tasks advance slowly */
/* while light tasks advance quickly with no divide. A wrap clamps to */
/* max, so a huge vruntime never falls to the front. */
static __always_inline u64 flow_vruntime_advance(u64 vruntime,
	u64 delta, u32 weight)
{
	return flow_sat_add(vruntime, flow_scaled_delta(delta, weight));
}
/* Clamped lag in nanos within the allowed bound. */
/* Values past plus or minus 2ms fold to the nearer bound, so a stale */
/* lag never grants a huge boost with no storm. */
static __always_inline s32 flow_lag_clamp(s32 lag)
{
	s32 bound = (s32)FLOW_VLAG_MAX_NS;
	if (lag > bound)
		return bound;
	if (lag < -bound)
		return -bound;
	return lag;
}
/* True when one vruntime is eligible against the CPU minimum. */
/* Eligible means the vruntime falls no more than the allowed lag past */
/* the minimum, so lagging tasks wait while leading tasks pace. The */
/* signed diff keeps order across the u64 wrap with no branch, and a */
/* saturated minimum plus lag never wraps to the front. */
static __always_inline bool flow_eligible(u64 vruntime,
	u64 min_vruntime, s32 vlag)
{
	s32 lag = flow_lag_clamp(vlag);
	u64 limit;
	if (lag < 0)
		lag = 0;
	limit = flow_sat_add(min_vruntime, (u64)lag);
	if (limit == (u64)~0ULL)
		return true;
	if (vruntime == limit)
		return true;
	return flow_time_before(vruntime, limit);
}
/* Virtual deadline from eligible plus request over weight. */
/* Adds the scaled request to the eligible base with saturation, so a */
/* heavy task earns a near deadline while a light task earns a far one */
/* with no divide. A wrap clamps to max, so a huge sum never jumps to */
/* the front. */
static __always_inline u64 flow_virt_deadline(u64 ve,
	u64 request, u32 weight)
{
	return flow_sat_add(ve, flow_scaled_delta(request, weight));
}
/* Fair queue key as the earlier of deadline plus virtual deadline. */
/* The EDF deadline caps latency while the virtual deadline paces */
/* fairness, so urgent tasks still win while hogs fall behind. A zero */
/* deadline means no EDF order yet, so the virtual deadline rules. The */
/* signed diff picks the earlier time with wrap safety. */
static __always_inline u64 flow_fair_vtime(u64 deadline,
	u64 vd)
{
	if (deadline == 0)
		return vd;
	if (vd == 0)
		return deadline;
	if (flow_time_before(vd, deadline))
		return vd;
	return deadline;
}
/* Absolute deadline from release plus relative period. */
/* The add saturates, so a huge release clamps instead of wrapping */
/* to the front. */
static __always_inline u64 flow_deadline_at(u64 release,
	u64 period)
{
	return flow_sat_add(release, period);
}
/* Period for one task from hint else default. */
/* A zero hint means no hint, so the default period applies. The hint */
/* converts from micros to nanos with saturation, so a huge hint */
/* clamps instead of wrapping to a short period. */
static __always_inline u64 flow_task_period(u32 hint_us)
{
	u64 hint;
	if (!hint_us)
		return (u64)FLOW_PERIOD_NS;
	hint = (u64)hint_us;
	if (hint > 18446744073709551ULL)
		return (u64)~0ULL;
	return hint * 1000ULL;
}
/* Clamped predictor value in 1ns to 1s with no wrap. */
/* Values below the floor rise to 1ns and values past the top fall */
/* to 1s, so a huge burst never wraps to a short deadline. */
static __always_inline u64 flow_pred_clamp(u64 v)
{
	if (v < (u64)FLOW_PRED_MIN_NS)
		return (u64)FLOW_PRED_MIN_NS;
	if (v > (u64)FLOW_PRED_MAX_NS)
		return (u64)FLOW_PRED_MAX_NS;
	return v;
}
/* Updated burst average with shift 3 and saturation. */
/* A zero average means no history, so the first sample sets the */
/* average at once. Later samples move one eighth toward the new */
/* delta with shifts only, so the verifier keeps no divide. The */
/* result clamps to 1ns to 1s, so a spike never wraps. */
static __always_inline u64 flow_pred_avg(u64 avg,
	u64 delta)
{
	u64 d;
	u64 diff;
	d = flow_pred_clamp(delta ? delta :
	    (u64)FLOW_PRED_MIN_NS);
	if (avg == 0)
		return d;
	if (d > avg) {
		diff = (d - avg) >> 3;
		return flow_pred_clamp(flow_sat_add(avg,
		    diff));
	}
	diff = (avg - d) >> 3;
	if (diff > avg)
		return (u64)FLOW_PRED_MIN_NS;
	return flow_pred_clamp(avg - diff);
}
/* Updated burst deviation with shift 2 and saturation. */
/* Tracks the absolute error between delta and average with one */
/* quarter steps, so a stable burst keeps a small margin while a */
/* ragged burst widens the deadline with no jump. A zero deviation */
/* means no history, so the first value takes the max of error and */
/* average quarter as the floor. The result clamps the same way with */
/* no divide and shifts stay at 2. */
static __always_inline u64 flow_pred_dev(u64 dev,
	u64 avg, u64 delta)
{
	u64 d;
	u64 a;
	u64 err;
	u64 diff;
	u64 floor;
	d = flow_pred_clamp(delta ? delta :
	    (u64)FLOW_PRED_MIN_NS);
	a = avg ? avg : d;
	err = d > a ? d - a : a - d;
	err = flow_pred_clamp(err ? err :
	    (u64)FLOW_PRED_MIN_NS);
	if (dev == 0) {
		floor = avg >> 2;
		if (floor > err)
			return flow_pred_clamp(floor);
		return err;
	}
	if (err > dev) {
		diff = (err - dev) >> 2;
		return flow_pred_clamp(flow_sat_add(dev,
		    diff));
	}
	diff = (dev - err) >> 2;
	if (diff > dev)
		return (u64)FLOW_PRED_MIN_NS;
	return flow_pred_clamp(dev - diff);
}
/* Predicted period from average plus deviation with fallback. */
/* A zero average means no history, so the default period applies. */
/* Later periods add average plus deviation with saturation, so a */
/* stable burst keeps a tight deadline while a ragged burst holds */
/* margin with no wrap past 1s. */
static __always_inline u64 flow_pred_period(u64 avg,
	u64 dev)
{
	u64 sum;
	if (avg == 0)
		return (u64)FLOW_PERIOD_NS;
	sum = flow_sat_add(avg, dev);
	if (sum == (u64)~0ULL)
		return (u64)FLOW_PRED_MAX_NS;
	return flow_pred_clamp(sum);
}
/* Predicted deadline from release plus predictor else hint period. */
/* A zero average means no history, so the hint period applies with */
/* the default when the hint is zero. Later releases add the */
/* predicted period with saturation, so a huge release clamps */
/* instead of wrapping to the front. Fair order via kernel priority */
/* queue: the vtime key holds the earlier of this deadline plus the */
/* virtual deadline, so the earliest fair time wins with lag bounds. */
static __always_inline u64 flow_pred_deadline(u64 release,
	u64 avg, u64 dev, u32 hint_us)
{
	u64 period;
	if (avg == 0)
		period = flow_task_period(hint_us);
	else
		period = flow_pred_period(avg, dev);
	return flow_deadline_at(release, period);
}
/* Fallback deadline from now plus the hint period with saturation. */
/* Tasks with no state or no history join a tier queue at once with */
/* this deadline, so no path needs a tail queue with no wait. */
static __always_inline u64 flow_fallback_deadline(u64 now,
	u32 hint_us)
{
	return flow_deadline_at(now, flow_task_period(hint_us));
}
/* True when one task missed its deadline at the given time. */
/* A zero deadline means no order yet, so the check skips. A time that */
/* falls before or on the deadline passes, so only a strictly later */
/* time counts a miss with wrap safety. */
static __always_inline bool flow_missed(u64 deadline,
	u64 now)
{
	if (deadline == 0)
		return false;
	if (flow_time_before(now, deadline))
		return false;
	if (now == deadline)
		return false;
	return true;
}
/* Local queue id of one CPU from base plus id. */
/* One ordered queue per CPU keeps deadline order local. */
static __always_inline u64 flow_local_dsq(u32 cpu)
{
	return (u64)FLOW_LOCAL_BASE + (u64)cpu;
}
/* Shared queue id of one node from base plus id. */
/* One ordered queue per node shares work inside the node. */
static __always_inline u64 flow_node_dsq(u32 node)
{
	return (u64)FLOW_NODE_BASE + (u64)node;
}
/* Id of the machine queue shared by every CPU. */
/* Work with no node home rests here with mask wins on drain. */
static __always_inline u64 flow_machine_dsq(void)
{
	return (u64)FLOW_MACHINE;
}
/* True when one id names a live scheduler queue. */
/* Local plus node plus machine pass, and all other ids fail, so a */
/* stale id never moves work. */
static __always_inline bool flow_dsq_valid(u64 dsq)
{
	if (dsq >= (u64)FLOW_LOCAL_BASE &&
	    dsq < (u64)FLOW_LOCAL_BASE + (u64)FLOW_MAX_CPUS)
		return true;
	if (dsq >= (u64)FLOW_NODE_BASE &&
	    dsq < (u64)FLOW_NODE_BASE + (u64)FLOW_MAX_NODES)
		return true;
	if (dsq == (u64)FLOW_MACHINE)
		return true;
	return false;
}
#endif
