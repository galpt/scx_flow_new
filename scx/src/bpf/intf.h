// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the flow core.
 *
 * The core parks at the overflow tail and notifies for observability.
 * The core orders through the Van Emde Boas tree and admits under
 * the bound in the core. Init reserves five hundred twelve local
 * queues, eight node queues, machine, overflow as an ABI placeholder
 * so queue identifiers stay stable across releases. Enqueue admits
 * synchronously with share math plus bound check then inserts
 * one key derived from the deadline plus one order row with sequence,
 * deadline, CPU and parks with plain insert. Task state also keeps
 * the deadline plus key from the same period plus deadline plus
 * quantize helpers with zero roundtrip, so dispatch compares without
 * touching order rows. Rejects park at the top key with the far
 * deadline plus no row plus no run, so every parked task stays
 * ordered with rejects last. One kick follows each park to the
 * chosen CPU when idle else one idle peer else one directed preempt
 * to the owner solely when the wakeup runs earlier than the owner
 * task, so urgent arrivals preempt longer runs with at most one kick
 * per park and no storm. Dispatch moves every parked task in global
 * deadline order up to sixteen per pass with no sequence gate and
 * no CPU gate. Each pass picks the least key then deadline then owned
 * then pid among entries the dispatch CPU may run, so any CPU takes
 * the earliest work it may run. The head keeps smallest pid best
 * effort while the full scan orders owned then pid.
 * Affinity plus liveness still gate every move through the same
 * entry check as the fallback path, so the target class never widens.
 * Ordered checks run first
 * so every parked task stays preferred, while the fallback drain moves
 * solely the empty plus corrupt plus stale remainder in queue order up
 * to the batch bound. The pass keeps no flood probe cap, so deep
 * backlog still drains sixteen ordered per pass with the earliest
 * moves kept in order. A recheck miss skips stale and keeps walking
 * within the batch with the fallback left for persistent stale. Stale
 * entries park and the core drops shares through stopping plus
 * disable plus exit plus gate fail paths exactly once. Empty queue
 * leaves at once with no scan. Stall drains solely through the same
 * fallback with liveness plus affinity checks and no order gate so
 * runnable tasks never stall on live work.
 * Ordered moves count one vEB hit plus fallback moves count one
 * FIFO park so every dispatched task lands in one bucket with
 * completions counted apart. Fallback stays as the empty plus corrupt
 * plus stale canary since task state plus tree land synchronously and
 * solely genuine misses reach it. Flood backlog still drains sixteen ordered
 * per pass with rejects ordered at the top key. A single tail avoids cross tier moves that would bounce
 * cache and NUMA locality. Undrained queues hold zero tasks and cost
 * solely at init. Counters use atomic adds from every CPU and stay
 * best effort for observability. Concurrent skips may count twice
 * with parks staying noisy but fail closed. Admits, rejects, misses
 * count in the core as source of truth and merge into the snapshot.
 * The wire stays at 112B. Reads poll at dashboard
 * cadence so line bouncing stays bounded by event rate. Shared
 * fields pair reads with writes through atomics plus volatile
 * access. The watchdog stays at twenty seconds. Admission plus order
 * live in the core with the daemon as monitor. The core holds gate,
 * admit, park, notify, execute. Rings carry observability solely
 * with loss irrelevant to decisions.
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
#ifndef WRITE_ONCE
#define WRITE_ONCE(x, v) (*(volatile typeof(x) *)&(x) = (v))
#endif
enum flow_consts {
	FLOW_QUANTUM_NS = 2000000ULL,
	FLOW_PERIOD_NS = 16000000ULL,
	FLOW_WEIGHT_MIN = 1ULL,
	FLOW_WEIGHT_BASE = 128ULL,
	FLOW_WEIGHT_MAX = 16384ULL,
	FLOW_MAX_CPUS = 512ULL,
	FLOW_MAX_NODES = 8ULL,
	FLOW_HINT_MAX = 4096ULL,
	FLOW_LOCAL_BASE = 0x5100ULL,
	FLOW_NODE_BASE = 0x5900ULL,
	FLOW_MACHINE = 0x5A00ULL,
	FLOW_OVERFLOW = 0x5A01ULL,
	FLOW_MAX_DSQS = 522ULL,
	FLOW_DISPATCH_MAX_BATCH = 16ULL,
	FLOW_DISPATCH_MAX_PROBES = 20ULL,
	FLOW_DISPATCH_FLOOD_PROBES = 4ULL,
	FLOW_DISPATCH_FLOOD_QUEUED = 128ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_PROTO_ENQUEUE = 1ULL,
	FLOW_PROTO_ORDER = 2ULL,
	FLOW_PROTO_DISPATCH = 3ULL,
	FLOW_PROTO_COMPLETE = 4ULL,
	FLOW_SEQ_INIT = 1ULL,
	FLOW_ORDER_DEPTH = 512ULL,
	FLOW_ORDER_CAP = 4096ULL,
	FLOW_VEB_U = 65536ULL,
	FLOW_QUANT_SHIFT = 10ULL,
	FLOW_VEB_EMPTY = 0xFFFFFFFFULL,
	FLOW_ADMIT_PERMILLE = 950ULL,
	/* CPU performance levels at half plus max with no knob. Any local */
	/* plus running picks max else half with no shared use. */
	FLOW_CPU_PERF_HALF = 512ULL,
	FLOW_CPU_PERF_MAX = 1024ULL,
};
struct flow_task_ctx {
	u64 run_at;
	u64 seq;
	u32 admit_share;
	u32 admit_cpu;
	u64 deadline;
	u32 key;
	u32 pad2;
};
struct flow_cpu_state {
	u32 running_pid;
	u32 pad;
};
struct flow_topo {
	u32 smt_sib;
	u32 node;
};
struct flow_sched_stats {
	u64 on_cpu;
	u64 total_runtime;
	u64 inserts;
	u64 requeues;
	u64 completions;
	u64 over_moves;
	u64 kicks;
	u64 admits;
	u64 rejects;
	u64 misses;
	u64 parks;
	u64 gate_rejects;
	u64 veb_hits;
	u64 fifo_parks;
};
struct flow_event {
	u64 kind;
	u64 seq;
	u32 pid;
	u32 cpu;
	u32 weight;
	u32 pad;
	u64 at;
};
struct flow_order_entry {
	u64 seq;
	u64 deadline;
	u32 cpu;
	u32 pad;
};
_Static_assert(sizeof(struct flow_task_ctx) == 40,
	"task state stays at 40B");
_Static_assert(sizeof(struct flow_cpu_state) == 8,
	"cpu state stays at 8B");
_Static_assert(sizeof(struct flow_topo) == 8,
	"topology view stays at 8B");
_Static_assert(sizeof(struct flow_sched_stats) == 112,
	"stats stay at 112B");
_Static_assert(sizeof(struct flow_event) == 40,
	"event stays at 40B");
_Static_assert(sizeof(struct flow_order_entry) == 24,
	"order entry stays at 24B");
_Static_assert(FLOW_MAX_DSQS ==
	FLOW_MAX_CPUS + FLOW_MAX_NODES + 2,
	"dsq count stays local, node, two");
static __always_inline bool flow_time_before(u64 a,
	u64 b)
{
	return (s64)(a - b) < 0;
}
static __always_inline u64 flow_sat_add(u64 a,
	u64 b)
{
	u64 out = a + b;
	if (out < a)
		return (u64)~0ULL;
	return out;
}
static __always_inline u64 flow_local_dsq(u32 cpu)
{
	return (u64)FLOW_LOCAL_BASE + (u64)cpu;
}
static __always_inline u64 flow_node_dsq(u32 node)
{
	return (u64)FLOW_NODE_BASE + (u64)node;
}
static __always_inline u64 flow_machine_dsq(void)
{
	return (u64)FLOW_MACHINE;
}
static __always_inline u64 flow_overflow_dsq(void)
{
	return (u64)FLOW_OVERFLOW;
}
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
	if (dsq == (u64)FLOW_OVERFLOW)
		return true;
	return false;
}
static __always_inline u32 flow_clamp_weight(u32 w)
{
	if (w < (u32)FLOW_WEIGHT_MIN)
		return (u32)FLOW_WEIGHT_MIN;
	if (w > (u32)FLOW_WEIGHT_MAX)
		return (u32)FLOW_WEIGHT_MAX;
	return w;
}
static __always_inline u64 flow_hint_us(u32 weight)
{
	u32 w = flow_clamp_weight(weight);
	if (w < 64)
		return 32000ULL;
	if (w < 128)
		return 16000ULL;
	if (w < 512)
		return 8000ULL;
	return 4000ULL;
}
static __always_inline u64 flow_period_ns(u32 weight)
{
	u64 hint = flow_hint_us(weight);
	if (hint == 0)
		return (u64)FLOW_PERIOD_NS;
	return hint * 1000ULL;
}
static __always_inline u64 flow_deadline_at(u64 now,
	u64 period)
{
	return flow_sat_add(now, period);
}
static __always_inline u64 flow_share_permille(u64 period)
{
	if (period == 0)
		return 0;
	return (u64)FLOW_QUANTUM_NS * 1000ULL / period;
}
static __always_inline bool flow_admit_ok(u64 held,
	u64 share)
{
	return flow_sat_add(held, share) <= (u64)FLOW_ADMIT_PERMILLE;
}
#endif
