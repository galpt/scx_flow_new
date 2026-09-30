// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants and helpers for the thin core.
 *
 * The core parks FIFO at the overflow tail and notifies the daemon.
 * The daemon orders through the quantized tree and admits under the
 * bound. Init reserves five hundred twelve local queues plus eight
 * node queues plus machine plus overflow as an ABI placeholder so
 * queue identifiers stay stable across releases. Dispatch drains the
 * overflow tail solely with FIFO order. A single tail avoids cross
 * tier moves that would bounce cache and NUMA locality. Undrained
 * queues hold zero tasks and cost solely at init. Counters use atomic
 * adds from every CPU and stay best effort for observability. Reads
 * poll at dashboard cadence so line bouncing stays bounded by event
 * rate. Shared fields pair reads with writes through atomics plus
 * volatile access. The watchdog stays at twenty seconds. Policy lives
 * in the daemon. The core holds gate plus park plus notify plus
 * execute.
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
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_PROTO_ENQUEUE = 1ULL,
	FLOW_PROTO_ORDER = 2ULL,
	FLOW_PROTO_DISPATCH = 3ULL,
	FLOW_PROTO_COMPLETE = 4ULL,
	FLOW_SEQ_INIT = 1ULL,
	FLOW_ORDER_DEPTH = 512ULL,
	FLOW_VEB_U = 65536ULL,
	FLOW_QUANT_SHIFT = 10ULL,
};
struct flow_task_ctx {
	u64 run_at;
	u64 seq;
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
	u64 local_moves;
	u64 node_moves;
	u64 machine_moves;
	u64 over_moves;
	u64 kicks;
	u64 admits;
	u64 rejects;
	u64 misses;
	u64 parks;
	u64 gate_rejects;
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
_Static_assert(sizeof(struct flow_task_ctx) == 16,
	"task state stays at 16B");
_Static_assert(sizeof(struct flow_cpu_state) == 8,
	"cpu state stays at 8B");
_Static_assert(sizeof(struct flow_topo) == 8,
	"topology view stays at 8B");
_Static_assert(sizeof(struct flow_sched_stats) == 120,
	"stats stay at 120B");
_Static_assert(sizeof(struct flow_event) == 40,
	"event stays at 40B");
_Static_assert(FLOW_MAX_DSQS ==
	FLOW_MAX_CPUS + FLOW_MAX_NODES + 2,
	"dsq count stays local plus node plus two");
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
#endif
