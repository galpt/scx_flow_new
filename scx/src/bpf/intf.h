// SPDX-License-Identifier: GPL-2.0
/*
 * Shared ABI for the flow scheduler.
 *
 * DSQs are one per LLC plus one fallback. Pair queues are arena DHQs
 * owned by this scheduler. Stats are four counters per LLC.
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
	/* Ops timeout in ms for the watchdog. */
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	/* Strand balance bound on enqueue with no knob. */
	FLOW_DHQ_MAX_IMBALANCE = 3ULL,
	/* Base DSQ id for per LLC queues. LLC id adds to the base. */
	FLOW_LLC_BASE = 0x6000ULL,
	/* Single fallback DSQ id used when pairing is off or full. */
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	/* Strand fixed A. */
	FLOW_STRAND_A = 0ULL,
	/* Strand fixed B. */
	FLOW_STRAND_B = 1ULL,
	/* Dequeue picks the lowest vtime with fallback. */
	FLOW_MODE_PRIORITY = 1ULL,
};
/* Per task state for the life of the task. Small with no padding drift. */
struct flow_task_ctx {
	u64 vtime;
	u32 strand;
	u32 llc_id;
	u32 flags;
	u32 pad;
};
/* Per CPU view seeded once from userspace. Small with no frozen row. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 llc_id;
	u32 node_id;
	u32 pad;
};
/* Seeded topology row per CPU with node plus LLC. */
struct flow_topo_entry {
	u32 node_id;
	u32 llc_id;
};
/* Minimal per LLC counters. Queued is a gauge, rest are totals. */
struct flow_llc_stats {
	u64 queued;
	u64 dispatched;
	u64 fallback;
	u64 steal;
};
#ifdef __BPF__
static __always_inline u64 flow_llc_dsq(u32 llc)
{
	return (u64)FLOW_LLC_BASE + (u64)llc;
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
static __always_inline bool flow_dsq_ok(u64 dsq)
{
	return dsq >= (u64)FLOW_LLC_BASE &&
	       dsq < (u64)FLOW_LLC_BASE + (u64)FLOW_MAX_LLCS;
}
#endif
#endif
