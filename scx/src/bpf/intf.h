// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each CPU owns one queue with two strands ordered by vd. Warm tasks
 * join the first strand and cold tasks join the second. Ties leave in
 * insertion order. Warm keeps the last CPU when it is allowed and live
 * in the same LLC, else the task stays cold. A strand that refuses an
 * insert tries the other strand once before the fallback queue.
 * Draining peeks both heads and pops the earlier vd with ties to the
 * first strand. Each per CPU queue holds at most ten tasks, so a full
 * queue drains in at most ten millis with one millis slices minus steal
 * parallelism. One millis alone stays aspirational since a cap of one
 * throttles throughput. Depth signal reuses the guard and the queued
 * plus fallback plus steal counts with no extra probe. One fallback
 * queue holds tasks that have no usable CPU in FIFO order as a best
 * effort overflow without a bound promise. Pinned tasks run on their
 * local queue.
 * Shares are read from the cgroup map on each enqueue and folded
 * with the task nice weight. A task pays
 * for the time it burns, scaled by its share. Fresh times move past
 * a per LLC floor so two tasks never share the same value. Vd adds
 * a share based step to the floored time, so a larger share gives
 * an earlier vd. Slices hold one fixed quantum. A shared
 * enqueue with a vd ahead of the running vd kicks for preempt
 * with idle wakes otherwise. Each running instance kicks at most once. A runnable yield with no burnt time still moves the
 * stored time forward by one. Each per CPU queue holds at most ten
 * tasks with the fallback holding at most one thousand twenty four.
 * Steal moves in topology order with local first then mates then the
 * rest of the same LLC then same node then remote. Queues come from the upstream
 * double helix library in virtual time mode, and placement follows
 * the upstream topology library with liveness from the same tree.
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
	FLOW_FALLBACK_CAP = 1024ULL,
	FLOW_SLICE_MIN_NS = 1000000ULL,
	FLOW_EXIT_SLICE_NS = 1000ULL,
	FLOW_FAIR_BASE_NS = 20000ULL,
	FLOW_FAIR_EXTRA_NS = 1000ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	FLOW_FLAG_QUEUED = 1ULL,
};
/* Per task state. Vtime is charged service. Slice holds the time
 * left in the current quantum. Gen identifies the running instance.
 * Llc records the last enqueue target. Flags holds the queued bit.
 * Cgrp holds the group id. A zero id means no group was recorded.
 * Vd holds the due time for queue order. */
struct flow_task_ctx {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	u64 cgrp_id;
	s64 vd;
};
/* Per CPU running view. Gen counts runs. Pad holds the last kicked
 * generation, so each run kicks at most once. Vd mirrors the running
 * task due time for gap checks. */
struct flow_running_state {
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 pad;
	s64 vd;
};
/* Per CPU seed from userspace. Holds the CPU id plus the cluster
 * index assigned at startup. Cache and node placement come from the
 * upstream topology tree, so no cached copy lives here. The cluster
 * index stays here as an interim until it moves into the tree data
 * pointer, which needs a non-zero data size at tree build time. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 ccx_id;
	u32 reserved;
	u32 pad;
};
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts preempt plus idle and skipped wakes. Overrun counts full
 * slice burns. Blocked counts stops that leave the task runnable.
 * Orphan counts mask change kicks. Forward counts heads passed to
 * their owner. */
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
	u64 blocked;
	u64 orphan_kick;
	u64 hol_forward;
};
#ifdef __BPF__
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
#endif
#endif
