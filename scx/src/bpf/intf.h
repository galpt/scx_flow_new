// SPDX-License-Identifier: GPL-2.0
/*
 * Shared constants for the flow scheduler.
 *
 * Each LLC owns one kernel vtime DSQ for shared tasks. Each CPU owns
 * one DSQ for pinned tasks. One fallback DSQ holds tasks with no
 * usable CPU. Drain walks CPU then LLC then neighbor then remote
 * then fallback. Tiers stay L1 greater than L2 greater than L3. Short
 * form is L1>L2>L3. Idle starts claim at once. Size breaks ties only
 * inside one tier with larger buckets first within tier when both
 * buckets are known. Each enqueue prices the task by context with
 * log scale. Virtual deadline adds a bounded step scaled by greedy
 * over latency score. Slices hold one base quantum with boost for
 * long frame tasks. A runnable yield with no burnt time still moves
 * stored state forward by one. Shared enqueue with a due time ahead
 * of the running due time yields soft with a one nanosecond slice.
 * Each running instance yields at most once per generation. The wire
 * keeps one hundred four bytes with the same order as before.
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
	FLOW_QUEUE_CAP = 64ULL, /* Kept reserved. */
	FLOW_FALLBACK_CAP = 1024ULL, /* Kept reserved. */
	FLOW_SLICE_MIN_NS = 500000ULL,
	FLOW_SLICE_MAX_NS = 5000000ULL,
	FLOW_SLICE_BOOST_MAX = 20000000ULL,
	FLOW_TARGETED_LATENCY_NS = 10000000ULL,
	FLOW_TASK_LAG_MAX = 500000000ULL,
	FLOW_DL_COMPETE_WINDOW = 4577ULL,
	FLOW_SYS_STAT_INTERVAL_NS = 10000000ULL,
	FLOW_PREEMPT_SHIFT = 6ULL,
	FLOW_CPU_DSQ_BASE = 0x1000ULL,
	FLOW_LLC_DSQ_BASE = 0x2000ULL,
	FLOW_FALLBACK_DSQ = 0x6100ULL,
	FLOW_FLAG_QUEUED = 1ULL,
	FLOW_FLAG_DIRECT_DISPATCH = 2ULL,
	FLOW_FLAG_IS_SYNC_WAKEUP = 4ULL,
	FLOW_FLAG_WOKEN_BY_HARDIRQ = 8ULL,
	FLOW_FLAG_WOKEN_BY_SOFTIRQ = 16ULL,
	FLOW_FLAG_IS_GREEDY = 32ULL,
	FLOW_CGROUP_WEIGHT_MIN = 1ULL,
	FLOW_CGROUP_WEIGHT_DFLT = 100ULL,
	FLOW_CGROUP_WEIGHT_MAX = 10000ULL,
	FLOW_CGROUP_WEIGHT_INVALID = 0ULL,
	FLOW_OPS_TIMEOUT_MS = 20000ULL,
};
/* Per task state. Acc holds burnt time in the current activation.
 * Avg holds the EWMA run length. Svc holds weighted service time.
 * Clocks hold last running plus runnable plus quiescent stamps.
 * Freq holds run plus wait plus wake rates in hertz. Lat holds the
 * urgency score with waker plus wakee inherit parts. Flags holds
 * queue plus dispatch plus sync plus irq bits plus greedy mark.
 * Llc holds the last enqueue target. Pinned holds the fixed CPU or
 * minus one. Slice holds the assigned quantum for this activation.
 * The state holds one hundred four bytes. */
struct flow_task_ctx {
	u64 acc_runtime_ns;
	u64 avg_runtime_ns;
	u64 svc_time_iwgt;
	u64 last_running_clk;
	u64 last_runnable_clk;
	u64 last_quiescent_clk;
	u64 run_freq;
	u64 wait_freq;
	u64 wake_freq;
	u32 lat_cri;
	u32 lat_cri_waker;
	u32 lat_cri_wakee;
	u32 flags;
	u32 llc_id;
	s32 pinned_cpu;
	u64 slice_ns;
};
/* The task state holds one hundred four bytes. */
_Static_assert(sizeof(struct flow_task_ctx) == 104, "flow_task_ctx size drifted");
/* Per CPU running view. Flags mirrors task bits for the run. Est
 * holds the expected stop stamp. Running holds the start stamp.
 * Lat holds the running task score for victim choice. Pinned counts
 * affinitized tasks waiting on this CPU. Llc holds the CPU LLC.
 * Perf holds the current target with commit stamp. Idle holds the
 * stamp when the CPU went idle. Sched counts runs. Preempt counts
 * soft yields. Tot holds weighted service. Sum plus max track score
 * for the timer path. The view holds ninety six bytes. */
struct flow_running_state {
	u64 flags;
	u64 est_stopping_clk;
	u64 running_clk;
	u32 lat_cri;
	u32 nr_pinned;
	u32 llc_id;
	u32 cpuperf_cur;
	u64 cpuperf_commit_clk;
	u64 idle_start_clk;
	u64 nr_sched;
	u64 nr_preempt;
	u64 tot_iwgt;
	u64 sum_lat_cri;
	u32 max_lat_cri;
	u32 pad;
};
/* The running view holds ninety six bytes. */
_Static_assert(sizeof(struct flow_running_state) == 96, "flow_running_state size drifted");
/* System wide scoreboard. Clk is the logical clock. Svc is the mean
 * weighted service. Avg plus max plus thr track urgency. Slice is
 * the base quantum for the next window. Queued counts waiting tasks.
 * The board holds fifty six bytes. */
struct flow_sys_stat {
	u64 cur_logical_clk;
	u64 avg_svc_time_iwgt;
	u64 avg_lat_cri;
	u64 max_lat_cri;
	u64 thr_lat_cri;
	u64 slice_ns;
	u64 nr_queued;
};
/* The board holds fifty six bytes. */
_Static_assert(sizeof(struct flow_sys_stat) == 56, "flow_sys_stat size drifted");
/* Per CPU seed from userspace. Holds the CPU id plus the cluster
 * index assigned at startup. Cache and node placement come from the
 * upstream topology tree, so no cached copy lives here. The cluster
 * index stays here as an interim until it moves into the tree data
 * pointer, which needs a non-zero data size at tree build time. The
 * spare word holds three size buckets plus one reserved byte. Each
 * bucket is a u8 with zero meaning unknown. The buckets share one
 * aggregated per CPU share from userspace. The seed stays sixteen
 * bytes total. */
struct flow_cpu_ctx {
	u32 cpu_id;
	u32 ccx_id;
	u8 l2_bkt;
	u8 l3_bkt;
	u8 cache_cls;
	u8 rsv;
	u32 pad;
};
/* The seed stays sixteen bytes with no growth. */
_Static_assert(sizeof(struct flow_cpu_ctx) == 16, "flow_cpu_ctx size drifted");
/* Bucket ladder over kibibytes. Zero means unknown with no size.
 * Larger numbers mean larger caches. Values cap at the top with no
 * wrap. Mirrors cache_bucket in topology.rs with identical thresholds.
 * Keep both in sync. Compares promote to int per C rules with identical
 * result and no extra budget. */
static __always_inline u8 cache_bucket(u32 kb)
{
	if (!kb)
		return 0;
	if (kb <= 32U)
		return 1;
	if (kb <= 48U)
		return 2;
	if (kb <= 256U)
		return 3;
	if (kb <= 512U)
		return 4;
	if (kb <= 1024U)
		return 5;
	if (kb <= 8192U)
		return 6;
	if (kb <= 16384U)
		return 7;
	if (kb <= 32768U)
		return 8;
	if (kb <= 98304U)
		return 9;
	if (kb <= 524288U)
		return 10;
	return 255;
}
/* Per LLC counters. The order matches the userspace reader.
 * Queued counts tasks waiting in shared queues. Dispatched counts
 * moves to a local queue. Fallback counts fallback inserts. Steal
 * counts remote moves, with a split count kept on the thief.
 * Duplicate counts requeues dropped while already queued. Kick
 * counts idle plus skipped wakes with the preempt count at zero. Overrun counts full
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
