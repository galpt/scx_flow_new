// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. The entry starts with the
 * bandwidth block so control calls see it at offset zero. CPU
 * storage holds the seed view written at startup. LLC storage holds
 * per LLC counters. Weight storage holds shares by group id. A
 * missing entry reads as the default share. Wait history holds per
 * CPU queue waits by kind and bucket for run plus dispatch halves.
 * Globals hold the running view, the per LLC floor, the per LLC
 * node, and the forward coalescing state. The CPU plus LLC plus
 * wait tables are written once, so a CPU that arrives late needs a
 * restart to be seen.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H
#include "intf.h"
#include <lib/cgroup.h>
/* Per task state. Bw holds the bandwidth block and stays first
 * so control calls see it at offset zero. Pid holds the task id
 * for requeue lookup. Vtime is charged service. Slice holds the
 * time left in the current quantum. Gen identifies the running
 * instance. Llc records the last enqueue target. Flags holds the
 * queued bit. Prio holds the selected queue. Burst holds the
 * recent run time estimate. Enq holds the last enqueue time. Cgrp
 * holds the group id and share hint. A zero id means no group was
 * recorded. Lat holds the wait kind for history. */
struct flow_task_ctx {
	struct scx_task_cgroup_bw bw;
	s64 vtime;
	u64 slice_rem;
	u64 gen;
	u32 llc_id;
	u32 flags;
	u32 prio;
	u32 cg_weight;
	u64 cgrp_id;
	u64 burst_ns;
	u64 enq_ns;
	u32 lat_kind;
	pid_t pid;
};
/* Alias used by the bandwidth requeue registration. */
typedef struct flow_task_ctx task_ctx;
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_ctx);
} cpu_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_LLCS);
	__type(key, u32);
	__type(value, struct flow_llc_stats);
} llc_stats_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} cgrp_weight_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_lat_hist);
} lat_hist SEC(".maps");
volatile u64 flow_nr_cpus;
volatile u64 flow_nr_llcs;
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
s64 flow_llc_seq[FLOW_MAX_LLCS];
u32 flow_llc_node[FLOW_MAX_LLCS];
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];
#endif
