// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. CPU storage holds the seed
 * view written at startup. LLC storage holds per LLC counters.
 * Weight storage holds shares by group id. A missing entry reads
 * as the default share. Wait history holds per CPU queue waits by
 * kind and bucket for run plus dispatch halves. Globals hold the
 * running view, the per LLC floor, the per LLC node, the
 * per CPU queue handles, the forward coalescing state, and four
 * switches for cluster choice plus distant wake hold plus thread
 * shape plus home stick. A zero handle means the CPU is offline
 * or its queues were never built. Thread shape defaults on so
 * a missed seed stays conservative. The CPU plus LLC plus wait
 * tables are written once, so a CPU that arrives late needs
 * a restart to be seen.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H
#include "intf.h"
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
volatile u64 flow_ccx_prefer;
volatile u64 flow_wait_allow;
volatile u64 flow_smt_enabled = 1;
volatile u64 flow_home_stick;
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
s64 flow_llc_seq[FLOW_MAX_LLCS];
u32 flow_llc_node[FLOW_MAX_LLCS];
u64 flow_dhq_live[FLOW_MAX_CPUS];
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];
#endif
