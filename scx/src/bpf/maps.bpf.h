// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. CPU storage holds the seed
 * view written at startup with the cluster index only; cache and node
 * placement come from the upstream topology tree. LLC storage holds
 * per LLC counters. Weight storage holds shares by group id. A missing
 * entry reads as the default share. Globals hold the running view,
 * the per LLC floor, the per CPU queue handles as upstream queue
 * pointers in arena memory, the per CPU waiting counts, the forward
 * coalescing state, and two switches for cluster choice plus thread shape. Each
 * CPU owns one handle with no second index, so one queue holds both
 * strands with per-CPU recency and a balance-only guard and no bound.
 * A zero handle means
 * the CPU is offline or its queue was never built. Counts hold one total
 * per CPU for least load inserts and most load steals with saturation
 * at the top and a floor at zero. Counts
 * stay internal with no export through the counter view. Thread shape
 * defaults on so a missed seed stays conservative. The CPU plus LLC
 * tables are written once, so a CPU that arrives late needs a restart
 * to be seen. Liveness comes from the topology tree, so no separate
 * live table is kept.
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
volatile u64 flow_ccx_prefer;
volatile u64 flow_smt_enabled = 1;
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
s64 flow_llc_seq[FLOW_MAX_LLCS];
u64 flow_dhqs[FLOW_MAX_CPUS];
u32 flow_qcnt[FLOW_MAX_CPUS];
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];
#endif
