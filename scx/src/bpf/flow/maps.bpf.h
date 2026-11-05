// SPDX-License-Identifier: GPL-2.0
/*
 * Flow maps and shared tables.
 *
 * Task storage carries per task state. CPU storage carries the
 * seeded topology view. LLC storage carries per LLC counters.
 * The weight hash carries cgroup shares. The sequence array keeps
 * a monotonic floor per LLC so fresh times stay unique. The
 * forward arrays coalesce head forward wakes by head and owner.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_MAPS_BPF_H
#define __FLOW_MAPS_BPF_H

#include "../intf.h"

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

/* Cgroup weight by kernfs id. A miss reads as default, and a full */
/* map misses the same way. Entries leave on cgroup exit so a reused */
/* id never reads a stale share. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} cgrp_weight_stor SEC(".maps");

volatile u64 flow_nr_cpus;
volatile u64 flow_nr_llcs;
/* Per CPU running snapshot. Zero generation means empty. */
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
/* Per CPU frequency hint state. Zero means empty. */
struct flow_freq_state flow_freq_state[FLOW_MAX_CPUS];
/* Per CPU burn score. Zero means fresh with no counts yet. */
struct flow_extra_state flow_extra_state[FLOW_MAX_CPUS];
/* Per LLC last virtual time for the monotonic floor. Zero init. */
s64 flow_llc_seq[FLOW_MAX_LLCS];
/* Per LLC node for drain order. Seeded once at init. Zero init. */
u32 flow_llc_node[FLOW_MAX_LLCS];
/* Last forwarded head per queue for wake coalescing. One slot per */
/* LLC plus one for the fallback queue. Pid plus time plus owner */
/* identify the head, so a new head or a new owner forwards again. */
u64 flow_fwd_pid[FLOW_MAX_LLCS + 1];
s64 flow_fwd_vtime[FLOW_MAX_LLCS + 1];
s32 flow_fwd_owner[FLOW_MAX_LLCS + 1];

#endif
