// SPDX-License-Identifier: GPL-2.0
/*
 * Tables for the flow scheduler.
 *
 * Task storage holds one entry per task. CPU storage holds the seed
 * view written at startup with the cluster index only. Cache and node
 * placement come from the upstream topology tree. LLC storage holds
 * per LLC counters. Globals hold the running view plus the system
 * board plus two switches for cluster choice plus thread shape. Each
 * LLC owns one kernel vtime DSQ for shared tasks. Each CPU owns one
 * DSQ for pinned tasks. The fallback DSQ holds tasks with no usable
 * CPU. The timer map holds one entry for the ten millisecond board
 * plus idle decay timer. The wire keeps one hundred four bytes.
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
	__uint(max_entries, FLOW_MAX_LLCS);
	__type(key, u32);
	__type(value, struct flow_llc_stats);
} llc_stats_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_ctx);
} cpu_ctx_stor SEC(".maps");
struct flow_update_timer {
	struct bpf_timer timer;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_update_timer);
} update_timer SEC(".maps");
volatile u64 flow_ccx_prefer;
volatile u64 flow_smt_enabled = 1;
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
struct flow_sys_stat sys_stat;
#endif
