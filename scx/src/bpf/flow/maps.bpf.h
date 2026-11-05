// SPDX-License-Identifier: GPL-2.0
/*
 * Flow maps plus pair tables.
 *
 * Moved from main plus one HASH for cgroup weights. All bounds stay fixed
 * with no knob. Single ownership through the queued flag is unchanged.
 * Hotplug needs restart, same risk as the pinned path.
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

/* Cgroup weight by kernfs id. Key is cgrp->kn->id, value holds the */
/* clamped cpu.weight. Miss plus zero id plus zero value all read as */
/* default, so an unknown kernel plus a missing entry fail open to */
/* 5.0.8 behavior. Sized for thousands of cgroups with no eviction. */
/* A full map misses to default with no stall. Deleted on cgroup_exit */
/* so a reused id never reads a stale weight. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u64);
} cgrp_weight_stor SEC(".maps");

volatile u64 flow_nr_cpus;
volatile u64 flow_nr_llcs;
scx_dhq_t *flow_pair_dhqs[FLOW_MAX_PAIRS];
u64 flow_llc_pair[FLOW_MAX_LLCS];
u64 flow_llc_strand[FLOW_MAX_LLCS];
u32 flow_node_count[FLOW_MAX_NODES];
u64 flow_node_last_pair[FLOW_MAX_NODES];
u32 flow_pair_count;
/* Per pair configured capacity for sizing. Set once at init, zero init. */
u64 flow_pair_cap[FLOW_MAX_PAIRS];
/* Per CPU running snapshot. Zero init means empty. */
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
/* Per CPU hint state. Zero init means empty. Persists across events. */
struct flow_freq_state flow_freq_state[FLOW_MAX_CPUS];
/* Per pair last vtime for monotonic unique assign. Zero init. */
s64 flow_dhq_seq[FLOW_MAX_PAIRS];
/* Node per pair for hierarchy walk. Zero init. */
u32 flow_pair_node[FLOW_MAX_PAIRS];

/* 5.0.10 note: maps bounds stay fixed 1024 CPUs, 64 LLCs, 8 nodes, */
/* 32 pairs plus 4096 weight entries with no eviction, queued flag holds */
/* single ownership. Docs only, no logic change. */

#endif
