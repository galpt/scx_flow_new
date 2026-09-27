// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * Maps hold task deadlines, CPU pid plus cursor rows, the
 * topology view, and the hierarchy share plus pool rows. Init
 * creates one deadline queue per CPU plus one overflow tail, and
 * it fails loudly when an id reaches the local range. Ops split
 * across select_cpu, enqueue plus enqueue/, dispatch plus
 * dispatch/, lifecycle, and hierarchy files. Shared helpers split
 * across main/task, hier, bw, cpu, and timer files with maps plus
 * init here. Hotplug needs a restart, and the watchdog stays at
 * 30 seconds.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Per task deadline for the life of the task. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
/* Per CPU pid with steal cursor. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
/* Per CPU topology view with sibling plus domain. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_topo);
} topo_stor SEC(".maps");
/* Per hierarchy share plus pool by id with miss default. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_CGRP_MAX);
	__type(key, u64);
	__type(value, struct flow_cgrp_ctx);
} cgrp_stor SEC(".maps");
/* Single kicking timer for throttled work with lazy refill. */
struct flow_bw_timer {
	struct bpf_timer timer;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_bw_timer);
} bw_timer SEC(".maps");
/* Ring of lately parked chains for the timer refill scan. */
/* Each slot holds 8 ancestor ids with the leaf first and zero pad. */
/* Parks record the walked chain with a wrapping counter, and the */
/* timer refills each listed pool with cap. Stale or reused ids refill */
/* harmlessly, so no cleanup runs. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_PARK_HINT_NR);
	__type(key, u32);
	__type(value, struct flow_park_chain);
} park_hint SEC(".maps");
volatile u64 nr_cpu_ids;
volatile struct flow_sched_stats flow_stats;
volatile u64 flow_cgrp_gen = 1;
volatile u64 flow_bw_limited = 0;
volatile u64 flow_bw_pending = 0;
/* Wrapping counter for the parked hint ring. */
volatile u64 flow_hint_idx = 0;
#include "main/task.bpf.c"
#include "main/hier.bpf.c"
#include "main/bw.bpf.c"
#include "main/cpu.bpf.c"
#include "main/timer.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"
#include "cgroup.bpf.c"
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	u64 n;
	s32 cpu;
	u32 tkey = 0;
	struct flow_bw_timer *tm;
	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_state *st;
		struct flow_topo *tp;
		u32 key;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (st) {
			st->running_pid = 0;
			st->cursor = (u32)cpu;
		}
		tp = bpf_map_lookup_elem(&topo_stor, &key);
		if (tp) {
			tp->smt_sib = 0xffffffffU;
			tp->llc = 0;
		}
	}
	/* One deadline queue per CPU plus one overflow tail. */
	/* Deadline holds 0x6800 plus id and overflow holds 0x7000. */
	/* Count holds one per CPU plus one with one bounded pass at init. */
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 vtime;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		vtime = flow_vtime_dsq((u32)cpu);
		if (vtime >= (u64)SCX_DSQ_LOCAL_ON) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(vtime, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	if (flow_overflow_dsq() >= (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_overflow_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Single timer wakes throttled parks with no pool scan. */
	tm = bpf_map_lookup_elem(&bw_timer, &tkey);
	if (!tm) {
		scx_bpf_error("timer lookup failed");
		return -EINVAL;
	}
	bpf_timer_init(&tm->timer, &bw_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tm->timer, flow_bw_timer_cb);
	ret = bpf_timer_start(&tm->timer, (u64)FLOW_BW_TIMER_NS, 0);
	if (ret < 0) {
		scx_bpf_error("timer start failed");
		return ret;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .enable			= (void *)flow_enable,
	       .disable			= (void *)flow_disable,
	       .exit_task		= (void *)flow_exit_task,
	       .cpu_release		= (void *)flow_cpu_release,
	       .cgroup_init		= (void *)flow_cgroup_init,
	       .cgroup_exit		= (void *)flow_cgroup_exit,
	       .cgroup_prep_move	= (void *)flow_cgroup_prep_move,
	       .cgroup_move		= (void *)flow_cgroup_move,
	       .cgroup_cancel_move	= (void *)flow_cgroup_cancel_move,
	       .cgroup_set_weight	= (void *)flow_cgroup_set_weight,
	       .cgroup_set_bandwidth	= (void *)flow_cgroup_set_bandwidth,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
