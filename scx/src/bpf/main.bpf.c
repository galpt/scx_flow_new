// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * Maps hold task releases, CPU pid plus cursor rows, the topology
 * view, the capacity view, the admitted use rows, and the flat hint
 * rows. Init creates one local queue per CPU plus one shared queue
 * per node plus one machine queue plus one overflow tail, and it
 * fails loudly when an id reaches the local range. Ops split across
 * select_cpu, enqueue plus enqueue/, dispatch plus dispatch/,
 * lifecycle, and flat hierarchy files. Shared helpers split across
 * main/task, deadline, hier, cpu, and timer files with maps plus
 * init here. Hotplug needs a restart, and the watchdog stays at
 * 20 seconds.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Per task release for the life of the task. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
/* Per CPU pid with drain cursor. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
/* Per CPU topology view with sibling plus node. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_topo);
} topo_stor SEC(".maps");
/* Per CPU capacity view with one units row. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_cap);
} cap_stor SEC(".maps");
/* Per CPU admitted use with one per mille row. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_admit);
} admit_stor SEC(".maps");
/* Flat period hint by id with miss default. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u64);
	__type(value, struct flow_hint);
} hint_stor SEC(".maps");
/* Single backstop timer for parked work. */
struct flow_backstop_timer {
	struct bpf_timer timer;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_backstop_timer);
} backstop_timer SEC(".maps");
volatile u64 nr_cpu_ids;
volatile u64 nr_node_ids;
volatile struct flow_sched_stats flow_stats;
volatile u64 flow_backstop_pending = 0;
#include "main/task.bpf.c"
#include "main/cpu.bpf.c"
#include "main/hier.bpf.c"
#include "main/deadline.bpf.c"
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
	struct flow_backstop_timer *tm;
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
	nr_node_ids = 1;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_state *st;
		struct flow_topo *tp;
		struct flow_cpu_cap *cp;
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
			tp->node = 0;
		}
		cp = bpf_map_lookup_elem(&cap_stor, &key);
		if (cp)
			cp->units = (u32)FLOW_CAP_BASE;
	}
	/* One local queue per CPU plus one shared queue per node plus */
	/* one machine queue plus one overflow tail. Local ids cover */
	/* 0x5100 plus id and node ids cover 0x5900 plus id. */
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 local;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		local = flow_local_dsq((u32)cpu);
		if (!flow_dsq_valid(local)) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(local, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	{
		u32 node = 0;
		u64 nd = flow_node_dsq(node);
		if (!flow_dsq_valid(nd)) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(nd, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	if (!flow_dsq_valid(flow_machine_dsq())) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_machine_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	if (!flow_dsq_valid(flow_overflow_dsq())) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_overflow_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Single timer wakes parked work with no queue scan. */
	tm = bpf_map_lookup_elem(&backstop_timer, &tkey);
	if (!tm) {
		scx_bpf_error("timer lookup failed");
		return -EINVAL;
	}
	bpf_timer_init(&tm->timer, &backstop_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tm->timer, flow_backstop_cb);
	ret = bpf_timer_start(&tm->timer,
	    (u64)FLOW_BACKSTOP_TIMER_NS, 0);
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
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
