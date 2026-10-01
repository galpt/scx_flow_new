// SPDX-License-Identifier: GPL-2.0
/*
 * Flow core with tree queues.
 *
 * Maps hold task run state, CPU rows, topology rows, admitted sums,
 * order rows, tree summary, clusters, counts, tree pid rows, root,
 * two notify rings. Init reserves five hundred twelve local queues,
 * eight node queues, machine, overflow as an ABI placeholder so
 * identifiers stay stable. The core parks and notifies for
 * observability solely. The core orders through the tree and admits
 * under the bound in the core. Dispatch moves every parked task in
 * tree order with rejects at the top key last. Hotplug needs a
 * restart. The watchdog stays at twenty seconds.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
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
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_topo);
} topo_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} flow_enq_rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} flow_cmp_rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_ORDER_CAP);
	__type(key, u32);
	__type(value, struct flow_order_entry);
} order_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, u64);
} admitted_stor SEC(".maps");
volatile u64 nr_cpu_ids;
volatile u64 nr_node_ids;
volatile struct flow_sched_stats flow_stats;
volatile u64 flow_seq;
#include "main/task.bpf.c"
#include "main/cpu.bpf.c"
#include "main/hier.bpf.c"
#include "main/timer.bpf.c"
#include "veb/map.bpf.c"
#include "veb/core.bpf.c"
#include "veb/min.bpf.c"
#include "veb/remove.bpf.c"
#include "veb/insert.bpf.c"
#include "veb/head.bpf.c"
#include "admit/share.bpf.c"
#include "admit/row.bpf.c"
#include "admit/drop.bpf.c"
#include "helpers/move.bpf.c"
#include "helpers/finish.bpf.c"
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
	nr_node_ids = (u64)FLOW_MAX_NODES;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_state *st;
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
			WRITE_ONCE(st->running_pid, 0);
			WRITE_ONCE(st->pad, 0);
		}
	}
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
		u32 node;
		bpf_for(node, 0, FLOW_MAX_NODES) {
			u64 nd;
			nd = flow_node_dsq(node);
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
	       .timeout_ms		= 20000,
	       .name			= "flow");
