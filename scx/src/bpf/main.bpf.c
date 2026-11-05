// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler core.
 *
 * Entry point with ordered includes and struct ops only. Queues
 * are one per LLC plus one fallback queue, each ordered by virtual
 * time with equal times leaving in insertion order. Pinned tasks
 * use the local queue in FIFO order. Cgroup weight scales virtual
 * time charges with default weight as identity and the slice
 * fixed. A full burn postpones the task by the award length. The
 * streak turns an idle wake into a preempt at the bound. Tables
 * are seeded once, so hotplug needs a restart.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
#include "flow/maps.bpf.h"
#include "flow/stats.bpf.h"
#include "flow/guards.bpf.h"
#include "flow/vtime.bpf.h"
#include "flow/cgroup.bpf.h"
#include "flow/freq.bpf.h"
#include "flow/preempt.bpf.h"
#include "flow/lifecycle.bpf.h"
#include "flow/enqueue.bpf.h"
#include "flow/dispatch.bpf.h"
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .tick			= (void *)flow_tick,
	       .set_cpumask		= (void *)flow_set_cpumask,
	       .enable			= (void *)flow_enable,
	       .init_task		= (void *)flow_init_task,
	       .cgroup_init		= (void *)flow_cgroup_init,
	       .cgroup_exit		= (void *)flow_cgroup_exit,
	       .cgroup_move		= (void *)flow_cgroup_move,
	       .cgroup_set_weight	= (void *)flow_cgroup_set_weight,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
