// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler entry.
 *
 * Thin glue that pulls in nine area headers in order and declares
 * the ops table. Each LLC has four queues and there is one fallback
 * queue. Ties leave in insertion order. Tables are written once, so
 * a CPU that arrives late needs a restart to be seen. Settings live
 * in the shared header. Bandwidth control follows the admin cpu max
 * through the shared library.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <lib/cgroup.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "sjf.bpf.h"
#include "cgroup.bpf.h"
#include "lat.bpf.h"
#include "select.bpf.h"
#include "enqueue.bpf.h"
#include "dispatch.bpf.h"
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
	       .exit_task		= (void *)flow_exit_task,
	       .cgroup_init		= (void *)flow_cgroup_init,
	       .cgroup_exit		= (void *)flow_cgroup_exit,
	       .cgroup_move		= (void *)flow_cgroup_move,
	       .cgroup_set_weight	= (void *)flow_cgroup_set_weight,
	       .cgroup_set_bandwidth	= (void *)flow_cgroup_set_bandwidth,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
int flow_enqueue_cb(struct task_struct *p __arg_trusted, u64 ctx);
REGISTER_SCX_CGROUP_BW_ENQUEUE_CB(flow_enqueue_cb);
/* Wake a CPU after bandwidth replenishment. The timer calls here
 * when the built-in idle knob stays off, so the override claims an
 * idle CPU through the kernel picker and kicks it for dispatch. */
void scx_cgroup_bw_kick_idle_cb(void)
{
	const struct cpumask *online;
	s32 cpu;
	online = scx_bpf_get_online_cpumask();
	cpu = scx_bpf_pick_idle_cpu(online, SCX_PICK_IDLE_CORE);
	if (cpu == -EBUSY)
		cpu = scx_bpf_pick_idle_cpu(online, 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	scx_bpf_put_cpumask(online);
}
