// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * Maps hold task deadlines, CPU pid plus cursor rows, and the
 * topology view. Init creates one deadline queue per CPU plus one
 * overflow tail, and it fails loudly when an id reaches the local
 * range. Ops split across select_cpu, enqueue, dispatch, and
 * lifecycle files. Hotplug needs a restart, and the watchdog stays
 * at 30 seconds.
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
volatile u64 nr_cpu_ids;
volatile struct flow_sched_stats flow_stats;
/* Monotonic clock in nanos for deadlines and starvation. */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}
/* Task state without create for fast read paths. */
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}
/* Task state with create for enqueue and enable paths. */
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
/* CPU state or null when the id is past the bound. */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}
/* Topology view or null when the id is past the bound. */
static struct flow_topo *flow_topo(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&topo_stor, &key);
}
/* True when the id is a live CPU below nr and the bound. */
/* Live means below the nr snapshot at init with no kernel online read. */
/* Hotplug needs a restart with fail closed to overflow. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
/* True when the CPU is live and inside the task mask. */
/* Live is the init snapshot with no hotplug read, so an offlined CPU */
/* past init still reads live here and needs a restart to drain. */
/* Unknown CPUs fail closed to overflow with mask wins on drain. */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* Drop the on CPU gauge by one with no wrap and no clear. */
/* Retries the compare and swap so concurrent stops pair, and a lost */
/* race leaves the gauge to the winner with no silent zero. */
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 4) {
		u64 cur = flow_stats.on_cpu;
		u64 nxt;
		u64 old;
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
	}
}
/* Clear the running pid with no other state change. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_pid = 0;
}
/* Clear the running pid only when the pid owns it. */
/* A stale exit never clears a new owner after a switch. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	if (st->running_pid != pid)
		return;
	st->running_pid = 0;
}
/* Charge one leftover run segment at most once with no scaling. */
/* Stopping owns the normal charge and clears the run start. */
/* Disable and exit funnel here only for a running task that */
/* stopping never saw. The count flag pairs with stopping through */
/* the run start, so a release never double charges. */
static __always_inline void flow_charge_leftover(s32 cpu,
	struct task_struct *p, struct flow_task_ctx *tctx, u32 pid)
{
	u64 start;
	u64 now;
	u64 delta;
	if (!tctx)
		return;
	start = tctx->run_at;
	if (start == 0)
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* A stopped task holds zero with no charge left. */
	/* Only the owning CPU charges, so a migrated stop stays once. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		if (!st || st->running_pid != pid)
			return;
	}
	now = flow_now();
	if (flow_time_before(now, start))
		return;
	delta = now - start;
	tctx->run_at = 0;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_on_cpu_dec();
}
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"
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
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
