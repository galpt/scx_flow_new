/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler BPF core. Each Cpu keeps an ordered
 * queue with a mean slice. Deadlines run first with
 * arrival order for ties. The deadline adds clamped
 * virtual time and scaled estimate with a sleeper cap
 * of one slice. The mean tracks unfinished work with
 * the running task included. Fresh tasks join with the
 * current mean so the mean stays neutral. Blocked
 * tasks complete and release. Runnable tasks requeue
 * ordered with a fresh estimate. Idle Cpus steal from
 * peers with a bounded rotating scan. Kicks wake idle
 * targets only.
 */

/*
 * This file holds the maps, the shared state, the
 * shared helpers, the init and exit paths, and the
 * ops table. Logic lives in the modules below, in
 * dependency order.
 *   select_cpu.bpf.c, placement and LLC idle.
 *   enqueue.bpf.c, routing, insert, and kick.
 *   dispatch.bpf.c, own, park, and peer drains.
 *   lifecycle.bpf.c, running, stopping, enable,
 *   disable, exit, and dequeue accounting.
 */

#include <scx/common.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per task state. Created on first use and kept for
 * the life of the task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per Cpu state. Keyed by Cpu id. Holds the mean with
 * the sum and the count plus the steal cursor and the
 * running view.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");

/* Number of possible Cpus. Written once at init. */
volatile u64 nr_cpu_ids;

/* Scheduler wide counters. Updated with atomics. */
volatile struct flow_sched_stats flow_stats;

/*
 * Per Cpu LLC ids. Seeded once by userspace from
 * host topology. Unknown entries hold the unknown
 * value. The count holds distinct domains. Zero or
 * one means plain behavior with no LLC step.
 */
volatile u32 flow_cpu_llc[FLOW_MAX_CPUS];

/* Count of distinct LLC domains. Zero is unknown. */
volatile u64 flow_llc_nr;

/* Owner value for tasks with no accounting. */
#define FLOW_OWNER_NONE 0xFFFFFFFFU

/*
 * Current time source. The plain kernel time is used
 * on all kernels, so stamps share one boot clock with
 * userspace reads from uptime.
 */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}

/*
 * Look up the task state without creating it. Returns
 * null when the task has no state yet.
 */
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}

/*
 * Look up or create the task state. Returns null on
 * allocation failure.
 */
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Look up the Cpu state for one Cpu. Returns null for
 * out of range ids.
 */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;

	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}

/*
 * Check that a Cpu id names a live Cpu. Used to guard
 * queue and state access.
 */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}

/*
 * Check that a Cpu may run a task. The id must be in
 * range and present in the task mask.
 */
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

/*
 * Join one estimate to a Cpu mean. The sum uses the
 * capped value when the gate is set, so one long run
 * never dominates the mean. The count grows by one.
 * The mean is refreshed from the new sum and count.
 */
static __always_inline void flow_join_cpu(u32 cpu,
	u64 est)
{
	struct flow_cpu_state *st;
	u64 acct = est;

	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	if ((u64)FLOW_GATE_CLAMP)
		acct = flow_clamp_acct(est);
	__sync_fetch_and_add(&st->sum_est, acct);
	__sync_fetch_and_add(&st->nr, 1);
	__sync_lock_test_and_set(&st->tq_ns,
	    flow_mean_tq(st->sum_est, st->nr));
}

/*
 * Leave one estimate from a Cpu mean. A missing entry
 * is a no op, so a double leave stays safe. The sum
 * uses the capped value when the gate is set, to match
 * the join path. The mean is refreshed from the new
 * sum and count.
 */
static __always_inline void flow_leave_cpu(u32 cpu,
	u64 est)
{
	struct flow_cpu_state *st;
	s32 i;
	u64 acct = est;

	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	if ((u64)FLOW_GATE_CLAMP)
		acct = flow_clamp_acct(est);
	bpf_for(i, 0, 4) {
		u64 cur_n = st->nr;
		u64 cur_s = st->sum_est;
		u64 nxt_n;
		u64 nxt_s;
		u64 old_n;
		u64 old_s;

		if (cur_n == 0)
			break;
		if (cur_s < acct)
			nxt_s = 0;
		else
			nxt_s = cur_s - acct;
		nxt_n = cur_n - 1;
		old_n = __sync_val_compare_and_swap(&st->nr,
		    cur_n, nxt_n);
		if (old_n != cur_n)
			continue;
		old_s = __sync_val_compare_and_swap(
		    &st->sum_est, cur_s, nxt_s);
		if (old_s != cur_s) {
			__sync_fetch_and_add(&st->nr, 1);
			__sync_lock_test_and_set(&st->sum_est,
			    cur_s);
			break;
		}
		__sync_lock_test_and_set(&st->tq_ns,
		    flow_mean_tq(nxt_s, nxt_n));
		break;
	}
}

/*
 * Replace one estimate in a Cpu mean. The count stays
 * fixed while the sum tracks the change. The sum uses
 * the capped values when the gate is set, so outliers
 * never dominate the mean. Equal estimates skip at
 * once with no sum or mean write. The mean is
 * refreshed from the new sum otherwise.
 */
static __always_inline void flow_replace_cpu(u32 cpu,
	u64 old, u64 next)
{
	struct flow_cpu_state *st;
	u64 old_a = old;
	u64 next_a = next;

	if ((u64)FLOW_GATE_CUTS && old == next)
		return;
	if (!flow_cpu_live(cpu))
		return;
	st = flow_cpu(cpu);
	if (!st)
		return;
	if ((u64)FLOW_GATE_CLAMP) {
		old_a = flow_clamp_acct(old);
		next_a = flow_clamp_acct(next);
		if (old_a == next_a)
			return;
	} else if (old_a == next_a) {
		return;
	}
	if (st->sum_est >= old_a)
		__sync_fetch_and_sub(&st->sum_est, old_a);
	else
		__sync_lock_test_and_set(&st->sum_est, 0);
	__sync_fetch_and_add(&st->sum_est, next_a);
	__sync_lock_test_and_set(&st->tq_ns,
	    flow_mean_tq(st->sum_est, st->nr));
}

/*
 * Drop the on Cpu count without wrap. Zero stays at
 * zero, so a double stop never wraps the gauge.
 */
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
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_stats.on_cpu, 0);
	}
}

/*
 * Clear the running view of one Cpu. Zero pid means
 * idle, so the dashboard sees idle at once.
 */
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
	st->running_est = 0;
	st->running_pid = 0;
}

/*
 * Set the Cpu hint from estimate against mean. Short
 * estimates ask for the high hint. Long estimates
 * restore the low hint. Unknown helpers stay safe
 * with no hint change.
 */
static __always_inline void flow_cpuperf_set(s32 cpu,
	u64 est, u64 tq)
{
	u32 perf;

	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	perf = flow_cpuperf_for_est(est, tq);
	scx_bpf_cpuperf_set(cpu, perf);
}

/*
 * Restore the low hint when a stop leaves the Cpu
 * idle. Runnable stops keep their work, so they
 * never restore. Queued work also keeps the hint,
 * so restore runs once per idle change.
 */
static __always_inline void flow_cpuperf_restore(s32 cpu,
	bool runnable)
{
	u64 dsq;

	if (runnable)
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	dsq = flow_dsq_for_cpu((u32)cpu);
	if (scx_bpf_dsq_nr_queued(dsq) != 0)
		return;
	if (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)cpu) != 0)
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	scx_bpf_cpuperf_set(cpu, (u32)FLOW_CPUPERF_LONG);
}

/*
 * Release one accounted entry exactly once. A missing
 * entry is a no op, so double release stays safe.
 */
static __always_inline void flow_release(
	struct flow_task_ctx *tctx)
{
	u32 owner;
	u64 est;

	if (!tctx)
		return;
	if (tctx->grant_ns == (u64)-1)
		return;
	owner = tctx->owner;
	est = tctx->est_ns;
	if (owner != FLOW_OWNER_NONE && flow_cpu_live(owner))
		flow_leave_cpu(owner, flow_clamp_est(est));
	tctx->grant_ns = (u64)-1;
	tctx->owner = FLOW_OWNER_NONE;
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
		scx_bpf_error("Cpu count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no Cpus found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	/* Create one ordered queue per Cpu. */
	bpf_for(cpu, 0, 1024) {
		u64 dsq;

		/* Negative check stays for the verifier with */
		/* no behavior change, since the loop starts */
		/* at zero. */
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		dsq = flow_dsq_for_cpu((u32)cpu);
		if (dsq >= (u64)SCX_DSQ_LOCAL_ON) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(dsq, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	/* Create the park DSQ for tasks with no target. */
	if ((u64)FLOW_DSQ_PARK >= (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq((u64)FLOW_DSQ_PARK, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Seed each mean with the seed value. */
	bpf_for(cpu, 0, 1024) {
		struct flow_cpu_state *st;
		u32 key;

		/* Negative check stays for the verifier with */
		/* no behavior change, since the loop starts */
		/* at zero. */
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (!st)
			continue;
		st->tq_ns = (u64)FLOW_TQ_SEED_NS;
		st->sum_est = 0;
		st->nr = 0;
		st->cursor = (u64)cpu;
		st->running_est = 0;
		st->running_pid = 0;
		st->pad = 0;
		st->frontier = 0;
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
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
