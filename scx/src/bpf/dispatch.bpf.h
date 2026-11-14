// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own DSQ first, then the local LLC DSQ, then
 * same node neighbor LLC DSQs, then remote LLC DSQs, then fallback.
 * Closer caches drain first. Fixed order covers the rest. If no DSQ
 * moves and prev is still runnable, prev continues in place with a
 * fresh slice. Running advances the logical clock and ramps the core
 * to max. Tick refreshes max so rate limits never drop the target.
 * Stopping folds run length into the average and tracks service.
 * Quiescent folds the wait rate on sleep. A ten millisecond timer
 * refreshes the score board and tracks idle cores to half. The timer
 * never touches a busy core, and the half set is deferred to dispatch
 * which holds the lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DISPATCH_BPF_H
#define __FLOW_DISPATCH_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "select.bpf.h"
#include "enqueue.bpf.h"
#include "fair.bpf.h"
#include <lib/topology.h>

/* Timer clock id for the board refresh. Matches the boot time base. */
enum flow_clock {
	FLOW_CLOCK_BOOTTIME = 7,
};

static __always_inline void flow_after_move(u32 cpu, u32 llc)
{
	/* Holds the dispatch lock for this CPU. */
	flow_stat_inc(llc, 1);
	flow_cpuperf_commit(cpu, (u32)SCX_CPUPERF_ONE, bpf_ktime_get_ns());
}

/* Continue prev in place with a fresh slice. Runs only when no DSQ
 * moved, so a queued urgent task always wins over continuation. Holds
 * the dispatch lock for this CPU. */
static __noinline bool flow_try_continue_prev(u32 cpu, u32 llc, struct task_struct *prev)
{
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 slice;

	if (!flow_cpu_ok(cpu))
		return false;
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return false;
	if (!flow_cpu_allowed((s32)cpu, prev))
		return false;
	t = bpf_task_storage_get(&task_ctx_stor, prev, 0, 0);
	if (!t)
		return false;
	rs = &flow_running_state[cpu];
	slice = flow_calc_slice(t, rs);
	t->slice_ns = slice;
	WRITE_ONCE(rs->est_stopping_clk, bpf_ktime_get_ns() + slice);
	scx_bpf_task_set_slice(prev, slice);
	flow_cpuperf_commit(cpu, (u32)SCX_CPUPERF_ONE, bpf_ktime_get_ns());
	flow_stat_inc(llc, 9);
	return true;
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	int v;
	u64 tried = 0;
	u32 idx;
	struct topo_iter hint_iter;
	topo_ptr hint_node = 0;
	topo_ptr walk = 0;

	flow_touch_arena();
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c) || !flow_cpu_live(c))
		return;
	v = topo_cpu_to_llc_id(c);
	if (v < 0 || !flow_llc_ok((u32)v))
		return;
	llc = (u32)v;
	if (topo_all && topo_contains(topo_all, c)) {
		TOPO_FOR_EACH_NODE(&hint_iter, walk) {
			if (topo_contains(walk, c)) {
				hint_node = walk;
				break;
			}
		}
	}
	/* Own CPU DSQ holds pinned tasks first. */
	if (scx_bpf_dsq_move_to_local((u64)FLOW_CPU_DSQ_BASE + (u64)c, 0)) {
		flow_after_move(c, llc);
		return;
	}
	/* Local LLC DSQ holds the earliest due time in this LLC. */
	if (scx_bpf_dsq_move_to_local((u64)FLOW_LLC_DSQ_BASE + (u64)llc, 0)) {
		flow_after_move(c, llc);
		return;
	}
	if (llc < 64U)
		tried |= (1ULL << llc);
	/* Same node neighbor LLC DSQs next, one try per LLC. */
	bpf_for(idx, 0, FLOW_MAX_CPUS) {
		int vl;
		u32 l;

		if (idx == c)
			continue;
		if (!hint_node || !topo_contains(hint_node, idx))
			continue;
		vl = topo_cpu_to_llc_id(idx);
		if (vl < 0 || !flow_llc_ok((u32)vl))
			continue;
		l = (u32)vl;
		if (l == llc)
			continue;
		if (l < 64U) {
			if (tried & (1ULL << l))
				continue;
			tried |= (1ULL << l);
		}
		if (scx_bpf_dsq_move_to_local((u64)FLOW_LLC_DSQ_BASE + (u64)l, 0)) {
			flow_after_move(c, llc);
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 5);
			return;
		}
	}
	/* Remote LLC DSQs after the node pass, one try per LLC. */
	bpf_for(idx, 0, FLOW_MAX_CPUS) {
		int vl;
		u32 l;

		if (idx == c)
			continue;
		if (hint_node && topo_contains(hint_node, idx))
			continue;
		vl = topo_cpu_to_llc_id(idx);
		if (vl < 0 || !flow_llc_ok((u32)vl))
			continue;
		l = (u32)vl;
		if (l == llc)
			continue;
		if (l < 64U) {
			if (tried & (1ULL << l))
				continue;
			tried |= (1ULL << l);
		}
		if (scx_bpf_dsq_move_to_local((u64)FLOW_LLC_DSQ_BASE + (u64)l, 0)) {
			flow_after_move(c, llc);
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 5);
			return;
		}
	}
	/* Fallback last for tasks with no usable CPU. */
	if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
		flow_after_move(c, llc);
		return;
	}
	/* Nothing queued and prev is still runnable: run prev on. */
	if (flow_try_continue_prev(c, llc, prev))
		return;
	/* Idle with no work. Starts the window here and applies half
	 * once the window elapsed. Holds the lock. */
	{
		struct flow_running_state *rs = &flow_running_state[c];
		u64 idle = READ_ONCE(rs->idle_start_clk);
		u64 now = bpf_ktime_get_ns();

		if (!idle) {
			if (flow_cpu_live(c))
				WRITE_ONCE(rs->idle_start_clk, now);
			return;
		}
		if (now - idle >= (u64)FLOW_SYS_STAT_INTERVAL_NS &&
		    flow_cpu_live(c)) {
			if (READ_ONCE(rs->cpuperf_cur) != (u32)(SCX_CPUPERF_ONE / 2))
				flow_cpuperf_commit(c, (u32)(SCX_CPUPERF_ONE / 2), now);
		}
	}
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u32 llc = 0;
	int v;
	u64 now;
	u64 vd;

	flow_touch_arena();
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	v = topo_cpu_to_llc_id(cpu);
	if (v >= 0 && flow_llc_ok((u32)v))
		llc = (u32)v;
	else if (flow_llc_ok(READ_ONCE(t->llc_id)))
		llc = READ_ONCE(t->llc_id);
	now = bpf_ktime_get_ns();
	vd = (u64)p->scx.dsq_vtime;
	/* Advance the logical clock toward the running due time. */
	{
		u64 clc = READ_ONCE(sys_stat.cur_logical_clk);
		u64 nq = READ_ONCE(sys_stat.nr_queued);

		if (!nq)
			nq = 1ULL;
		if (vd > clc)
			WRITE_ONCE(sys_stat.cur_logical_clk, clc + (vd - clc) / nq);
	}
	/* Fold this task service into the system mean. */
	WRITE_ONCE(sys_stat.avg_svc_time_iwgt,
		   flow_calc_avg(READ_ONCE(sys_stat.avg_svc_time_iwgt),
				 READ_ONCE(t->svc_time_iwgt)));
	rs = &flow_running_state[cpu];
	{
		u32 lc = flow_calc_lat_cri(p, t);
		u64 slice = flow_calc_slice(t, rs);

		t->lat_cri = lc;
		t->slice_ns = slice;
		WRITE_ONCE(rs->lat_cri, lc);
		WRITE_ONCE(rs->llc_id, llc);
		WRITE_ONCE(rs->running_clk, now);
		WRITE_ONCE(rs->est_stopping_clk, now + slice);
		WRITE_ONCE(rs->sum_lat_cri, READ_ONCE(rs->sum_lat_cri) + (u64)lc);
		if (lc > READ_ONCE(rs->max_lat_cri))
			WRITE_ONCE(rs->max_lat_cri, lc);
		__sync_fetch_and_add(&rs->nr_sched, 1ULL);
	}
	t->last_running_clk = now;
	/* Drop the queue gauge now that the task left the DSQ. */
	{
		u32 old = __sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);

		if (old & (u32)FLOW_FLAG_QUEUED) {
			u32 q = READ_ONCE(t->llc_id);

			if (!flow_llc_ok(q))
				q = 0;
			flow_queued_dec(q);
			{
				u64 nq = READ_ONCE(sys_stat.nr_queued);

				if (nq)
					__sync_val_compare_and_swap(&sys_stat.nr_queued, nq, nq - 1);
			}
		}
		if (READ_ONCE(t->pinned_cpu) >= 0) {
			t->pinned_cpu = -1;
			if (READ_ONCE(rs->nr_pinned))
				__sync_fetch_and_sub(&rs->nr_pinned, 1U);
		}
	}
	/* Busy cores ramp to max at once. Holds the lock. */
	WRITE_ONCE(rs->idle_start_clk, 0);
	flow_cpuperf_commit(cpu, (u32)SCX_CPUPERF_ONE, now);
}

void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	u64 now;

	flow_touch_arena();
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	now = bpf_ktime_get_ns();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	/* Refresh max every millisecond so rate limits keep the target. Holds the lock. */
	flow_cpuperf_commit(cpu, (u32)SCX_CPUPERF_ONE, now);
	have = READ_ONCE(t->slice_ns);
	if (have > cur) {
		u64 delta = have - cur;
		u32 w = flow_task_weight(p, t);

		t->acc_runtime_ns += delta;
		if (w)
			t->svc_time_iwgt += delta * 100ULL / (u64)w;
		WRITE_ONCE(rs->tot_iwgt, READ_ONCE(rs->tot_iwgt) + delta);
		t->slice_ns = cur;
		/* Pinned tasks waiting here shorten the running slice. */
		if (READ_ONCE(rs->nr_pinned)) {
			u64 base = READ_ONCE(sys_stat.slice_ns);

			if (!base)
				base = (u64)FLOW_SLICE_MIN_NS;
			if (cur > base)
				scx_bpf_task_set_slice(p, base);
		}
	}
	/* A claimed stop yields at the next check with no interrupt. */
	if (cur > 1ULL && READ_ONCE(rs->est_stopping_clk) <= now)
		scx_bpf_task_set_slice(p, 1U);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	u64 now;

	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	have = READ_ONCE(t->slice_ns);
	now = bpf_ktime_get_ns();
	/* Charge the tail past the last tick, then fold the average. */
	if (have > cur) {
		u64 tail = have - cur;
		u32 w = flow_task_weight(p, t);

		t->acc_runtime_ns += tail;
		if (w)
			t->svc_time_iwgt += tail * 100ULL / (u64)w;
		WRITE_ONCE(rs->tot_iwgt, READ_ONCE(rs->tot_iwgt) + tail);
	}
	t->avg_runtime_ns = flow_calc_avg(READ_ONCE(t->avg_runtime_ns),
					  READ_ONCE(t->acc_runtime_ns));
	{
		u64 last = READ_ONCE(t->last_running_clk);
		u64 gap = now > last ? now - last : 0;

		t->run_freq = flow_calc_avg_freq(READ_ONCE(t->run_freq), gap);
		t->last_running_clk = now;
	}
	t->slice_ns = cur;
	if (runnable)
		flow_stat_inc(READ_ONCE(rs->llc_id), 10);
	else if (!cur)
		flow_stat_inc(READ_ONCE(rs->llc_id), 9);
}

void BPF_STRUCT_OPS(flow_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	u64 now;

	(void)deq_flags;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		return;
	now = bpf_ktime_get_ns();
	{
		u64 last = READ_ONCE(t->last_quiescent_clk);
		u64 gap = (last && now > last) ? now - last : 0;

		if (gap)
			t->wait_freq = flow_calc_avg_freq(READ_ONCE(t->wait_freq), gap);
		t->last_quiescent_clk = now;
	}
}

static int flow_stat_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	u64 sum = 0;
	u64 max = 0;
	u32 cpu;
	u64 ncpu;
	u64 nq;
	u64 slice;

	(void)map;
	(void)key;
	flow_touch_arena();
	/* Mean plus max score over online CPUs. */
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 v;

		if ((u64)cpu >= scx_bpf_nr_cpu_ids())
			continue;
		v = READ_ONCE(flow_running_state[cpu].sum_lat_cri);
		sum += v;
		WRITE_ONCE(flow_running_state[cpu].sum_lat_cri, 0);
		v = READ_ONCE(flow_running_state[cpu].max_lat_cri);
		if (v > max)
			max = v;
		WRITE_ONCE(flow_running_state[cpu].max_lat_cri, 0);
	}
	ncpu = scx_bpf_nr_cpu_ids();
	if (!ncpu)
		ncpu = 1ULL;
	WRITE_ONCE(sys_stat.avg_lat_cri, sum / ncpu);
	WRITE_ONCE(sys_stat.max_lat_cri, max);
	WRITE_ONCE(sys_stat.thr_lat_cri, max >> (u32)FLOW_PREEMPT_SHIFT);
	if (!READ_ONCE(sys_stat.thr_lat_cri) && max)
		WRITE_ONCE(sys_stat.thr_lat_cri, 1ULL);
	/* Base slice covers all queued tasks inside ten milliseconds. */
	nq = READ_ONCE(sys_stat.nr_queued);
	if (!nq)
		nq = 1ULL;
	slice = (u64)FLOW_TARGETED_LATENCY_NS * ncpu / nq;
	if (slice < (u64)FLOW_SLICE_MIN_NS)
		slice = (u64)FLOW_SLICE_MIN_NS;
	if (slice > (u64)FLOW_SLICE_MAX_NS)
		slice = (u64)FLOW_SLICE_MAX_NS;
	WRITE_ONCE(sys_stat.slice_ns, slice);
	if (!READ_ONCE(sys_stat.nr_queued) && READ_ONCE(sys_stat.avg_svc_time_iwgt))
		WRITE_ONCE(sys_stat.avg_svc_time_iwgt,
			   READ_ONCE(sys_stat.avg_svc_time_iwgt) -
			   (READ_ONCE(sys_stat.avg_svc_time_iwgt) >> 3));
	bpf_timer_start(timer, (u64)FLOW_SYS_STAT_INTERVAL_NS, 0);
	return 0;
}

void BPF_STRUCT_OPS(flow_set_cpumask, struct task_struct *p, const struct cpumask *mask)
{
	struct flow_task_ctx *t;

	(void)mask;
	flow_touch_arena();
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);

		if (!flow_llc_ok(qllc))
			qllc = 0;
		if (owner < 0) {
			flow_stat_inc(qllc, 8);
			return;
		}
		if (!flow_cpu_allowed(owner, p) || !flow_cpu_live((u32)owner)) {
			flow_stat_inc(qllc, 8);
			return;
		}
		flow_kick_idle_lockfree(owner, p, qllc);
		flow_stat_inc(qllc, 11);
		return;
	}
	{
		s32 tgt = flow_first_allowed(p);
		int vv;

		if (tgt < 0)
			return;
		if (!flow_cpu_live((u32)tgt))
			return;
		vv = topo_cpu_to_llc_id((u32)tgt);
		if (vv < 0 || !flow_llc_ok((u32)vv))
			return;
		t->llc_id = (u32)vv;
	}
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;

	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	t->acc_runtime_ns = 0;
	t->avg_runtime_ns = 0;
	t->svc_time_iwgt = 0;
	t->last_running_clk = 0;
	t->last_runnable_clk = 0;
	t->last_quiescent_clk = 0;
	t->run_freq = 0;
	t->wait_freq = 0;
	t->wake_freq = 0;
	t->lat_cri = 1U;
	t->lat_cri_waker = 0;
	t->lat_cri_wakee = 0;
	t->flags = 0;
	/* Cold start uses LLC 0 until the first enqueue sets the owner. */
	t->llc_id = 0;
	t->pinned_cpu = -1;
	t->slice_ns = (u64)FLOW_SLICE_MIN_NS;
	scx_bpf_task_set_dsq_vtime(p, 0);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;

	(void)args;
	if (!p)
		return 0;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (t) {
		t->acc_runtime_ns = 0;
		t->avg_runtime_ns = 0;
		t->svc_time_iwgt = 0;
		t->last_running_clk = 0;
		t->last_runnable_clk = 0;
		t->last_quiescent_clk = 0;
		t->run_freq = 0;
		t->wait_freq = 0;
		t->wake_freq = 0;
		t->lat_cri = 1U;
		t->lat_cri_waker = 0;
		t->lat_cri_wakee = 0;
		t->flags = 0;
		t->llc_id = 0;
		t->pinned_cpu = -1;
		t->slice_ns = (u64)FLOW_SLICE_MIN_NS;
		scx_bpf_task_set_dsq_vtime(p, 0);
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	struct flow_task_ctx *t;
	u32 old;

	(void)args;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	old = __sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	if (old & (u32)FLOW_FLAG_QUEUED) {
		u32 llc = READ_ONCE(t->llc_id);

		if (!flow_llc_ok(llc))
			llc = 0;
		flow_queued_dec(llc);
		{
			u64 nq = READ_ONCE(sys_stat.nr_queued);

			if (nq)
				__sync_val_compare_and_swap(&sys_stat.nr_queued, nq, nq - 1);
		}
	}
	if (READ_ONCE(t->pinned_cpu) >= 0) {
		s32 pc = READ_ONCE(t->pinned_cpu);

		t->pinned_cpu = -1;
		if (pc >= 0 && flow_cpu_ok((u32)pc)) {
			struct flow_running_state *rs = &flow_running_state[(u32)pc];

			if (READ_ONCE(rs->nr_pinned))
				__sync_fetch_and_sub(&rs->nr_pinned, 1U);
		}
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u32 i;
	u32 k = 0;
	struct flow_update_timer *ft;
	int err;

	flow_touch_arena();
	n = scx_bpf_nr_cpu_ids();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	/* The topology tree must be ready before any queue is built.
	 * Userspace sets up the tree before load, so a missing tree
	 * fails closed here with no partial queues. */
	if (!topo_all) {
		scx_bpf_error("topology tree missing");
		return -ENODEV;
	}
	/* Operational queue table caps at five hundred twelve. The first
	 * check guards the static area and the second guards the DSQ
	 * table, so both stay closed with no silent truncation. */
	if (n > 512ULL) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	flow_ccx_prefer = 1;
	WRITE_ONCE(sys_stat.cur_logical_clk, 0);
	WRITE_ONCE(sys_stat.avg_svc_time_iwgt, 0);
	WRITE_ONCE(sys_stat.avg_lat_cri, 0);
	WRITE_ONCE(sys_stat.max_lat_cri, 0);
	WRITE_ONCE(sys_stat.thr_lat_cri, 0);
	WRITE_ONCE(sys_stat.slice_ns, (u64)FLOW_SLICE_MAX_NS);
	WRITE_ONCE(sys_stat.nr_queued, 0);
	/* One DSQ per CPU for pinned tasks. */
	bpf_for(i, 0, FLOW_MAX_CPUS) {
		s32 ret;

		if ((u64)i >= n)
			break;
		ret = scx_bpf_create_dsq((u64)FLOW_CPU_DSQ_BASE + (u64)i, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("cpu dsq create failed");
			return ret;
		}
	}
	/* One vtime DSQ per LLC for shared tasks. */
	bpf_for(i, 0, FLOW_MAX_LLCS) {
		s32 ret;

		ret = scx_bpf_create_dsq((u64)FLOW_LLC_DSQ_BASE + (u64)i, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("llc dsq create failed");
			return ret;
		}
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);

		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	/* Arm the ten millisecond board plus idle decay timer. */
	ft = bpf_map_lookup_elem(&update_timer, &k);
	if (!ft) {
		scx_bpf_error("timer lookup failed");
		return -ESRCH;
	}
	bpf_timer_init(&ft->timer, &update_timer, FLOW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(&ft->timer, flow_stat_timer_cb);
	err = bpf_timer_start(&ft->timer, (u64)FLOW_SYS_STAT_INTERVAL_NS, 0);
	if (err) {
		scx_bpf_error("timer start failed");
		return err;
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	u32 i;

	UEI_RECORD(uei, info);
	bpf_for(i, 0, FLOW_MAX_CPUS) {
		if ((u64)i >= scx_bpf_nr_cpu_ids())
			break;
		scx_bpf_destroy_dsq((u64)FLOW_CPU_DSQ_BASE + (u64)i);
	}
	bpf_for(i, 0, FLOW_MAX_LLCS)
		scx_bpf_destroy_dsq((u64)FLOW_LLC_DSQ_BASE + (u64)i);
	scx_bpf_destroy_dsq((u64)FLOW_FALLBACK_DSQ);
}
#endif
