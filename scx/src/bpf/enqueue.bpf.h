// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Runnable resets the per activation burn and folds wake rates with
 * two way urgency inherit capped at one quarter. Enqueue prices the
 * due time and parks pinned tasks on the CPU DSQ and shared tasks
 * on the LLC DSQ. An idle target is claimed and kicked at max. A
 * non greedy urgent task past the top tier threshold tries a soft
 * yield on a peer CPU with a near stop claim and no IPI.
 * Dequeue drops the queue gauge on cancel. Every insert pairs with
 * one dec on move or cancel for telemetry only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"

static __always_inline int flow_llc_for_cpu(s32 tgt, u32 *out)
{
	int v;

	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return -1;
	v = topo_cpu_to_llc_id((u32)tgt);
	if (v < 0 || !flow_llc_ok((u32)v))
		return -1;
	*out = (u32)v;
	return 0;
}

static __always_inline void flow_queued_add(u32 llc)
{
	flow_stat_inc(llc, 0);
	__sync_fetch_and_add(&sys_stat.nr_queued, 1ULL);
}

static __always_inline void flow_queued_drop(u32 llc)
{
	u32 q = llc;

	if (!flow_llc_ok(q))
		q = 0;
	flow_queued_dec(q);
	{
		u64 old = READ_ONCE(sys_stat.nr_queued);

		if (old)
			__sync_val_compare_and_swap(&sys_stat.nr_queued, old, old - 1);
	}
}

/* Idle wake only. Misses count a skip with no wake. A bad or masked
 * or offline or busy target skips. A won idle claim ramps to max and
 * fires one idle kick. */
static __noinline void flow_kick_idle_only(s32 tgt, struct task_struct *p, u32 llc)
{
	u32 c;

	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!scx_bpf_test_and_clear_cpu_idle(tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	c = (u32)tgt;
	if (!flow_cpu_ok(c) || !flow_cpu_live(c)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if ((u64)c >= scx_bpf_nr_cpu_ids()) {
		flow_stat_inc(llc, 8);
		return;
	}
	flow_cpuperf_mark(c, false);
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}

/* Soft yield without IPI. Greedy tasks and tasks below the top tier
 * threshold never yield. Probes the hint plus two peers in the same
 * LLC and picks the lowest score with the farthest stop stamp. The
 * victim stop is claimed near so it yields at its next check with no
 * pipeline stall. At most one yield per run. */
static __noinline void flow_try_preempt(struct task_struct *p, struct flow_task_ctx *t,
					s32 tgt, u32 llc)
{
	u32 self;
	u32 thr;
	u32 me;
	u64 now;
	s32 cand[3];
	int i;
	s32 best = -1;
	u64 best_stop = 0;
	u32 best_score = 0;
	bool first = true;

	if (!p || !t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_IS_GREEDY)
		return;
	me = flow_calc_lat_cri(p, t);
	thr = (u32)READ_ONCE(sys_stat.thr_lat_cri);
	if (thr && me < thr)
		return;
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return;
	self = (u32)bpf_get_smp_processor_id();
	now = bpf_ktime_get_ns();
	cand[0] = tgt;
	cand[1] = -1;
	cand[2] = -1;
	{
		u32 ncpu = (u32)scx_bpf_nr_cpu_ids();
		u32 r1;
		u32 r2;

		if (!ncpu)
			ncpu = 1U;
		r1 = bpf_get_prandom_u32() % ncpu;
		r2 = bpf_get_prandom_u32() % ncpu;
		if (flow_cpu_ok(r1) && (s32)r1 != tgt)
			cand[1] = (s32)r1;
		if (flow_cpu_ok(r2) && (s32)r2 != tgt && (s32)r2 != cand[1])
			cand[2] = (s32)r2;
	}
	for (i = 0; i < 3; i++) {
		s32 c = cand[i];
		struct flow_running_state *rs;
		u32 cs;
		u64 stop;

		if (c < 0 || !flow_cpu_ok((u32)c))
			continue;
		if ((u64)(u32)c >= scx_bpf_nr_cpu_ids())
			continue;
		if (!flow_cpu_live((u32)c))
			continue;
		if (!flow_cpu_allowed(c, p))
			continue;
		rs = &flow_running_state[(u32)c];
		if (READ_ONCE(rs->llc_id) != llc)
			continue;
		cs = READ_ONCE(rs->lat_cri);
		if (cs >= me)
			continue;
		stop = READ_ONCE(rs->est_stopping_clk);
		if (stop < now)
			continue;
		if (first || stop > best_stop) {
			first = false;
			best_stop = stop;
			best_score = cs;
			best = c;
		}
		(void)best_score;
	}
	if (best < 0)
		return;
	if ((u32)best == self)
		return;
	/* Claim the victim stop stamp so the next check on that CPU sees a
	 * near stop with no IPI. The victim yields at its next check. */
	{
		u32 b = (u32)best;

		if ((u64)b >= scx_bpf_nr_cpu_ids())
			return;
		{
			struct flow_running_state *rs = &flow_running_state[b];
			u64 old = READ_ONCE(rs->est_stopping_clk);
			u64 want = now + 1ULL;

			if (want < old)
				__sync_val_compare_and_swap(&rs->est_stopping_clk, old, want);
			__sync_fetch_and_add(&rs->nr_preempt, 1ULL);
		}
	}
}

void BPF_STRUCT_OPS(flow_runnable, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t;
	u64 now;

	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	now = bpf_ktime_get_ns();
	t->acc_runtime_ns = 0;
	t->last_runnable_clk = now;
	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;
	{
		struct task_struct *waker = bpf_get_current_task_btf();
		struct flow_task_ctx *wt;

		if (!waker || waker == p)
			return;
		wt = bpf_task_storage_get(&task_ctx_stor, waker, 0, 0);
		if (!wt)
			return;
		{
			u64 last = READ_ONCE(wt->last_runnable_clk);
			u64 gap = now > last ? now - last : 0;

			wt->wake_freq = flow_calc_avg_freq(READ_ONCE(wt->wake_freq), gap);
			wt->last_runnable_clk = now;
		}
		{
			u32 giver = READ_ONCE(wt->lat_cri);
			u32 mine = READ_ONCE(t->lat_cri);
			u32 add = giver >> 3;
			u32 cap = mine >> 2;

			if (add > cap)
				add = cap;
			t->lat_cri_waker = giver;
			if (mine + add > mine)
				t->lat_cri = mine + add;
		}
		{
			u32 giver = READ_ONCE(t->lat_cri);
			u32 mine = READ_ONCE(wt->lat_cri);
			u32 add = giver >> 3;
			u32 cap = mine >> 2;

			if (add > cap)
				add = cap;
			if (mine + add > mine) {
				wt->lat_cri_wakee = giver;
				WRITE_ONCE(wt->lat_cri, mine + add);
			}
		}
	}
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu;
	s32 tgt;
	u32 llc = 0;
	bool pinned = false;
	bool no_cpu = false;
	struct flow_task_ctx *t;
	u32 fl;

	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		s32 fb = flow_first_allowed(p);

		if (fb < 0)
			fb = (s32)bpf_get_smp_processor_id();
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(0, 2);
		return;
	}
	fl = READ_ONCE(t->flags);
	/* Direct dispatch from select already queued to local. Clear the
	 * mark and leave so the task is not queued twice. */
	if (fl & (u32)FLOW_FLAG_DIRECT_DISPATCH) {
		WRITE_ONCE(t->flags, fl & (u32)~(u32)FLOW_FLAG_DIRECT_DISPATCH);
		return;
	}
	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu < 0)
		task_cpu = (s32)bpf_get_smp_processor_id();
	tgt = flow_constrained_target(task_cpu, p);
	pinned = flow_is_pinned(p);
	if (tgt < 0 || !flow_cpu_live((u32)tgt)) {
		no_cpu = true;
	} else {
		u32 tmp = 0;

		if (!flow_llc_for_cpu(tgt, &tmp))
			llc = tmp;
	}
	/* Fallback to LLC 0 keeps stats bounded. */
	llc &= ((u32)FLOW_MAX_LLCS - 1U);
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;

			scx_bpf_dsq_insert(p, ldsq, 1000ULL, enq_flags);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, 1000ULL, enq_flags);
		flow_stat_inc(llc, 2);
		return;
	}
	{
		u64 vd = flow_calc_when_to_run(p, t);
		u64 greedy = flow_calc_greedy_penalty(p, t);
		u32 lc = flow_calc_lat_cri(p, t);

		if (greedy > 1024ULL)
			WRITE_ONCE(t->flags, READ_ONCE(t->flags) | (u32)FLOW_FLAG_IS_GREEDY);
		else
			WRITE_ONCE(t->flags, READ_ONCE(t->flags) & (u32)~(u32)FLOW_FLAG_IS_GREEDY);
		t->lat_cri = lc;
		t->llc_id = llc;
		scx_bpf_task_set_dsq_vtime(p, vd);
		if (!no_cpu && pinned) {
			u64 dsq = (u64)FLOW_CPU_DSQ_BASE + (u64)(u32)tgt;
			struct flow_running_state *rs = &flow_running_state[(u32)tgt];
			u64 slice = flow_calc_slice(t, rs);

			__sync_fetch_and_add(&rs->nr_pinned, 1ULL);
			t->pinned_cpu = tgt;
			t->slice_ns = slice;
			__sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
			scx_bpf_dsq_insert(p, dsq, slice, enq_flags);
			flow_queued_add(llc);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
		if (!no_cpu) {
			u64 dsq = (u64)FLOW_LLC_DSQ_BASE + (u64)llc;
			struct flow_running_state *rs = &flow_running_state[(u32)tgt];
			u64 slice = flow_calc_slice(t, rs);

			t->pinned_cpu = -1;
			t->slice_ns = slice;
			__sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
			scx_bpf_dsq_insert(p, dsq, slice, enq_flags);
			flow_queued_add(llc);
			if (scx_bpf_test_and_clear_cpu_idle(tgt)) {
				if (flow_cpu_ok((u32)tgt) &&
				    (u64)(u32)tgt < scx_bpf_nr_cpu_ids())
					flow_cpuperf_mark((u32)tgt, false);
				scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
				flow_stat_inc(llc, 7);
				return;
			}
			flow_try_preempt(p, t, tgt, llc);
			return;
		}
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 2);
	}
}

void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	u32 old;

	(void)deq_flags;
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
		flow_queued_drop(llc);
	}
}
#endif
