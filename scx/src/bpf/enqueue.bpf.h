// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the LLC queue of the constrained target in time
 * order. The kernel keeps insertion order for equal times, so the
 * code adds no extra tie handling. Pinned tasks join the local queue
 * in order with a single slice. Exiting tasks use the local queue
 * when allowed and the LLC queue otherwise with a short slice. Tasks
 * that have no usable CPU join the fallback queue. The stored time
 * is left unchanged while the queue key is earlier for latency
 * sensitive tasks. Fresh times move past the per LLC floor. The
 * charge scales with the share and the extra amount is fixed. Each
 * enqueue sends at most one kick. Local inserts are not counted in
 * the shared gauge. Shared and fallback inserts count the gauge,
 * and fallback inserts also count fallback. Dequeue drops the gauge
 * on cancel. The kick compares shifted keys on both sides and uses
 * the runner queue to shift the runner side. Enqueue reads the
 * cgroup map on every insert. The birth id comes from init args.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "srtf.bpf.h"
#include "cgroup.bpf.h"
#include "select.bpf.h"
static __always_inline int flow_kick_constrained(s32 tgt, s64 use_v, struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;
	u64 gap;
	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL_NS)
		goto idle;
	{
		s64 run_v = rs->vtime;
		int run_lat = (rs->prio == (u32)FLOW_PRIO_LAT);
		s64 run_key = flow_lat_key(run_v, run_lat);
		if (run_key <= use_v)
			goto idle;
		gap = (u64)(run_key - use_v);
	}
	if (gap >= (u64)FLOW_PREEMPT_GAP_NS) {
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		return 1;
	}
idle:
	if (rs->gen != 0 && rs->streak >= (u32)FLOW_STREAK_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 8);
			return 0;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 8);
			return 0;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		flow_stat_inc(llc, 12);
		return 1;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	if (!flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return 0;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
	return 0;
}
static __always_inline void flow_kick_pinned(s32 tgt, struct task_struct *p, u32 llc)
{
	u32 cpu;
	struct flow_running_state *rs;
	if (tgt < 0) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (!flow_cpu_allowed(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	cpu = (u32)tgt;
	if (!flow_cpu_live(cpu)) {
		flow_stat_inc(llc, 8);
		return;
	}
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL_NS)
		goto idle;
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
	return;
idle:
	if (rs->gen != 0 && rs->streak >= (u32)FLOW_STREAK_MAX) {
		if (!flow_cpu_allowed(tgt, p)) {
			flow_stat_inc(llc, 8);
			return;
		}
		if (!flow_cpu_live((u32)tgt)) {
			flow_stat_inc(llc, 8);
			return;
		}
		scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
		flow_stat_inc(llc, 6);
		flow_stat_inc(llc, 12);
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
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}
static __always_inline void flow_kick_idle_only(s32 tgt, struct task_struct *p, u32 llc)
{
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
	scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
	flow_stat_inc(llc, 7);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu;
	s32 tgt;
	u32 llc = 0;
	u32 cpu_ok = 0;
	s64 raw_v;
	s64 key_v;
	u64 slice_len;
	u64 quanta = 1;
	u64 extra = 0;
	u32 prio = (u32)FLOW_PRIO_NORM;
	u32 w = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	u64 now;
	int is_lat = 0;
	bool pinned = false;
	struct flow_task_ctx *t;
	u32 old_flags;
	if (!p)
		return;
	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	tgt = flow_constrained_target(task_cpu, p);
	if (tgt >= 0 && flow_cpu_live((u32)tgt)) {
		struct flow_cpu_ctx *cc;
		u32 key = (u32)tgt;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cc) {
			u32 tmp = READ_ONCE(cc->llc_id);
			if (flow_llc_ok(tmp))
				llc = tmp;
		}
		cpu_ok = 1;
	}
	raw_v = (s64)p->scx.dsq_vtime;
	pinned = flow_is_pinned(p);
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		if (p->flags & PF_EXITING) {
			if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
			{
				u64 dsq = tgt < 0 ? (u64)FLOW_FALLBACK_DSQ : flow_llc_dsq_prio(llc, (u32)FLOW_PRIO_NORM);
				if (!flow_dsq_ok(dsq))
					dsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS, (u64)raw_v, enq_flags);
				flow_stat_inc(llc, 0);
				if (dsq == (u64)FLOW_FALLBACK_DSQ)
					flow_stat_inc(llc, 2);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
		}
		goto insert_only;
	}
	/* Local placements run before ownership is taken. A task on a
	 * local queue is not counted in the shared gauge, so it leaves
	 * without the queued bit. Shared and fallback inserts take the
	 * bit below and count the gauge together. */
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
	}
	if (pinned) {
		s32 first = flow_first_allowed(p);
		if (first < 0)
			first = tgt;
		if (first >= 0 && flow_cpu_allowed(first, p)) {
			u32 pcpu = (u32)first;
			struct flow_cpu_ctx *cc;
			u32 key = pcpu;
			u32 pllc = llc;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (cc) {
				u32 tmp = READ_ONCE(cc->llc_id);
				if (flow_llc_ok(tmp))
					pllc = tmp;
			}
			{
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)pcpu;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_MIN_NS, enq_flags);
				flow_kick_pinned(first, p, pllc);
				return;
			}
		}
	}
	old_flags = __sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
	if (old_flags & (u32)FLOW_FLAG_QUEUED) {
		flow_fb_inc(llc, 4);
		return;
	}
	if (p->flags & PF_EXITING) {
		u64 dsq = tgt < 0 ? (u64)FLOW_FALLBACK_DSQ : flow_llc_dsq_prio(llc, (u32)FLOW_PRIO_NORM);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		t->llc_id = llc;
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS, (u64)raw_v, enq_flags);
		flow_stat_inc(llc, 0);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
	if (pinned) {
		u64 dsq = (u64)FLOW_FALLBACK_DSQ;
		t->llc_id = llc;
		scx_bpf_dsq_insert(p, dsq, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		return;
	}
	now = bpf_ktime_get_ns();
	w = flow_cgroup_lookup(t->cgrp_id);
	{
		int rescued = 0;
		u64 aged = flow_sjf_age(t->burst_ns ? t->burst_ns : (u64)FLOW_SJF_INIT_NS, t->enq_ns, now, llc, &rescued);
		u64 est = aged;
		if (!t->burst_ns)
			est = (u64)FLOW_SJF_INIT_NS;
		prio = flow_sjf_prio(est, t->enq_ns, now);
		if (!flow_prio_ok(prio))
			prio = (u32)FLOW_PRIO_NORM;
		t->burst_ns = est;
		is_lat = (prio == (u32)FLOW_PRIO_LAT);
		if (is_lat)
			flow_stat_inc(llc, 15);
		else
			flow_stat_inc(llc, 16);
		slice_len = est;
		if (slice_len < (u64)FLOW_SLICE_MIN_NS)
			slice_len = (u64)FLOW_SLICE_MIN_NS;
		if (slice_len > (u64)FLOW_SLICE_MIN_NS * 3)
			slice_len = (u64)FLOW_SLICE_MIN_NS * 3;
		quanta = slice_len / (u64)FLOW_SLICE_MIN_NS;
		if (quanta < 1)
			quanta = 1;
		if (quanta > 3)
			quanta = 3;
		extra = quanta - 1;
		if (cpu_ok) {
			struct flow_running_state *rs = &flow_running_state[(u32)tgt];
			if (rs->gen != 0 && flow_hog_rounds(rs->streak)) {
				u64 dem = flow_hog_demote(extra);
				if (dem != extra) {
					extra = dem;
					quanta = extra + 1;
					slice_len = quanta * (u64)FLOW_SLICE_MIN_NS;
				}
			}
		}
		t->enq_ns = now ? now : 1;
	}
	{
		s64 base = t->vtime;
		u64 use_len = slice_len;
		if (t->gen == 0 || base == 0) {
			s64 floored = flow_seq_floor(llc, base);
			raw_v = floored;
			if (raw_v <= 0)
				raw_v = floored;
			t->vtime = raw_v;
		} else if (t->slice_rem == 0) {
			s64 charged = flow_fair_charge(base, use_len, w);
			charged = flow_fair_extra(charged, extra);
			charged = flow_seq_floor(llc, charged);
			raw_v = charged;
			t->vtime = charged;
			flow_stat_inc(llc, 9);
			flow_stat_inc(llc, 10);
			flow_stat_add(llc, 19, extra);
			flow_stat_add(llc, 20, quanta);
		} else {
			raw_v = base;
		}
		t->slice_rem = slice_len;
		t->llc_id = llc;
		t->prio = prio;
		key_v = flow_lat_key(raw_v, is_lat);
	}
	{
		u64 dsq;
		if (!cpu_ok || tgt < 0)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_llc_dsq_prio(llc, prio);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, slice_len, (u64)key_v, enq_flags);
		flow_stat_inc(llc, 0);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			flow_stat_inc(llc, 2);
		if (!cpu_ok || tgt < 0) {
			return;
		}
		if (flow_kick_constrained(tgt, key_v, p, llc) && is_lat)
			flow_stat_inc(llc, 17);
		return;
	}
insert_only:
	{
		u64 dsq;
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		s64 k = raw_v;
		if (!cpu_ok || tgt < 0)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_llc_dsq_prio(llc, (u32)FLOW_PRIO_NORM);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, sl, (u64)k, enq_flags);
		flow_stat_inc(llc, 0);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
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
		u32 dllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(dllc))
			dllc = 0;
		flow_queued_dec(dllc);
	}
}
#endif
