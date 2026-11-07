// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the LLC queue of the constrained target in time
 * order. The kernel keeps insertion order for equal times, so the
 * code adds no extra tie handling. Pinned tasks join the local queue
 * in order with a single slice. Exiting tasks use the local queue
 * when allowed and the LLC queue otherwise with a short slice. Tasks
 * that have no usable CPU join the fallback queue. The queue key
 * is the stored virtual time. Shared inserts move past the per LLC
 * floor. Queue choice uses remaining time from the aged estimate
 * minus the burnt part with saturation at the floor. The
 * charge scales with the share and the extra amount is fixed. Each
 * enqueue sends at most one idle wake. A wake goes only to an idle
 * target, else it counts a skip with no wake. The kernel idle flag
 * decides the wake. Local inserts are not
 * counted in the shared gauge. Shared and fallback inserts count
 * the gauge, and fallback inserts also count fallback. Dequeue drops
 * the gauge on cancel. Masks are tested again before each wake, so
 * a task is never kicked toward a CPU outside its current mask.
 * Enqueue reads the cgroup map on shared and fallback inserts. The
 * birth id comes
 * from init args. Throttled tasks wait aside under the admin limit
 * and rejoin through the requeue path. Enqueue finalizes the wait
 * kind with the full path and stamps the wait start with the full
 * clock with zero stored as one.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "sjf.bpf.h"
#include "cgroup.bpf.h"
#include "select.bpf.h"
#include "lat.bpf.h"
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
	if (!scx_bpf_test_and_clear_cpu_idle(tgt)) {
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
	u64 slice_len;
	u64 quanta = 1;
	u64 extra = 0;
	u32 prio = (u32)FLOW_PRIO_NORM;
	u32 w = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	u64 now;
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
	bool no_cpu = !cpu_ok || tgt < 0;
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
				if (dsq == (u64)FLOW_FALLBACK_DSQ)
					scx_bpf_dsq_insert(p, dsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				else
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
			flow_lat_finalize(t, (u32)FLOW_LAT_EXITING, scx_bpf_now());
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
				flow_lat_finalize(t, (u32)FLOW_LAT_PINNED, scx_bpf_now());
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_MIN_NS, enq_flags);
				flow_kick_idle_only(first, p, pllc);
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
		flow_lat_finalize(t, (u32)FLOW_LAT_EXITING, scx_bpf_now());
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			scx_bpf_dsq_insert(p, dsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
		else
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
		flow_lat_finalize(t, (u32)FLOW_LAT_PINNED, scx_bpf_now());
		scx_bpf_dsq_insert(p, dsq, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		return;
	}
	now = scx_bpf_now();
	w = flow_cgroup_lookup(t->cgrp_id);
	{
		u64 aged = flow_sjf_age(t->burst_ns ? t->burst_ns : (u64)FLOW_SJF_INIT_NS, t->enq_ns, now, llc);
		u64 est = aged;
		u64 old_rem = t->slice_rem;
		u64 used_last = 0;
		u64 rem;
		if (!t->burst_ns)
			est = (u64)FLOW_SJF_INIT_NS;
		if (t->gen == 0)
			used_last = 0;
		else if (old_rem < (u64)FLOW_SLICE_MIN_NS)
			used_last = (u64)FLOW_SLICE_MIN_NS - old_rem;
		rem = flow_sjf_remain(aged, used_last);
		prio = flow_sjf_prio(rem, t->enq_ns, now);
		if (!flow_prio_ok(prio))
			prio = (u32)FLOW_PRIO_NORM;
		t->burst_ns = est;
		if (prio == (u32)FLOW_PRIO_LAT)
			flow_stat_inc(llc, 15);
		else
			flow_stat_inc(llc, 16);
		slice_len = (u64)FLOW_SLICE_MIN_NS;
		quanta = 1;
		extra = 0;
	}
	{
		/* Shared inserts join the order past the floor. Tasks with no
		 * usable CPU skip the floor, and fallback inserts ignore the
		 * key and stay FIFO. */
		s64 base = t->vtime;
		u64 use_len = 0;
		if (t->gen == 0) {
			/* Fresh tasks never burnt anything, only join the order. */
			raw_v = no_cpu ? base : flow_seq_floor(llc, base);
			t->vtime = raw_v;
		} else if (t->slice_rem == 0) {
			/* The tail already paid at the tick plus stopping, so only
			 * the unpaid part charges here. */
			s64 charged = flow_fair_charge(base, use_len, w);
			charged = flow_fair_extra(charged, extra);
			charged = no_cpu ? charged : flow_seq_floor(llc, charged);
			raw_v = charged;
			t->vtime = charged;
			flow_stat_inc(llc, 9);
			flow_stat_inc(llc, 10);
			flow_stat_add(llc, 19, extra);
			flow_stat_add(llc, 20, quanta);
		} else {
			raw_v = no_cpu ? base : flow_seq_floor(llc, base);
			t->vtime = raw_v;
		}
		t->slice_rem = slice_len;
		t->llc_id = llc;
		t->prio = prio;
		/* Mirror the stored time so later reads see the same value. */
		scx_bpf_task_set_dsq_vtime(p, raw_v);
		if (flow_cgroup_throttled(p, t, true, (u64)raw_v) == -EAGAIN) {
			__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
			return;
		}
	}
	{
		u64 dsq;
		u32 final_kind;
		if (no_cpu)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_llc_dsq_prio(llc, prio);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			final_kind = (u32)FLOW_LAT_FALLBACK;
		else if (!flow_prio_ok(prio))
			final_kind = (u32)FLOW_LAT_OTHER;
		else
			final_kind = prio;
		flow_lat_finalize(t, final_kind, now);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			scx_bpf_dsq_insert(p, dsq, slice_len, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, dsq, slice_len, (u64)raw_v, enq_flags);
		flow_stat_inc(llc, 0);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			flow_stat_inc(llc, 2);
		if (no_cpu) {
			return;
		}
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
insert_only:
	{
		u64 dsq;
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		s64 k = raw_v;
		if (no_cpu)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_llc_dsq_prio(llc, (u32)FLOW_PRIO_NORM);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			scx_bpf_dsq_insert(p, dsq, sl, enq_flags);
		else
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
	if (scx_cgroup_bw_is_task_throttled((u64)t))
		scx_cgroup_bw_cancel((u64)t, SCX_CGROUP_BW_CANCEL_UNLINK);
}
#endif
