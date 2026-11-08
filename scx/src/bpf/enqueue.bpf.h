// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the per CPU queue of the constrained target
 * in vd order. The upstream queue keeps insertion order for equal
 * vd, so the code adds no extra tie handling. All shared tasks take
 * the first strand. Pinned tasks join the local queue in order with
 * a single slice. Exiting tasks use the local queue when allowed and
 * the owner queue otherwise with a short slice. Tasks that have no
 * usable CPU join the fallback queue in FIFO order. The queue key is
 * the vd. Shared inserts move past the per LLC floor. Vd adds the
 * share step to the floored time. The charge scales with the share.
 * Each shared enqueue checks the idle flag first, then the running
 * vd on the target for an earlier vd win. Idle targets take an idle
 * wake and never preempt. Each running instance kicks at most once.
 * A vd win kicks for preempt on a win, else it counts a skip with no
 * wake. A wake goes only to an idle target, else it counts a skip
 * with no wake. The kernel idle flag decides the idle wake. Preempts
 * stay in the same LLC with an allowed live target. Local inserts
 * are not counted in the shared gauge. Shared and fallback inserts
 * count the gauge, and fallback inserts also count fallback. Dequeue
 * drops the gauge on cancel. Masks are checked again before each
 * wake, so a task is never kicked toward a CPU outside its current
 * mask. Enqueue reads the cgroup map on shared and fallback inserts.
 * The birth id comes from init args. Full and overfull inserts fall
 * back to the FIFO queue with no extra probe.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "cgroup.bpf.h"
#include "select.bpf.h"
#include <lib/dhq.h>
#include <lib/sdt_alloc.h>
static __always_inline scx_dhq_t *flow_queue_for_cpu(s32 tgt)
{
	u64 h;
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return 0;
	if (!flow_cpu_live((u32)tgt))
		return 0;
	h = READ_ONCE(flow_dhqs[(u32)tgt]);
	if (!h)
		return 0;
	return (scx_dhq_t *)h;
}
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
static __always_inline void flow_kick_vd(s32 tgt, struct task_struct *p, u32 llc, s64 new_vd)
{
	struct flow_running_state *rs;
	u64 rgen;
	u32 rllc;
	u32 last;
	s64 run_vd;
	if (tgt < 0 || !p || !flow_cpu_ok((u32)tgt) || !flow_cpu_allowed(tgt, p) ||
	    !flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (scx_bpf_test_and_clear_cpu_idle(tgt)) {
		scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
		flow_stat_inc(llc, 7);
		return;
	}
	rs = &flow_running_state[(u32)tgt];
	rgen = READ_ONCE(rs->gen);
	rllc = READ_ONCE(rs->llc_id);
	if (!rgen || !flow_llc_ok(rllc) || rllc != llc) {
		flow_stat_inc(llc, 8);
		return;
	}
	last = READ_ONCE(rs->pad);
	if ((u32)rgen == last) {
		flow_stat_inc(llc, 8);
		return;
	}
	run_vd = READ_ONCE(rs->vd);
	if (!(new_vd < run_vd)) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (__sync_val_compare_and_swap(&rs->pad, last, (u32)rgen) != last) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu;
	s32 tgt;
	u32 llc = 0;
	u32 cpu_ok = 0;
	s64 raw_v;
	bool pinned = false;
	struct flow_task_ctx *t;
	u32 old_flags;
	if (!p)
		return;
	scx_arena_subprog_init();
	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	tgt = flow_constrained_target(task_cpu, p);
	if (tgt >= 0 && flow_cpu_live((u32)tgt)) {
		u32 tmp = 0;
		if (!flow_llc_for_cpu(tgt, &tmp))
			llc = tmp;
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
				scx_dhq_t *dhq = no_cpu ? 0 : flow_queue_for_cpu(tgt);
				bool fell = true;
				if (dhq) {
					int ret = scx_dhq_insert_vtime(dhq, (u64)p->pid,
								       (u64)raw_v,
								       (u64)SCX_DHQ_STRAND_A);
					if (!ret)
						fell = false;
				}
				if (fell)
					scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ,
							   (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				flow_stat_inc(llc, 0);
				if (fell)
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
			u32 pllc = llc;
			u32 tmp = 0;
			if (!flow_llc_for_cpu(first, &tmp))
				pllc = tmp;
			{
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)first;
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
		scx_dhq_t *dhq = no_cpu ? 0 : flow_queue_for_cpu(tgt);
		bool fell = true;
		t->llc_id = llc;
		if (dhq) {
			int ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)raw_v,
						       (u64)SCX_DHQ_STRAND_A);
			if (!ret)
				fell = false;
		}
		if (fell)
			scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ,
					   (u64)FLOW_EXIT_SLICE_NS, enq_flags);
		flow_stat_inc(llc, 0);
		if (fell)
			flow_stat_inc(llc, 2);
		flow_kick_idle_only(tgt, p, llc);
		return;
	}
	if (pinned) {
		t->llc_id = llc;
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, (u64)FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(llc, 0);
		flow_stat_inc(llc, 2);
		/* No owner queue took the task. Kick self when idle so the
		 * fallback head is peeked again soon. */
		flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
		return;
	}
	{
		/* Shared inserts join the order past the floor. Tasks with no
		 * usable CPU skip the floor, and fallback inserts stay FIFO.
		 * Each owner queue holds at most two hundred fifty six tasks. */
		s64 base = READ_ONCE(t->vtime);
		u32 w = flow_cgroup_lookup(READ_ONCE(t->cgrp_id));
		s64 floored = no_cpu ? base : flow_seq_floor(llc, base);
		s64 vd = flow_vd_for(floored, w);
		u64 slice_len = (u64)FLOW_SLICE_MIN_NS;
		scx_dhq_t *dhq = no_cpu ? 0 : flow_queue_for_cpu(tgt);
		bool fell = true;
		t->vtime = floored;
		t->vd = vd;
		t->slice_rem = slice_len;
		t->llc_id = llc;
		/* Mirror the due time so later reads see the same value. */
		scx_bpf_task_set_dsq_vtime(p, vd);
		/* Overfull inserts fall back to FIFO with no extra probe. */
		if (dhq) {
			int ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)vd,
						       (u64)SCX_DHQ_STRAND_A);
			if (!ret)
				fell = false;
		}
		if (fell)
			scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice_len, enq_flags);
		flow_stat_inc(llc, 0);
		if (fell)
			flow_stat_inc(llc, 2);
		if (no_cpu) {
			/* No usable CPU. Kick self when idle so the
			 * fallback head is peeked again soon. */
			flow_kick_idle_only((s32)bpf_get_smp_processor_id(), p, llc);
			return;
		}
		flow_kick_vd(tgt, p, llc, vd);
		return;
	}
insert_only:
	{
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		s64 k = raw_v;
		scx_dhq_t *dhq = no_cpu ? 0 : flow_queue_for_cpu(tgt);
		bool fell = true;
		if (dhq) {
			int ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)k,
						       (u64)SCX_DHQ_STRAND_A);
			if (!ret)
				fell = false;
		}
		if (fell)
			scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, sl, enq_flags);
		flow_stat_inc(llc, 0);
		if (fell)
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
