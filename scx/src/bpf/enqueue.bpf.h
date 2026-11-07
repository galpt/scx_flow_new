// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the per CPU queue of the constrained target
 * in time order. The kernel keeps insertion order for equal times,
 * so the code adds no extra tie handling. Urgent tasks take the
 * first strand and the rest take the second strand. Pinned tasks
 * join the local queue in order with a single slice. Exiting tasks
 * use the local queue when allowed and the owner queue otherwise
 * with a short slice. Tasks that have no usable CPU join the
 * fallback queue. The queue key is the stored virtual time. Shared
 * inserts move past the per LLC floor. Queue choice uses slack from deadline minus now minus
 * remain with saturation in fixed bands. The
 * charge scales with the share and the extra amount is fixed. Each
 * shared enqueue first checks the hold, then the idle flag, then
 * the running slack on the target for a gap win. Holds gate gap
 * wins and count a skip. Idle targets take an idle wake and never
 * preempt. Each running instance kicks at most once. A gap win
 * kicks for preempt on a win, else it counts a skip with no wake.
 * Overdue tasks stay on the first strand with a fresh span. A wake
 * goes only to an idle target, else it counts a
 * skip with no wake. The kernel idle flag decides the idle wake.
 * Preempts stay in the same LLC with an
 * allowed live target. Local inserts are not
 * counted in the shared gauge. Shared and fallback inserts count
 * the gauge, and fallback inserts also count fallback. Dequeue drops
 * the gauge on cancel. Masks are tested again before each wake, so
 * a task is never kicked toward a CPU outside its current mask.
 * Enqueue reads the cgroup map on shared and fallback inserts. The
 * birth id comes
 * from init args. Enqueue finalizes the wait kind with the full
 * path and stamps the wait start with the full clock with zero
 * stored as one. Distant wakes hold when the target drains fast.
 * Long waits suppress one hold then decay, and holds count a skip.
 * New storage repairs home to unset for the first run. Holds stay
 * distant only with the same cluster excluded.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "fair.bpf.h"
#include "lst.bpf.h"
#include "cgroup.bpf.h"
#include "select.bpf.h"
#include "lat.bpf.h"
#include "lib/dhq.bpf.h"
static __always_inline u64 flow_enqueue_dhq_or_fallback(s32 tgt, u32 strand)
{
	u64 dsq_a;
	u64 dsq_b;
	s32 qa;
	s32 qb;
	u64 my;
	u64 other;
	if (tgt < 0 || !flow_dhq_ok((u32)tgt, strand))
		return (u64)FLOW_FALLBACK_DSQ;
	if (!READ_ONCE(flow_dhq_live[(u32)tgt]))
		return (u64)FLOW_FALLBACK_DSQ;
	dsq_a = flow_dhq_id((u32)tgt, (u32)FLOW_DHQ_STRAND_A);
	dsq_b = flow_dhq_id((u32)tgt, (u32)FLOW_DHQ_STRAND_B);
	if (!flow_dsq_ok(dsq_a) || !flow_dsq_ok(dsq_b))
		return (u64)FLOW_FALLBACK_DSQ;
	qa = scx_bpf_dsq_nr_queued(dsq_a);
	qb = scx_bpf_dsq_nr_queued(dsq_b);
	my = strand == (u32)FLOW_DHQ_STRAND_A ? (qa < 0 ? 0ULL : (u64)qa) : (qb < 0 ? 0ULL : (u64)qb);
	other = strand == (u32)FLOW_DHQ_STRAND_A ? (qb < 0 ? 0ULL : (u64)qb) : (qa < 0 ? 0ULL : (u64)qa);
	if (flow_dhq_over_imbalance(my, other))
		return (u64)FLOW_FALLBACK_DSQ;
	if (strand == (u32)FLOW_DHQ_STRAND_A)
		return dsq_a;
	return dsq_b;
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
static __always_inline bool flow_wait_hold(s32 tgt, struct task_struct *p)
{
	u32 cur;
	u32 key;
	struct flow_cpu_ctx *ac;
	struct flow_cpu_ctx *bc;
	struct flow_task_ctx *t;
	struct flow_lat_hist *h;
	u32 tgt_ccx;
	u32 cur_ccx;
	u32 kind;
	u64 base;
	u64 s0;
	u64 s1;
	u64 l6;
	u64 l7;
	if (!READ_ONCE(flow_wait_allow))
		return false;
	if (tgt < 0 || !p)
		return false;
	if (!flow_cpu_ok((u32)tgt))
		return false;
	cur = bpf_get_smp_processor_id();
	if (cur == (u32)tgt)
		return false;
	if (!flow_cpu_ok(cur))
		return false;
	key = (u32)tgt;
	ac = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!ac)
		return false;
	tgt_ccx = READ_ONCE(ac->ccx_id);
	key = cur;
	bc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (!bc)
		return false;
	cur_ccx = READ_ONCE(bc->ccx_id);
	if (tgt_ccx == cur_ccx)
		return false;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return false;
	kind = READ_ONCE(t->lat_kind);
	if (kind >= (u32)FLOW_LAT_KINDS)
		return false;
	key = (u32)tgt;
	h = bpf_map_lookup_elem(&lat_hist, &key);
	if (!h)
		return false;
	base = (u64)72 + (u64)kind * (u64)8;
	if (base + (u64)7 >= (u64)FLOW_HIST_LEN)
		return false;
	s0 = READ_ONCE(h->cells[base]);
	s1 = READ_ONCE(h->cells[base + 1]);
	l6 = READ_ONCE(h->cells[base + 6]);
	l7 = READ_ONCE(h->cells[base + 7]);
	if ((s0 || s1) && !l6 && !l7)
		return true;
	/* Longs suppress one hold then decay, so one old long never
	 * blocks holds forever. Holds count a skip for observability. */
	if (l6 || l7) {
		__sync_fetch_and_and(&h->cells[base], 0ULL);
		__sync_fetch_and_and(&h->cells[base + 1], 0ULL);
		__sync_fetch_and_and(&h->cells[base + 6], 0ULL);
		__sync_fetch_and_and(&h->cells[base + 7], 0ULL);
	}
	return false;
}
static __always_inline void flow_kick_checked(s32 tgt, struct task_struct *p, u32 llc)
{
	if (flow_wait_hold(tgt, p)) {
		flow_stat_inc(llc, 8);
		return;
	}
	flow_kick_idle_only(tgt, p, llc);
}
static __always_inline void flow_kick_lst(s32 tgt, struct task_struct *p, u32 llc, s64 new_slack)
{
	struct flow_running_state *rs;
	u64 rgen;
	u32 rllc;
	u32 last;
	s64 run_slack;
	s64 need;
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	if (tgt < 0 || !p || !flow_cpu_ok((u32)tgt) || !flow_cpu_allowed(tgt, p) ||
	    !flow_cpu_live((u32)tgt)) {
		flow_kick_checked(tgt, p, llc);
		return;
	}
	if (flow_wait_hold(tgt, p)) {
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
	run_slack = READ_ONCE(rs->slack);
	if (new_slack > vmax - (s64)FLOW_LST_PREEMPT_GAP_NS)
		need = vmax;
	else
		need = new_slack + (s64)FLOW_LST_PREEMPT_GAP_NS;
	if (need >= run_slack) {
		flow_stat_inc(llc, 8);
		return;
	}
	if (__sync_val_compare_and_swap(&rs->pad, last, (u32)rgen) != last) {
		flow_stat_inc(llc, 8);
		return;
	}
	scx_bpf_kick_cpu(tgt, SCX_KICK_PREEMPT);
	flow_stat_inc(llc, 6);
	flow_stat_inc(llc, 17);
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
	s64 new_slack = 0;
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
				flow_kick_checked(tgt, p, llc);
				return;
			}
			{
				u64 dsq = flow_enqueue_dhq_or_fallback(tgt, (u32)FLOW_DHQ_STRAND_B);
				if (!flow_dsq_ok(dsq))
					dsq = (u64)FLOW_FALLBACK_DSQ;
				if (dsq == (u64)FLOW_FALLBACK_DSQ)
					scx_bpf_dsq_insert(p, dsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
				else
					scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS, (u64)raw_v, enq_flags);
				flow_stat_inc(llc, 0);
				if (dsq == (u64)FLOW_FALLBACK_DSQ)
					flow_stat_inc(llc, 2);
				flow_kick_checked(tgt, p, llc);
				return;
			}
		}
		goto insert_only;
	}
	/* CREATE zero-inits new entries, so repair home to unset. A zero
	 * remain marks a fresh entry; running then records the first CPU
	 * instead of sticking to the zero CPU. */
	if (!READ_ONCE(t->remain_ns) && READ_ONCE(t->home_cpu) == 0)
		t->home_cpu = -1;
	/* Local placements run before ownership is taken. A task on a
	 * local queue is not counted in the shared gauge, so it leaves
	 * without the queued bit. Shared and fallback inserts take the
	 * bit below and count the gauge together. */
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			flow_lat_finalize(t, (u32)FLOW_LAT_EXITING, scx_bpf_now());
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_kick_checked(tgt, p, llc);
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
				flow_kick_checked(first, p, pllc);
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
		u64 dsq = flow_enqueue_dhq_or_fallback(tgt, (u32)FLOW_DHQ_STRAND_B);
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
		flow_kick_checked(tgt, p, llc);
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
		u64 rem = READ_ONCE(t->remain_ns);
		u64 dl = READ_ONCE(t->deadline_ns);
		s64 slack;
		bool over = false;
		if (!rem)
			rem = (u64)FLOW_LST_INIT_NS;
		rem = flow_lst_clamp_rem(rem);
		if (!dl) {
			dl = now + (u64)FLOW_LST_REL_NS;
			if (dl < now)
				dl = ~0ULL;
		} else if (now && dl <= now) {
			flow_stat_inc(llc, 18);
			flow_stat_inc(llc, 12);
			dl = now + (u64)FLOW_LST_REL_NS;
			if (dl < now)
				dl = ~0ULL;
			over = true;
		}
		slack = flow_lst_slack(dl, now, rem);
		prio = flow_lst_prio(slack);
		if (over)
			prio = (u32)FLOW_PRIO_LAT;
		if (!flow_prio_ok(prio))
			prio = (u32)FLOW_PRIO_NORM;
		t->remain_ns = rem;
		t->deadline_ns = dl;
		new_slack = slack;
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
		 * key and stay FIFO. Each owner queue holds at most two
		 * hundred fifty six tasks. */
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
	}
	{
		u64 dsq;
		u32 final_kind;
		u64 strand64;
		u32 strand;
		strand64 = flow_dhq_strand_for_prio(prio);
		strand = strand64 > (u64)FLOW_DHQ_STRAND_B ? (u32)FLOW_DHQ_STRAND_B : (u32)strand64;
		if (!flow_strand_ok(strand))
			strand = (u32)FLOW_DHQ_STRAND_B;
		if (no_cpu)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_enqueue_dhq_or_fallback(tgt, strand);
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
		flow_kick_lst(tgt, p, llc, new_slack);
		return;
	}
insert_only:
	{
		u64 dsq;
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		s64 k = raw_v;
		u32 strand = (u32)FLOW_DHQ_STRAND_B;
		if (no_cpu)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_enqueue_dhq_or_fallback(tgt, strand);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			scx_bpf_dsq_insert(p, dsq, sl, enq_flags);
		else
			scx_bpf_dsq_insert_vtime(p, dsq, sl, (u64)k, enq_flags);
		flow_stat_inc(llc, 0);
		if (dsq == (u64)FLOW_FALLBACK_DSQ)
			flow_stat_inc(llc, 2);
		flow_kick_checked(tgt, p, llc);
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
