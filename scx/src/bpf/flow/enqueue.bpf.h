// SPDX-License-Identifier: GPL-2.0
/*
 * Flow enqueue.
 *
 * Tasks enter the LLC queue of the constrained target in virtual
 * time order, or the fallback queue when no target exists. Pinned
 * tasks enter the local queue of the allowed CPU in FIFO order.
 * Stored time stays raw while latency tasks take a one slice queue
 * key shift. A requeued task carries its remaining slice with a
 * weight scaled charge, else a fresh time steps past the per LLC
 * floor. A full burn postpones the task by the award length with
 * saturation. One kick per enqueue keeps wakes bounded.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "vtime.bpf.h"
#include "cgroup.bpf.h"
#include "freq.bpf.h"
#include "preempt.bpf.h"

/**
 * flow_seq_floor - lift a time past the per LLC floor.
 * @llc: LLC index.
 * @v: candidate time.
 *
 * Steps to one past the floor when the candidate does not lead it,
 * saturating at the maximum. Records the result as the new floor.
 *
 * Returns: the floored time.
 */
static __always_inline s64 flow_seq_floor(u32 llc, s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	s64 last;
	if (!flow_llc_ok(llc))
		return v;
	last = flow_llc_seq[llc];
	if (v <= last) {
		if (last == vmax)
			v = last;
		else
			v = last + 1;
	}
	flow_llc_seq[llc] = v;
	return v;
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (!p)
		return;
	s32 task_cpu = scx_bpf_task_cpu(p);
	s32 tgt;
	u32 cpu;
	u32 llc = 0;
	s64 kv;
	s64 use_v;
	s64 use_d;
	s64 key_v;
	int is_lat = 0;
	u64 use_sl;
	u32 use_llc;
	u32 w;
	int carry = 0;
	bool pinned = false;
	u64 extra_q = 1;
	struct flow_task_ctx *t;
	u32 old_flags;
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	/* One target drives the insert and the kick. The hint wins */
	/* when allowed and live, else the first allowed live CPU wins. */
	/* Minus one means no target, queued to fallback with no wake. */
	tgt = flow_constrained_target(task_cpu, p);
	if (tgt >= 0 && flow_cpu_live((u32)tgt)) {
		struct flow_cpu_ctx *cc;
		u32 key = (u32)tgt;
		cpu = (u32)tgt;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cc) {
			u32 tmp = READ_ONCE(cc->llc_id);
			if (flow_llc_ok(tmp))
				llc = tmp;
		}
	} else {
		cpu = (u32)FLOW_MAX_CPUS;
	}
	kv = (s64)p->scx.dsq_vtime;
	use_v = kv;
	use_d = flow_vtime_add_slice(kv);
	use_sl = (u64)FLOW_SLICE_NS;
	use_llc = llc;
	/* Default to the raw key so the context-less path below */
	/* cannot queue stack garbage. */
	key_v = use_v;
	pinned = flow_is_pinned(p);
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		/* No context means no duplicate state exists, so the */
		/* insert below cannot double queue. Exiting tasks */
		/* still need a queue: local when allowed, else the LLC */
		/* queue with a minimal slice. */
		if (p->flags & PF_EXITING) {
			if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS,
						 enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
			{
				u64 dsq;

				if (tgt < 0)
					dsq = (u64)FLOW_FALLBACK_DSQ;
				else
					dsq = flow_llc_dsq(llc);
				if (!flow_dsq_ok(dsq))
					dsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, dsq,
							 (u64)FLOW_EXIT_SLICE_NS,
							 (u64)kv, enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(tgt, p, llc);
				return;
			}
		}
		goto insert_only;
	}
	old_flags = __sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_QUEUED);
	if (old_flags & (u32)FLOW_FLAG_QUEUED) {
		flow_fb_inc(llc, 4);
		return;
	}
	/* Exiting tasks hold single ownership through the guard above. */
	/* A task already queued keeps its first entry. Local queuing */
	/* uses FIFO, shared queuing keeps time order. Enqueue keeps */
	/* caller flags with an idle kick only. A missing local target */
	/* falls back to the LLC queue so the wakeup always queues. */
	if (p->flags & PF_EXITING) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
		{
			u64 dsq;

			if (tgt < 0)
				dsq = (u64)FLOW_FALLBACK_DSQ;
			else
				dsq = flow_llc_dsq(llc);
			if (!flow_dsq_ok(dsq))
				dsq = (u64)FLOW_FALLBACK_DSQ;
			scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS,
						 (u64)kv, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(tgt, p, llc);
			return;
		}
	}
	/* Weight shares start here. Pinned and exiting paths above */
	/* never scale. Charge and fresh times below scale the virtual */
	/* time step by cpu.weight while the slice stays fixed. Default */
	/* weight is identity. The live map read heals a reversed start */
	/* on the next enqueue. A miss reads as default. */
	w = flow_cgroup_lookup(t->cgrp_id);
	if (t->gen != 0 &&
	 flow_llc_ok(t->llc_id) &&
	 t->deadline == flow_vtime_add_slice(t->vtime)) {
		if (flow_cpu_live(cpu)) {
			struct flow_running_state *rs = &flow_running_state[cpu];
			if (rs->gen != 0 && rs->gen == t->gen &&
			 flow_llc_ok(rs->llc_id)) {
				s64 charged;
				u64 used;
				u64 rem = t->slice_rem;
				u64 rem_raw = rem;
				if (rem > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
					rem = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
				{
					u64 rem_c = rem;
					if (rem_c > (u64)FLOW_SLICE_NS)
						rem_c = (u64)FLOW_SLICE_NS;
					if ((u64)FLOW_SLICE_NS >= rem_c)
						used = (u64)FLOW_SLICE_NS - rem_c;
					else
						used = 0;
				}
				if (used > (u64)FLOW_SLICE_NS)
					used = (u64)FLOW_SLICE_NS;
				/* Heavier tasks pay less time for the same */
				/* burnt slice. The extra slice below never */
				/* scales by weight and only sets run length. */
				charged = flow_cgroup_charge(t->vtime, used, w);
				/* A full burn postpones the task so the head */
				/* keeps moving. The postponed time steps behind */
				/* the floor while idle CPUs reclaim the wait. */
				if (rem_raw == 0 && !pinned) {
					u64 score = 0;
					u64 prev = 0;
					u64 ex = 0;
					u64 q = 1;
					charged = flow_vtime_add_penalty(charged);
					flow_stat_inc(llc, 9);
					flow_stat_inc(llc, 10);
					if (flow_cpu_ok(cpu)) {
						struct flow_extra_state *es = &flow_extra_state[cpu];
						u64 st = es->score;
						/* Fresh reads zero with one */
						/* quantum until the first count, */
						/* since no burn has been seen. */
						if (es->n_growth == 0 && es->n_decay == 0) {
							st = 0;
						} else if (st > (u64)FLOW_SCORE_HMAX) {
							st = (u64)FLOW_SCORE_HMAX;
						}
						score = st;
						/* The hold travels in the task */
						/* pad across migration while the */
						/* score stays per CPU. */
						if (t->pad[1] <= (u8)2)
							prev = (u64)t->pad[1];
						else
							prev = 0;
						ex = flow_score_extra(st, prev);
						q = flow_score_quanta(ex);
						if (q < 1ULL)
							q = 1ULL;
						if (q > (u64)FLOW_MAX_QUANTA)
							q = (u64)FLOW_MAX_QUANTA;
						if (ex > (u64)FLOW_MAX_EXTRA)
							ex = (u64)FLOW_MAX_EXTRA;
						/* The debt totals q slices with */
						/* saturation, so a long burn pays */
						/* its full length. */
						if (ex >= 1ULL)
							charged = flow_vtime_add_penalty(charged);
						if (ex >= 2ULL)
							charged = flow_vtime_add_penalty(charged);
					} else {
						if (t->pad[1] <= (u8)2)
							prev = (u64)t->pad[1];
						else
							prev = 0;
						score = 0;
						ex = flow_score_extra(score, prev);
						q = flow_score_quanta(ex);
						if (q < 1ULL)
							q = 1ULL;
						if (q > (u64)FLOW_MAX_QUANTA)
							q = (u64)FLOW_MAX_QUANTA;
						if (ex > (u64)FLOW_MAX_EXTRA)
							ex = (u64)FLOW_MAX_EXTRA;
						if (ex >= 1ULL)
							charged = flow_vtime_add_penalty(charged);
						if (ex >= 2ULL)
							charged = flow_vtime_add_penalty(charged);
					}
					extra_q = q;
					t->pad[0] = (u8)q;
					t->pad[1] = (u8)ex;
					/* Extra takes q minus one, total takes */
					/* q, so total meets penalty plus extra */
					/* on each award and on deltas. */
					flow_stat_add(llc, 19, ex);
					flow_stat_add(llc, 20, q);
				} else {
					/* A clean stop keeps one quantum. */
					/* The pad holds the slice length while */
					/* the hold level rides along. */
					t->pad[0] = 1;
				}
				charged = flow_seq_floor(llc, charged);
				carry = 1;
				use_v = charged;
				use_d = flow_vtime_add_slice(charged);
				/* Zero remain on overrun refreshes at running */
				/* time from the kernel slice. */
				use_sl = rem;
				use_llc = t->llc_id;
			}
		}
	}
	/* A pinned carry follows the current LLC so later accounting */
	/* lands on the queue it waits in. Its time never orders shared */
	/* queues. */
	if (pinned)
		use_llc = llc;
	if (!carry) {
		s64 last;
		s64 fresh;
		if (!flow_llc_ok(llc))
			llc = 0;
		last = flow_llc_seq[llc];
		/* Fresh times step past the floor with a weight scaled */
		/* gap, so heavy tasks start nearer and light tasks start */
		/* farther. A truncated gap steps to one past the floor. */
		/* The slice never scales. */
		if (kv > last) {
			fresh = flow_cgroup_charge(last, (u64)(kv - last), w);
			if (fresh <= last)
				fresh = flow_seq_floor(llc, last);
			else
				fresh = flow_seq_floor(llc, fresh);
		} else {
			fresh = flow_seq_floor(llc, last);
		}
		use_v = fresh;
		use_d = flow_vtime_add_slice(fresh);
		use_sl = (u64)FLOW_SLICE_NS;
		use_llc = llc;
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->llc_id = use_llc;
		t->gen = 0;
		/* Fresh keeps one quantum with the hold level intact. */
		t->pad[0] = 1;
	} else {
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->llc_id = use_llc;
	}
	/* The stamp holds the wait start with no time shift. Running */
	/* treats zero as no age out. */
	{
		u64 now = bpf_ktime_get_ns();

		t->enq_ns = now;
	}
	/* Stored time stays raw and only the key takes the latency */
	/* shift. Pinned and exiting tasks keep the raw key with no */
	/* count. The shift applies once since stored time stays raw. */
	is_lat = 0;
	key_v = use_v;
	if (t && !pinned)
		is_lat = flow_hist_is_lat(t->hist3) ? 1 : 0;
	key_v = flow_vtime_boost(use_v, is_lat);
	if (t && !pinned) {
		if (is_lat)
			flow_stat_inc(llc, 15);
		else
			flow_stat_inc(llc, 16);
	}
	scx_bpf_task_set_dsq_vtime(p, (u64)key_v);
insert_only:
	/* Pinned tasks wait in the local queue of the allowed CPU, */
	/* out of shared queues so no other CPU can take them off */
	/* mask. The fallback covers a missing local target. Without */
	/* context the wake stays idle only with no preempt. With */
	/* context the pinned fast path ends a hold with no move. */
	if (pinned) {
		if (tgt >= 0 && flow_cpu_allowed(tgt, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)tgt;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			if (!t)
				flow_kick_idle_only(tgt, p, llc);
			else
				flow_kick_pinned(tgt, use_v, p, llc);
			return;
		}
	}
	/* Shared tasks join the LLC queue in time order with a slice */
	/* of one quantum times q and no weight scale on the extra */
	/* part. Pinned tasks keep one slice with no award. */
	{
		u64 dsq;
		u64 sl = (u64)FLOW_SLICE_NS * extra_q;

		if (extra_q < 1ULL || extra_q > (u64)FLOW_MAX_QUANTA)
			sl = (u64)FLOW_SLICE_NS;
		if (tgt < 0)
			dsq = (u64)FLOW_FALLBACK_DSQ;
		else
			dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, sl, (u64)key_v, enq_flags);
		flow_stat_inc(llc, 0);
	}
	/* One kick per enqueue. A preempt won by a latency task counts */
	/* the latency win with the class already in hand. */
	if (!t)
		flow_kick_idle_only(tgt, p, llc);
	else if (flow_kick_constrained(tgt, key_v, p, llc) && is_lat)
		flow_stat_inc(llc, 17);
}

#endif
