// SPDX-License-Identifier: GPL-2.0
/*
 * Flow enqueue with steal-outcome split.
 *
 * Moved from main with the enqueue LLC passed to kick helpers for
 * per LLC 11 plus 12 plus 13 plus 17 counting. Predicates plus vtime
 * carry plus pair insert plus LLC spill plus occupancy are unchanged.
 * Carry plus fresh vtime increments scale by cpu.weight with slice
 * never scaled and default 100 as exact identity. Non pinned carry
 * with no remain adds one extra fixed uniform slice with saturation
 * and counts overrun plus penalty on the enqueue LLC, which moves a
 * full burn hog behind the pair sequence and behind LLC order so the
 * head keeps moving. Pinned carry skips the penalty and stays at the
 * scaled charge with prior behavior while exiting bypasses through
 * the early returns above, and pinned placement stays local FIFO so
 * its vtime never orders shared queues. Pinned local wakes through the
 * pinned fast path with streak cover. Enqueue time stamps the wait with
 * the monotonic clock with a zero clock clearing to unknown and never
 * shifts vtime. Latency class comes from the three bit task history
 * with two of three early yields reading as latency else a hog, fresh
 * zero neutral as a hog, pinned plus exiting bypassing with prior
 * behavior. The queue key subtracts one fixed slice for latency tasks
 * only one shot with no accumulation while stored time plus deadline
 * stay raw, so the offset never compounds. Only the insert key plus the
 * kick compare use the offset key, and the stamp never shifts with the
 * offset. Latency enqueues count the boost tail while hog enqueues
 * count the hold tail on the enqueue LLC. Single ownership through
 * the queued flag is unchanged with no loss.
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

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	TOUCH_ARENA();
	if (!p)
		return;
	s32 task_cpu = scx_bpf_task_cpu(p);
	s32 tgt;
	u32 cpu;
	u32 llc = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	s64 kv;
	s64 use_v;
	s64 use_d;
	s64 key_v;
	int is_lat = 0;
	u64 use_sl;
	u32 use_strand;
	u32 use_llc;
	u32 w;
	int carry = 0;
	u32 pair_u = 0;
	int have_pair = 0;
	bool pinned = false;
	u64 extra_q = 1;
	struct flow_task_ctx *t;
	scx_dhq_t *dhq = NULL;
	int ret;
	u32 old_flags;
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	/* Single constrained target drives inserts plus kicks. Keeps the */
	/* hint when allowed and live, else falls back to the first live CPU. */
	/* Fails closed to minus one with no move when no target exists. */
	/* No live target queues to the fallback safety net with no wake. */
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
	use_strand = strand;
	use_llc = llc;
	/* Fail closed to raw. No context below jumps to insert only */
	/* with the hog key, so shared queues never take stack garbage. */
	key_v = use_v;
	pinned = flow_is_pinned(p);
	if (pinned) {
		dhq = NULL;
		have_pair = 0;
	} else if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)SCX_DHQ_STRAND_A &&
			 strand != (u32)SCX_DHQ_STRAND_B)
				strand = (u32)SCX_DHQ_STRAND_A;
			use_strand = strand;
			pair_u = (u32)idx;
			have_pair = 1;
		}
	}
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t) {
		/* No context means no duplicate state exists, so the queued */
		/* guard has nothing to check and the insert below cannot */
		/* double queue. Exiting without context still needs no loss, */
		/* so try local then fall back to the LLC queue with a minimal */
		/* slice. A later enqueue creates storage with no stale hold. */
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
		flow_fb_inc(llc, 5);
		return;
	}
	/* Exiting keeps single ownership through the queued guard above. */
	/* A task already queued keeps its first entry and this requeue */
	/* drops as duplicate, so no second local queue forms. Pair plus */
	/* sequence are skipped. Local uses FIFO, shared fallback keeps */
	/* vtime order. Enqueue keeps caller flags, dispatch synthesizes */
	/* zero, same split as the normal path. Idle kick only. */
	/* No drop exists. A missing local target falls back to LLC so an */
	/* exiting wakeup always queues. Bound check is best effort. */
	/* Hotplug needs restart, same risk as the pinned path. */
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
	/* Weight shares start here. Pinned plus exiting above never scale */
	/* and stay byte-identical. Charge plus fresh below scale the vtime */
	/* increment by cpu.weight while seq plus publish plus insert plus */
	/* kick stay unchanged. Slice never scales. Default weight 100 is */
	/* exact identity with prior behavior. Live lookup by id keeps a plain echo */
	/* weight effective on next enqueue with no move needed. Miss reads */
	/* as default and fails open. */
	w = flow_cgroup_lookup(t->cgrp_id);
	if (t->gen != 0 &&
	 (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B) &&
	 flow_llc_ok(t->llc_id) &&
	 t->deadline == flow_vtime_add_slice(t->vtime)) {
		if (flow_cpu_live(cpu)) {
			struct flow_running_state *rs = &flow_running_state[cpu];
			if (rs->gen != 0 && rs->gen == t->gen &&
			 flow_llc_ok(rs->llc_id) &&
			 (rs->strand == (u32)FLOW_STRAND_A ||
			 rs->strand == (u32)FLOW_STRAND_B)) {
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
				/* Scaled charge. Heavier pays less vtime for */
				/* the same burnt slice. Saturation plus the */
				/* monotonic floor below are unchanged. Extra */
				/* slice never scales by weight and never moves */
				/* order, only run length once picked. */
				charged = flow_cgroup_charge(t->vtime, used, w);
				/* Overrun postponement. No remain means the full */
				/* slice burnt, so add one extra fixed uniform slice */
				/* with saturation to move the hog behind the head. */
				/* Uniform keeps one quantum for every weight with no */
				/* new knob: the base charge already scales by weight, */
				/* so a heavy hog pays a large relative penalty that */
				/* breaks its head hold while a light hog already pays */
				/* a large base charge and still steps behind. Counts */
				/* overrun plus penalty one to one on the enqueue LLC */
				/* by design, event versus slices charged. Saturated at */
				/* max the vtime stays capped while the count still */
				/* grows for visibility. Pinned skips the penalty and */
				/* stays at the scaled charge, exiting never reaches */
				/* here through the early returns above. Extra award */
				/* shares this carry with no remain on non pinned */
				/* alongside fifteen with no fast path for pinned. */
				/* Order stays strict priority lowest boosted time */
				/* with ties to strand A. Score plus hold give q of */
				/* one plus extra with top first then middle then zero. */
				/* Debt scales with q: one uniform slice now plus ex */
				/* more below for a total of q, so a three quantum */
				/* burn pays three slices and cannot hold the head */
				/* three times longer on one slice of debt. Each add */
				/* saturates at max with no wrap and no knob. Counters */
				/* keep event versus extra split with fifteen at one */
				/* per overrun plus twenty four at ex plus twenty five */
				/* at q, so total still equals fifteen plus twenty */
				/* four per award and on deltas. Streak escape still */
				/* bounds the hold at the pop retry bound with clean */
				/* decay, gap plus tail unchanged, tick keeps no */
				/* preempt. Full soak gates stay OPEN deferred live */
				/* with no live run here, weight fairness holds since */
				/* base scales while extra stays uniform. */
				if (rem_raw == 0 && !pinned) {
					u64 score = 0;
					u64 prev = 0;
					u64 ex = 0;
					u64 q = 1;
					charged = flow_vtime_add_penalty(charged);
					flow_stat_inc(llc, 14);
					flow_stat_inc(llc, 15);
					if (flow_cpu_ok(cpu)) {
						struct flow_extra_state *es = &flow_extra_state[cpu];
						u64 st = es->score;
						/* Fresh reads zero with q one until the */
						/* first count, amended from the prior */
						/* middle default with no burn seen yet. */
						if (es->n_growth == 0 && es->n_decay == 0) {
							st = 0;
						} else if (st > (u64)FLOW_SCORE_HMAX) {
							st = (u64)FLOW_SCORE_HMAX;
						}
						score = st;
						/* Hold is single sourced from the task */
						/* pad so the sticky travels with the */
						/* task on migration while score stays */
						/* per CPU with no cross average. The */
						/* per CPU hold row stays as shadow for */
						/* the future per award log and never */
						/* feeds the award here. */
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
						/* Scale the debt with the award. */
						/* Total penalty is q with saturation */
						/* and no knob, so the hold cannot */
						/* triple on one slice of debt. */
						if (ex >= 1ULL)
							charged = flow_vtime_add_penalty(charged);
						if (ex >= 2ULL)
							charged = flow_vtime_add_penalty(charged);
					} else {
						/* Invalid CPU fallback keeps a fresh */
						/* zero default with no award and */
						/* bounded debt, documented. */
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
					/* Per award books with score plus hold plus q. */
					/* Twenty four takes q minus one as extra, twenty */
					/* five takes q as total, so total equals old */
					/* penalty plus new extra per award and again on */
					/* deltas with one addition. Score stays live in */
					/* the per CPU row, hold plus q stay live in the */
					/* task pad for the future per award log with no */
					/* second path. Per CPU prev stays reserved zero. */
					flow_stat_add(llc, 24, ex);
					flow_stat_add(llc, 25, q);
				} else {
					/* Non overrun keeps one quantum. Pad zero */
					/* holds the current slice with no award */
					/* while pad one keeps the sticky hold for */
					/* the next award, so a stale three never */
					/* steps the hold by three nor splits pair */
					/* three against DSQ one. Steal stays */
					/* untouched with no placement shift. */
					t->pad[0] = 1;
				}
				if (have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
					/* Pair only floor. LLC order uses the vtime */
					/* directly with no sequence, so this last plus */
					/* one step keeps only the pair unique. */
					s64 last = flow_dhq_seq[pair_u];
					if (charged <= last) {
						if (last == (s64)0x7fffffffffffffffLL)
							charged = last;
						else
							charged = last + 1;
					}
					flow_dhq_seq[pair_u] = charged;
				}
				carry = 1;
				use_v = charged;
				use_d = flow_vtime_add_slice(charged);
				/* Transient remain. Zero on overrun refreshes at */
				/* running time from the kernel slice, so no stuck */
				/* zero persists past the next run. */
				use_sl = rem;
				use_strand = t->strand;
				use_llc = t->llc_id;
			}
		}
	}
	/* Pinned carry keeps vtime plus slice but follows the current LLC. */
	/* This keeps the task context aligned with the queue it waits in */
	/* so later victim accounting stays on the enqueue LLC. Counters */
	/* always use the enqueue LLC above, never the cached id, so thief */
	/* versus victim attribution stays explicit. Pinned placement below */
	/* stays local FIFO, so its vtime never orders shared queues and the */
	/* skip above only keeps its future charge with no order effect. */
	if (pinned)
		use_llc = llc;
	if (!carry) {
		if (dhq && have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
			s64 last = flow_dhq_seq[pair_u];
			s64 fresh;
			/* Scaled fresh. Gap from the pair sequence pays */
			/* by weight, so heavy starts nearer last while */
			/* light starts farther. Tiny gaps can truncate to */
			/* zero at heavy weights, so a scaled result at or */
			/* below last steps to last plus one with max */
			/* saturation, so sequence stays unique. Slice */
			/* never scales. */
			if (kv > last) {
				fresh = flow_cgroup_charge(last, (u64)(kv - last), w);
				if (fresh <= last) {
					if (last == (s64)0x7fffffffffffffffLL)
						fresh = last;
					else
						fresh = last + 1;
				}
			} else if (last == (s64)0x7fffffffffffffffLL)
				fresh = last;
			else
				fresh = last + 1;
			flow_dhq_seq[pair_u] = fresh;
			use_v = fresh;
			use_d = flow_vtime_add_slice(fresh);
			use_sl = (u64)FLOW_SLICE_NS;
			use_strand = strand;
			use_llc = llc;
		} else {
			use_v = kv;
			use_d = flow_vtime_add_slice(kv);
			use_sl = (u64)FLOW_SLICE_NS;
			use_strand = strand;
			use_llc = llc;
		}
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->strand = use_strand;
		t->llc_id = use_llc;
		t->gen = 0;
		/* Fresh keeps one quantum with sticky hold. Same split */
		/* fix as the carry non overrun above with no award. */
		t->pad[0] = 1;
	} else {
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->strand = use_strand;
		t->llc_id = use_llc;
	}
	/* Enqueue stamp. Holds the wait start with no vtime shift. Zero */
	/* clock clears to unknown so a bad read never keeps a stale wait. */
	/* Running treats zero as no decay with no false age out. */
	{
		u64 now = bpf_ktime_get_ns();

		t->enq_ns = now;
	}
	/* Latency key. Fresh plus carry above stay raw in stored time plus */
	/* deadline, and only this key takes the one slice offset for */
	/* latency tasks. Pinned plus exiting bypass with the raw key and */
	/* no count, and no context stays a hog with no count. One shot */
	/* with no accumulation since stored time stays raw. */
	is_lat = 0;
	key_v = use_v;
	if (t && !pinned)
		is_lat = flow_hist_is_lat(t->hist3) ? 1 : 0;
	key_v = flow_vtime_boost(use_v, is_lat);
	if (t && !pinned) {
		if (is_lat)
			flow_stat_inc(llc, 20);
		else
			flow_stat_inc(llc, 21);
	}
	scx_bpf_task_set_dsq_vtime(p, (u64)key_v);
insert_only:
	/* Pinned tasks wait in the local queue of the allowed CPU only. */
	/* This keeps them out of shared LLC queues so no other CPU can */
	/* steal them off mask. Falls through to the LLC queue only when */
	/* no allowed local target exists as safety against loss. */
	/* The single constrained target drives the local insert plus the */
	/* shared fallback kick with no stale split, so one mask walk serves */
	/* inserts plus kicks. Without context the kick stays idle only with */
	/* no preempt so the wake stays cheap with no running state lookup. */
	/* With context the pinned local wake uses the pinned fast path with */
	/* streak cover so a hold ends with no move. */
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
	if (dhq && tgt >= 0) {
		int queued_pair = 0;
		ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)key_v,
					 (u64)use_strand);
		if (ret == 0) {
			u64 cap = 0;
			if (pair_u < (u32)FLOW_MAX_PAIRS)
				cap = flow_pair_cap[pair_u];
			flow_stat_inc(llc, 0);
			flow_occupancy_set(llc, dhq, cap);
			queued_pair = 1;
		} else {
			/* Pair full. Count the spill to the LLC queue in */
			/* the aggregate plus the pair-full tail. Occupancy */
			/* keeps the full depth for sizing. This counter is */
			/* separate from the fallback DSQ. */
			u64 cap = 0;
			if (pair_u < (u32)FLOW_MAX_PAIRS)
				cap = flow_pair_cap[pair_u];
			flow_fb_inc(llc, 4);
			flow_occupancy_set(llc, dhq, cap);
		}
		if (queued_pair)
			goto do_kick;
	}
	/* Fallback safety net charges queued to the enqueue LLC, zero when */
	/* no live target exists. Dispatch takes a best effort dec from a */
	/* victim with backlog so the total stays close with no loss. The */
	/* fallback DSQ has no per queue stats, so the enqueue LLC carries */
	/* the queued count and the dispatch LLC carries the dispatched count. */
	/* Awarded tasks run one slice times q with no other scale and no */
	/* weight scale on the extra part. Pinned keeps one slice with no */
	/* award. Order stays strict priority with no vtime shift for extra. */
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
do_kick:
	/* One kick per enqueue keeps no storm. Pair success plus spill */
	/* plus fallback share this single wake with the same target plus */
	/* key, so the order above never doubles a wake. A preempt won by a */
	/* latency task counts the latency preempt tail on the enqueue LLC */
	/* with the class already in hand and no extra lookup. Forward plus */
	/* steal wins keep the preempt count with no latency split. */
	if (!t)
		flow_kick_idle_only(tgt, p, llc);
	else if (flow_kick_constrained(tgt, key_v, p, llc) && is_lat)
		flow_stat_inc(llc, 22);
}

/* Enqueue vtime budgets stay fixed slice 1ms times q plus preempt */
/* threshold 500us plus tail 125us plus latency offset 1ms, weight scaling */
/* saturates with last plus one floor on the pair path only, pinned skips */
/* the penalty plus the offset plus the award while exiting bypasses */
/* through early returns. Extra changes run length only with no order */
/* shift and no weight scale on the extra part. */
/* Docs only, no logic change. */

#endif
