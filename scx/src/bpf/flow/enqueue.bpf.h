// SPDX-License-Identifier: GPL-2.0
/*
 * Flow enqueue with steal-outcome split.
 *
 * Moved from main with the enqueue LLC passed to kick helpers for
 * per LLC 11 plus 12 plus 13 counting. Predicates plus vtime carry
 * plus pair insert plus LLC spill plus occupancy are unchanged.
 * Carry plus fresh vtime increments scale by cpu.weight with slice
 * never scaled and default 100 as exact identity. Pinned plus exiting
 * paths stay byte-identical. Single ownership through the queued flag
 * is unchanged with no loss.
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
#include "preempt.bpf.h"

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	TOUCH_ARENA();
	if (!p)
		return;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	u32 llc = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	s64 kv;
	s64 use_v;
	s64 use_d;
	u64 use_sl;
	u32 use_strand;
	u32 use_llc;
	u32 w;
	int carry = 0;
	u32 pair_u = 0;
	int have_pair = 0;
	bool pinned = false;
	struct flow_task_ctx *t;
	scx_dhq_t *dhq = NULL;
	int ret;
	u32 old_flags;
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	if (p->cpus_ptr && !flow_cpu_allowed(task_cpu, p)) {
		u32 first = bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(first))
			task_cpu = (s32)first;
	}
	cpu = (u32)task_cpu;
	if (flow_cpu_ok(cpu)) {
		struct flow_cpu_ctx *cc;
		u32 key = cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cc && flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
	}
	kv = (s64)p->scx.dsq_vtime;
	use_v = kv;
	use_d = flow_vtime_add_slice(kv);
	use_sl = (u64)FLOW_SLICE_NS;
	use_strand = strand;
	use_llc = llc;
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
		/* No context means no duplicate state exists. Exiting */
		/* without context still needs no loss, so try local */
		/* then fall back to the LLC queue with a minimal slice. */
		if (p->flags & PF_EXITING) {
			if (task_cpu >= 0 && flow_cpu_ok((u32)task_cpu) &&
			 flow_cpu_allowed(task_cpu, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS,
						 enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(task_cpu, p, llc);
				return;
			}
			{
				u64 dsq = flow_llc_dsq(llc);
				if (!flow_dsq_ok(dsq))
					dsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, dsq,
							 (u64)FLOW_EXIT_SLICE_NS,
							 (u64)kv, enq_flags);
				flow_stat_inc(llc, 0);
				flow_kick_idle_only(task_cpu, p, llc);
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
		if (task_cpu >= 0 && flow_cpu_ok((u32)task_cpu) &&
		 flow_cpu_allowed(task_cpu, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(task_cpu, p, llc);
			return;
		}
		{
			u64 dsq = flow_llc_dsq(llc);
			if (!flow_dsq_ok(dsq))
				dsq = (u64)FLOW_FALLBACK_DSQ;
			scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_EXIT_SLICE_NS,
						 (u64)kv, enq_flags);
			flow_stat_inc(llc, 0);
			flow_kick_idle_only(task_cpu, p, llc);
			return;
		}
	}
	/* Weight shares start here. Pinned plus exiting above never scale */
	/* and stay byte-identical. Charge plus fresh below scale the vtime */
	/* increment by cpu.weight while seq plus publish plus insert plus */
	/* kick stay unchanged. Slice never scales. Default weight 100 is */
	/* exact identity with 5.0.8. Live lookup by id keeps a plain echo */
	/* weight effective on next enqueue with no move needed. Miss reads */
	/* as default and fails open. */
	w = flow_cgroup_lookup(t->cgrp_id);
	if (t->gen != 0 &&
	 (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B) &&
	 flow_llc_ok(t->llc_id) &&
	 t->deadline == flow_vtime_add_slice(t->vtime)) {
		if (flow_cpu_ok(cpu)) {
			struct flow_running_state *rs = &flow_running_state[cpu];
			if (rs->gen != 0 && rs->gen == t->gen &&
			 flow_llc_ok(rs->llc_id) &&
			 (rs->strand == (u32)FLOW_STRAND_A ||
			 rs->strand == (u32)FLOW_STRAND_B)) {
				s64 charged;
				u64 used;
				u64 rem = t->slice_rem;
				if (rem > (u64)FLOW_SLICE_NS)
					rem = (u64)FLOW_SLICE_NS;
				if ((u64)FLOW_SLICE_NS >= rem)
					used = (u64)FLOW_SLICE_NS - rem;
				else
					used = 0;
				if (used > (u64)FLOW_SLICE_NS)
					used = (u64)FLOW_SLICE_NS;
				/* Scaled charge. Heavier pays less vtime for */
				/* the same burnt slice. Saturation plus the */
				/* monotonic floor below are unchanged. */
				charged = flow_cgroup_charge(t->vtime, used, w);
				if (have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
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
				use_sl = rem;
				use_strand = t->strand;
				use_llc = t->llc_id;
			}
		}
	}
	/* Pinned carry keeps vtime plus slice but follows the current LLC. */
	/* This keeps the task context aligned with the queue it waits in */
	/* so later victim accounting stays on the enqueue LLC. */
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
	} else {
		t->vtime = use_v;
		t->deadline = use_d;
		t->slice_rem = use_sl;
		t->strand = use_strand;
		t->llc_id = use_llc;
	}
	scx_bpf_task_set_dsq_vtime(p, (u64)use_v);
insert_only:
	/* Pinned tasks wait in the local queue of the allowed CPU only. */
	/* This keeps them out of shared LLC queues so no other CPU can */
	/* steal them off mask. Falls through to the LLC queue only when */
	/* no allowed local target exists as safety against loss. */
	if (pinned) {
		if (task_cpu >= 0 && flow_cpu_allowed(task_cpu, p)) {
			u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)task_cpu;
			scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_SLICE_NS, enq_flags);
			flow_stat_inc(llc, 0);
			if (!t)
				flow_kick_idle_only(task_cpu, p, llc);
			else
				flow_kick_for_enq(task_cpu, use_v, p, llc);
			return;
		}
	}
	if (dhq) {
		ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)use_v,
					 (u64)use_strand);
		if (ret == 0) {
			u64 cap = 0;
			if (pair_u < (u32)FLOW_MAX_PAIRS)
				cap = flow_pair_cap[pair_u];
			flow_stat_inc(llc, 0);
			flow_occupancy_set(llc, dhq, cap);
			if (!t)
				flow_kick_idle_only(task_cpu, p, llc);
			else
				flow_kick_for_enq(task_cpu, use_v, p, llc);
			return;
		}
		/* Pair full. Count the spill to the LLC queue in the */
		/* aggregate plus the pair-full tail. Occupancy keeps the */
		/* full depth for sizing. This counter is separate from */
		/* the fallback DSQ. */
		{
			u64 cap = 0;
			if (pair_u < (u32)FLOW_MAX_PAIRS)
				cap = flow_pair_cap[pair_u];
			flow_fb_inc(llc, 4);
			flow_occupancy_set(llc, dhq, cap);
		}
	}
	{
		u64 dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, (u64)use_v, enq_flags);
		flow_stat_inc(llc, 0);
		if (!t)
			flow_kick_idle_only(task_cpu, p, llc);
		else
			flow_kick_for_enq(task_cpu, use_v, p, llc);
	}
}

#endif
