// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Shared tasks join the queue of the constrained target in deadline order.
 * The upstream queue keeps insertion order for equal deadlines, so the code
 * adds no extra tie handling. Pinned tasks join the local queue in order
 * with a single slice. Exiting tasks use the local queue when allowed and
 * the owner queue otherwise with a short slice. Tasks that have no usable
 * CPU join the fallback queue in FIFO order. The queue key is the floored
 * virtual deadline saturated to unsigned with negatives at zero. Shared
 * inserts move past the per LLC floor and add the burst scaled effective
 * step to the floored time through the shared charge path. Tasks with
 * no usable CPU skip the floor and stay FIFO. The charge scales with
 * the effective weight. Each shared enqueue checks the idle flag first, then the
 * running deadline on the target for an earlier deadline win. Idle targets take
 * an idle wake and running targets keep running unless the guarded win
 * fires. Each running instance kicks at most once.
 * A deadline win preempts on a guarded win, else it counts a skip with no wake. A wake goes only to an idle target, else it counts a
 * skip with no wake. The kernel idle flag decides the idle wake.
 * Wakes stay in the same LLC with an allowed live target. Local
 * inserts are not counted in the shared gauge. Shared and fallback
 * inserts count the gauge, and fallback inserts also count fallback.
 * Dequeue drops the gauge on cancel. Masks
 * are checked again before each wake, so a task is never kicked toward
 * a CPU outside its current mask. The queue node lives in arena memory
 * beside the task with the pid for owner lookup. A full target keeps
 * the newcomer in the FIFO queue with no extra probe. Queues hold
 * bounded at 64 total with eligibility always eligible.
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
#include <lib/edq.h>
#include <lib/sdt_task.h>
#include <lib/sdt_alloc.h>
static __always_inline struct scx_edq __arena *flow_edq_for_cpu(s32 tgt)
{
	if (tgt < 0 || !flow_cpu_ok((u32)tgt))
		return 0;
	if (!flow_cpu_live((u32)tgt))
		return 0;
	if (!flow_edqs)
		return 0;
	return &flow_edqs[(u32)tgt];
}
static __always_inline u64 flow_edq_deadline(s64 vd)
{
	if (vd < 0)
		return 0;
	return (u64)vd;
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
/* Idle wakes go only to an idle target. Each miss counts a skip
 * with no wake. Misses split by cause with no new counter. A bad
 * target skips. A masked target skips. An offline target skips.
 * A busy target skips. */
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
/* Guarded deadline wins preempt with one kick per run. Seven steps run
 * target then idle then run then token then gap then wall then win. Each
 * miss counts a skip with no wake. Misses split by cause with no new
 * counter. A bad or masked or offline target skips. An idle target takes
 * an idle wake. A stale run skips. An already kicked run skips. A late due
 * time past the gap skips. A fresh run under granularity skips. A short
 * tail skips. A lost race skips. A changed run after the win skips, so a
 * stale kick never wakes a fresh run. The token keeps the low thirty two
 * bits of the run count, so a repeat needs four billion runs on one CPU.
 * Gates run gap then granularity then tail with no reorder. */
static __always_inline void flow_kick_vd(s32 tgt, struct task_struct *p, u32 llc, s64 new_vd)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	struct flow_running_state *rs;
	u64 rgen;
	u32 rllc;
	u32 last;
	s64 run_vd;
	s64 win;
	u64 start;
	u64 now;
	u64 ran;
	u64 rem;
	u32 c;
	u64 fresh_gen;
	s64 fresh_vd;
	/* Step one of seven keeps the target gate. A bad or masked or
	 * offline target skips with no wake. */
	if (tgt < 0 || !p || !flow_cpu_ok((u32)tgt) || !flow_cpu_allowed(tgt, p) ||
	    !flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step two of seven keeps the idle fast path. An idle target takes
	 * an idle wake with no preempt. */
	if (scx_bpf_test_and_clear_cpu_idle(tgt)) {
		scx_bpf_kick_cpu(tgt, SCX_KICK_IDLE);
		flow_stat_inc(llc, 7);
		return;
	}
	/* Reassert the bound on the index used below so the verifier
	 * keeps the range across the calls above. The barrier keeps the
	 * compiler from folding the check away with the earlier one. */
	c = (u32)tgt;
	asm volatile ("" : "+r" (c));
	if (c >= (u32)FLOW_MAX_CPUS) {
		flow_stat_inc(llc, 8);
		return;
	}
	rs = &flow_running_state[c];
	rgen = READ_ONCE(rs->gen);
	rllc = READ_ONCE(rs->llc_id);
	/* Step three of seven keeps the run gate. A stale run skips. */
	if (!rgen || !flow_llc_ok(rllc) || rllc != llc) {
		flow_stat_inc(llc, 8);
		return;
	}
	last = READ_ONCE(rs->pad);
	/* Step four of seven keeps the token gate. An already kicked run
	 * skips. */
	if ((u32)rgen == last) {
		flow_stat_inc(llc, 8);
		return;
	}
	run_vd = READ_ONCE(rs->vd);
	/* Step five of seven keeps the gap gate. The win needs the new due
	 * time plus the gap below the running due time with signed
	 * saturation, else a late due time skips. */
	win = new_vd;
	if (win >= vmax - (s64)FLOW_KICK_GAP_NS)
		win = vmax;
	else
		win += (s64)FLOW_KICK_GAP_NS;
	if (!(win < run_vd)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step six of seven keeps the wall gates. A fresh run under
	 * granularity skips with cache plus lock protected, then a short
	 * tail skips with the tail protected. Wraparound reads zero. */
	start = READ_ONCE(rs->start_ts);
	now = bpf_ktime_get_ns();
	ran = now > start ? now - start : 0;
	if (ran < (u64)FLOW_KICK_GRAN_NS) {
		flow_stat_inc(llc, 8);
		return;
	}
	rem = READ_ONCE(rs->slice_rem);
	if (rem < (u64)FLOW_KICK_TAIL_NS) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Step seven of seven wins the token then rechecks the run. A lost
	 * race skips with the token spent, so each run still kicks at most
	 * once. */
	if (__sync_val_compare_and_swap(&rs->pad, last, (u32)rgen) != last) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* Freshness check after the win. The run may have ended and
	 * the mask may have moved while winning the token. A changed
	 * run skips with the token spent, so each run still kicks at
	 * most once. */
	if (!flow_cpu_allowed(tgt, p) || !flow_cpu_live((u32)tgt)) {
		flow_stat_inc(llc, 8);
		return;
	}
	fresh_gen = READ_ONCE(rs->gen);
	if (fresh_gen != rgen) {
		flow_stat_inc(llc, 8);
		return;
	}
	fresh_vd = READ_ONCE(rs->vd);
	if (!(win < fresh_vd)) {
		flow_stat_inc(llc, 8);
		return;
	}
	/* The running CPU keeps its LLC for the whole run, so this recheck
	 * always holds and only states the bound in the open. */
	rllc = READ_ONCE(rs->llc_id);
	if (!flow_llc_ok(rllc) || rllc != llc) {
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
	bool no_cpu;
	if (!p)
		return;
	scx_arena_subprog_init();
	task_cpu = scx_bpf_task_cpu(p);
	if (task_cpu < 0)
		task_cpu = (s32)bpf_get_smp_processor_id();
	tgt = flow_constrained_target(task_cpu, p);
	if (tgt >= 0 && flow_cpu_live((u32)tgt)) {
		u32 tmp = 0;
		if (!flow_llc_for_cpu(tgt, &tmp))
			llc = tmp;
		cpu_ok = 1;
	}
	/* The bound is a power of two, so a mask keeps the index in
	 * range with no division. */
	llc &= ((u32)FLOW_MAX_LLCS - 1U);
	no_cpu = !cpu_ok || tgt < 0;
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
				struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
				bool fell = true;
				if (edq) {
					void __arena *mem = __scx_task_data(p);
					if (mem) {
						struct flow_arena_task __arena *at = mem;
						u64 dl = flow_edq_deadline(raw_v);
						WRITE_ONCE(at->pid, p->pid);
						/* Unbounded admit with the insert return
						 * as the sole test and no room probe. */
						{
							int ret = scx_edq_insert(edq,
										 (scx_edq_task_t *)at,
										 dl, 0,
										 (u64)FLOW_EXIT_SLICE_NS);
							if (!ret)
								fell = false;
						}
					}
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
		/* Single slot per task through the queued bit. A duplicate
		 * requeue drops with the duplicate count only and no gauge
		 * move and no fallback move and no extra probe, so the
		 * backlog stays within the live task count with FIFO order
		 * kept and no new counter. */
		flow_stat_inc(llc, 4);
		return;
	}
	if (p->flags & PF_EXITING) {
		struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
		bool fell = true;
		t->llc_id = llc;
		if (edq) {
			void __arena *mem = __scx_task_data(p);
			if (mem) {
				struct flow_arena_task __arena *at = mem;
				u64 dl = flow_edq_deadline(raw_v);
				WRITE_ONCE(at->pid, p->pid);
				/* Unbounded admit with the insert return
				 * as the sole test and no room probe. */
				{
					int ret = scx_edq_insert(edq,
								 (scx_edq_task_t *)at,
								 dl, 0,
								 (u64)FLOW_EXIT_SLICE_NS);
					if (!ret)
						fell = false;
				}
			}
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
		 * Queues hold bounded at 64 total with pure deadline order
		 * and a single kick. A full target keeps the newcomer in
		 * FIFO with no evict. Steady tasks price by the kept max
		 * with the shared charge path and run in one slice quanta,
		 * while unknown tasks keep the burst path with no extra
		 * probe. Enqueue reads the cached flag with no clock and
		 * no scan. */
		s64 base = READ_ONCE(t->vtime);
		u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));
		s64 floored = no_cpu ? base : flow_seq_floor(llc, base);
		s64 vd = flow_vd_for(floored, READ_ONCE(t->burst_ns), w);
		u64 slice_len = (u64)FLOW_SLICE_MIN_NS;
		struct scx_edq __arena *edq = no_cpu ? 0 : flow_edq_for_cpu(tgt);
		bool fell = true;
		bool can_queue = false;
		void __arena *mem = 0;
		u64 ref = READ_ONCE(t->run_max);
		u32 known = READ_ONCE(t->run_known);
		if (known && ref) {
			u64 eff = flow_run_eff(ref, READ_ONCE(t->burst_ns));
			vd = flow_run_vd(floored, eff, w);
			slice_len = flow_run_slice(ref);
		}
		if (edq) {
			mem = __scx_task_data(p);
			if (mem)
				can_queue = true;
		}
		t->vtime = floored;
		t->vd = vd;
		t->slice_rem = slice_len;
		t->llc_id = llc;
		/* Mirror the due time beside the stored time so later reads see the same due time for order checks. */
		scx_bpf_task_set_dsq_vtime(p, vd);
		/* A full target keeps the newcomer in FIFO with no extra probe. */
		if (can_queue) {
			struct flow_arena_task __arena *at = mem;
			u64 dl = flow_edq_deadline(vd);
			WRITE_ONCE(at->pid, p->pid);
			{
				int ret = scx_edq_insert(edq,
							 (scx_edq_task_t *)at,
							 dl, 0, slice_len);
				if (!ret)
					fell = false;
			}
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
	/* Task state is missing, so the queued bit stays clear and a cancel
	 * before the run leaves one gauge unit behind. This path only runs
	 * when the state alloc fails, so the drift stays within those misses. */
	{
		u64 sl = (u64)FLOW_SLICE_MIN_NS;
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, sl, enq_flags);
		flow_stat_inc(llc, 0);
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
