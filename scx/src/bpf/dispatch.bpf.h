// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own queue first, then the most loaded queue,
 * then mates in the same LLC, then the rest of the same LLC, then
 * the same node, then distant queues last, then fallback. The most loaded
 * pick scans waiting counts with mates first on ties and lowest id
 * after that. Idle work starts at once with no wait for warm tasks.
 * Queues hold without a bound and empty queues are skipped with no
 * peek through waiting counts. Mates compare the cluster hint with
 * no extra walk. Each queue drains the earlier vd across both strands
 * with ties to the first strand. Remote queues drain last with both
 * strands in vd order, so locality comes from order alone. The same
 * LLC means the same chip and the same node comes from the tree walk. Trying one strand
 * first or the fuller side or alternating sides would favor warm or
 * cold tasks and break fairness, so the drain keeps vd order by vd
 * only. A head that cannot run here sends one wake to its owner and
 * stays queued. Each victim keeps its own forward slot with the
 * fallback on the last slot, so one victim does not hide another.
 * A dead head is dropped with its count and the next queue is tried.
 * Waiting counts drop on moves to local plus dead drops plus moves
 * to fallback with the race kept. The fallback drops its count from
 * the task and wakes the owner when the move fails. A dispatch that
 * moved nothing but saw such a head wakes the fallback head again
 * without the dedup check. Remote moves count on the thief and drop
 * the gauge on the source. Running records the task snapshot with
 * the vd. Stopping charges burnt time into the stored time with the
 * same value mirrored beside it. A runnable yield with no burnt time
 * still moves the stored time forward by one. The tick charges the
 * burnt delta and moves the left slice forward with the same value
 * mirrored beside it, so stopping charges only the tail past the last
 * tick. A busy core runs at max and an idle core runs at half. The
 * set call never sends zero and never steers placement. A mask change
 * on a queued task keeps the queue and wakes the new owner, counting
 * the wake when the owner is usable. A task with no usable CPU waits
 * in the fallback queue until the mask widens. Init creates one queue
 * per CPU and the fallback queue. Queues use the upstream library in
 * virtual time mode. Liveness comes from the upstream tree, so CPUs
 * that arrive late need a restart to be seen.
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
#include "cgroup.bpf.h"
#include <lib/dhq.h>
#include <lib/topology.h>
#include <lib/sdt_alloc.h>
/* A busy core runs at max and an idle core runs at half. The call
 * stays on one live core and never sends zero. */
static __always_inline void flow_cpuperf_mark(u32 cpu, bool idle)
{
	u32 perf;
	if (!flow_cpu_ok(cpu) || !flow_cpu_live(cpu))
		return;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	perf = (u32)SCX_CPUPERF_ONE;
	if (idle)
		perf = (u32)(SCX_CPUPERF_ONE / 2);
	if (!perf)
		return;
	scx_bpf_cpuperf_set((s32)cpu, perf);
}
static __always_inline void flow_forward_from_peeked(struct task_struct *ph, u32 llc, u32 slot)
{
	s32 owner;
	s64 hv;
	u64 pid;
	if (!ph)
		return;
	if (slot > (u32)FLOW_MAX_LLCS)
		return;
	pid = (u64)ph->pid;
	hv = (s64)ph->scx.dsq_vtime;
	owner = flow_first_allowed(ph);
	{
		u64 last_p = READ_ONCE(flow_fwd_pid[slot]);
		s64 last_v = READ_ONCE(flow_fwd_vtime[slot]);
		s32 last_o = READ_ONCE(flow_fwd_owner[slot]);
		if (last_p == pid && last_v == hv && last_o == owner)
			return;
		flow_fwd_pid[slot] = pid;
		flow_fwd_vtime[slot] = hv;
		flow_fwd_owner[slot] = owner;
	}
	if (owner < 0) {
		flow_kick_idle_only(owner, ph, llc);
		return;
	}
	flow_stat_inc(llc, 12);
	flow_kick_idle_only(owner, ph, llc);
}
/* A dispatch that moved nothing but saw an unrunnable head wakes the
 * fallback head again without the dedup check, so an owner that
 * turned idle is not missed. The kick stays idle only with no pad check. */
static __always_inline void flow_rekick_unrunnable(struct task_struct *ph, u32 llc)
{
	s32 owner;
	if (!ph)
		return;
	owner = flow_first_allowed(ph);
	flow_kick_idle_only(owner, ph, llc);
}
static __always_inline int flow_try_move_dhq(u32 cpu, u32 llc, u32 vllc, u32 victim, scx_dhq_t *dhq,
					     u64 strand, u32 slot, int steal, bool *saw)
{
	u64 peeked;
	struct task_struct *ph;
	struct task_struct *p;
	struct flow_task_ctx *lt;
	u64 slice;
	u64 popped;
	if (!dhq)
		return 0;
	if (slot > (u32)FLOW_MAX_LLCS)
		return 0;
	peeked = scx_dhq_peek_strand(dhq, strand);
	if (!peeked)
		return 0;
	ph = bpf_task_from_pid((s32)peeked);
	if (!ph) {
		u64 dead = scx_dhq_pop_strand(dhq, strand);
		struct task_struct *dq;
		if (!dead)
			return 0;
		dq = bpf_task_from_pid((s32)dead);
		if (!dq) {
			flow_queued_dec(vllc);
			flow_qcnt_dec(victim);
			return 0;
		}
		/* Another CPU removed the dead head and this pop took the
		 * next task. Keep it alive through fallback with no count
		 * drop, so no task is lost on the race. */
		if (saw)
			*saw = true;
		flow_forward_from_peeked(dq, llc, slot);
		lt = bpf_task_storage_get(&task_ctx_stor, dq, 0, 0);
		slice = (u64)FLOW_SLICE_MIN_NS;
		if (lt) {
			u64 s = READ_ONCE(lt->slice_rem);
			if (s)
				slice = s;
		}
		scx_bpf_dsq_insert(dq, (u64)FLOW_FALLBACK_DSQ, slice, 0);
		flow_stat_inc(llc, 2);
		flow_qcnt_dec(victim);
		bpf_task_release(dq);
		return 0;
	}
	if (!flow_cpu_allowed((s32)cpu, ph)) {
		if (saw)
			*saw = true;
		flow_forward_from_peeked(ph, llc, slot);
		bpf_task_release(ph);
		return 0;
	}
	bpf_task_release(ph);
	popped = scx_dhq_pop_strand(dhq, strand);
	if (!popped)
		return 0;
	p = bpf_task_from_pid((s32)popped);
	if (!p) {
		flow_queued_dec(vllc);
		flow_qcnt_dec(victim);
		return 0;
	}
	if (!flow_cpu_allowed((s32)cpu, p)) {
		if (saw)
			*saw = true;
		flow_forward_from_peeked(p, llc, slot);
		/* Keep the task alive through the fallback queue. */
		lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		slice = (u64)FLOW_SLICE_MIN_NS;
		if (lt) {
			u64 s = READ_ONCE(lt->slice_rem);
			if (s)
				slice = s;
		}
		scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, slice, 0);
		flow_stat_inc(llc, 2);
		flow_qcnt_dec(victim);
		bpf_task_release(p);
		return 0;
	}
	lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	slice = (u64)FLOW_SLICE_MIN_NS;
	if (lt) {
		u64 s = READ_ONCE(lt->slice_rem);
		if (s)
			slice = s;
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	bpf_task_release(p);
	flow_cpuperf_mark(cpu, false);
	flow_stat_inc(llc, 1);
	flow_queued_dec(vllc);
	flow_qcnt_dec(victim);
	if (steal) {
		flow_stat_inc(llc, 3);
		flow_stat_inc(llc, 5);
	}
	return 1;
}
/* Pick the loaded queue with the most waiting tasks. Ties prefer
 * mates first with the lowest id after that. Empty queues never win. */
static __always_inline s32 flow_pick_busiest(u32 self, u32 self_llc, u32 self_ccx)
{
	s32 best = -1;
	u32 best_cnt = 0;
	bool best_mate = false;
	u32 cpu;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 h;
		u32 cnt;
		int vl;
		bool mate;
		if (cpu == self)
			continue;
		if (!flow_cpu_live(cpu))
			continue;
		h = READ_ONCE(flow_dhqs[cpu]);
		if (!h)
			continue;
		cnt = READ_ONCE(flow_qcnt[cpu]);
		if (!cnt)
			continue;
		if (best < 0 || cnt > best_cnt) {
			vl = topo_cpu_to_llc_id(cpu);
			mate = (vl >= 0 && (u32)vl == self_llc &&
				flow_cpu_ccx(cpu) == self_ccx);
			best = (s32)cpu;
			best_cnt = cnt;
			best_mate = mate;
		} else if (cnt == best_cnt) {
			vl = topo_cpu_to_llc_id(cpu);
			mate = (vl >= 0 && (u32)vl == self_llc &&
				flow_cpu_ccx(cpu) == self_ccx);
			if (mate && !best_mate) {
				best = (s32)cpu;
				best_mate = true;
			}
		}
	}
	return best;
}
/* Same node holds the same LLC plus the tree node. Remote queues drain
 * last with both strands in vd order, so locality comes from order. */
static __always_inline int flow_is_same_node(u32 cpu, u32 llc, topo_ptr hint_node, u32 victim)
{
	int vl;
	if (!flow_cpu_ok(victim))
		return 0;
	vl = topo_cpu_to_llc_id(victim);
	if (vl >= 0 && flow_llc_ok((u32)vl) && (u32)vl == llc)
		return 1;
	(void)cpu;
	if (hint_node && topo_contains(hint_node, victim))
		return 1;
	return 0;
}
static __always_inline int flow_drain_cpu(u32 cpu, u32 llc, u32 victim, int steal, bool *saw,
					  int warm_only)
{
	scx_dhq_t *dhq;
	u64 h;
	int vllc;
	u32 vuse;
	u32 slot;
	if (!flow_cpu_ok(victim) || !flow_cpu_live(victim))
		return 0;
	h = READ_ONCE(flow_dhqs[victim]);
	if (!h)
		return 0;
	dhq = (scx_dhq_t *)h;
	vllc = topo_cpu_to_llc_id(victim);
	if (vllc < 0 || !flow_llc_ok((u32)vllc))
		return 0;
	vuse = (u32)vllc;
	/* The bound is a power of two, so a mask keeps the slot in
	 * range with no division. The fallback keeps the last slot. */
	slot = victim & ((u32)FLOW_MAX_LLCS - 1U);
	/* No warm caller. Remote drains last with both strands in vd order. */
	if (warm_only)
		return flow_try_move_dhq(cpu, llc, vuse, victim, dhq,
					 (u64)SCX_DHQ_STRAND_A, slot, steal, saw);
	/* Dual strand drain orders by vd only. */
	{
		u64 pa = scx_dhq_peek_strand(dhq, (u64)SCX_DHQ_STRAND_A);
		u64 pb = scx_dhq_peek_strand(dhq, (u64)SCX_DHQ_STRAND_B);
		if (!pa && !pb)
			return 0;
		if (pa && pb) {
			struct task_struct *ta = bpf_task_from_pid((s32)pa);
			struct task_struct *tb = bpf_task_from_pid((s32)pb);
			u64 first = (u64)SCX_DHQ_STRAND_A;
			u64 second = (u64)SCX_DHQ_STRAND_B;
			if (ta && tb) {
				s64 va = (s64)ta->scx.dsq_vtime;
				s64 vb = (s64)tb->scx.dsq_vtime;
				if (vb < va) {
					first = (u64)SCX_DHQ_STRAND_B;
					second = (u64)SCX_DHQ_STRAND_A;
				}
			} else if (!ta && tb) {
				first = (u64)SCX_DHQ_STRAND_B;
				second = (u64)SCX_DHQ_STRAND_A;
			}
			if (ta)
				bpf_task_release(ta);
			if (tb)
				bpf_task_release(tb);
			if (flow_try_move_dhq(cpu, llc, vuse, victim, dhq, first, slot, steal, saw))
				return 1;
			return flow_try_move_dhq(cpu, llc, vuse, victim, dhq, second, slot, steal, saw);
		}
		if (pa)
			return flow_try_move_dhq(cpu, llc, vuse, victim, dhq,
						 (u64)SCX_DHQ_STRAND_A, slot, steal, saw);
		return flow_try_move_dhq(cpu, llc, vuse, victim, dhq,
					 (u64)SCX_DHQ_STRAND_B, slot, steal, saw);
	}
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 victim;
	int v;
	bool saw_unrunnable = false;
	struct topo_iter hint_iter;
	topo_ptr hint_node = 0;
	topo_ptr walk = 0;
	(void)prev;
	scx_arena_subprog_init();
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
	if (flow_drain_cpu(c, llc, c, 0, &saw_unrunnable, 0))
		return;
	{
		u32 my_ccx = flow_cpu_ccx(c);
		s32 busy = flow_pick_busiest(c, llc, my_ccx);
		if (busy >= 0) {
			/* Busiest victim drains both strands with locality from order. */
			if (flow_drain_cpu(c, llc, (u32)busy, 1, &saw_unrunnable, 0))
				return;
		}
		bpf_for(victim, 0, FLOW_MAX_CPUS) {
			int vl;
			if (victim == c)
				continue;
			if (!flow_cpu_live(victim))
				continue;
			/* Empty queues are skipped with no peek. */
			if (!flow_qcnt_get(victim))
				continue;
			vl = topo_cpu_to_llc_id(victim);
			if (vl < 0 || (u32)vl != llc)
				continue;
			/* Mates first in the same LLC with no extra walk. */
			if (flow_cpu_ccx(victim) != my_ccx)
				continue;
			if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable, 0))
				return;
		}
		bpf_for(victim, 0, FLOW_MAX_CPUS) {
			int vl;
			bool same_llc;
			if (victim == c)
				continue;
			if (!flow_cpu_live(victim))
				continue;
			/* Empty queues are skipped with no peek. */
			if (!flow_qcnt_get(victim))
				continue;
			vl = topo_cpu_to_llc_id(victim);
			same_llc = (vl >= 0 && flow_llc_ok((u32)vl) && (u32)vl == llc);
			if (same_llc) {
				/* Mates already ran, so only the rest remains. */
				if (flow_cpu_ccx(victim) == my_ccx)
					continue;
			} else {
				if (vl < 0 || !flow_llc_ok((u32)vl))
					continue;
				/* Node identity comes from the tree with no per-CPU walk here. */
				if (!hint_node || !topo_contains(hint_node, victim))
					continue;
			}
			if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable, 0))
				return;
		}
	}
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
		/* Empty queues are skipped with no peek. */
		if (!flow_qcnt_get(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		if (hint_node && topo_contains(hint_node, victim))
			continue;
		/* Remote drains last with both strands in vd order. */
		if (flow_drain_cpu(c, llc, victim, 1, &saw_unrunnable, 0))
			return;
	}
	{
		struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (ph) {
			if (!flow_cpu_allowed((s32)c, ph)) {
				flow_forward_from_peeked(ph, llc, (u32)FLOW_MAX_LLCS);
				saw_unrunnable = true;
			} else {
				struct flow_task_ctx *pt;
				u32 vllc = llc;
				pt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
				if (pt) {
					u32 q = READ_ONCE(pt->llc_id);
					if (flow_llc_ok(q))
						vllc = q;
				}
				if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
					flow_stat_inc(llc, 1);
					flow_cpuperf_mark(c, false);
					flow_queued_dec(vllc);
					return;
				}
				/* The head can run here but the move failed.
				 * Wake the owner so the task is not left idle. */
				flow_forward_from_peeked(ph, llc, (u32)FLOW_MAX_LLCS);
				saw_unrunnable = true;
			}
		}
	}
	if (saw_unrunnable) {
		struct task_struct *rh = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (rh)
			flow_rekick_unrunnable(rh, llc);
	}
	/* No task moved, so the core stays idle at half. */
	flow_cpuperf_mark(c, true);
}
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	u32 llc = 0;
	struct flow_running_state *rs;
	u64 sl;
	u64 ng;
	int v;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	v = topo_cpu_to_llc_id(cpu);
	if (v >= 0 && flow_llc_ok((u32)v))
		llc = (u32)v;
	else if (flow_llc_ok(t->llc_id))
		llc = t->llc_id;
	sl = p->scx.slice;
	if (!sl)
		sl = (u64)FLOW_SLICE_MIN_NS;
	else if (sl > (u64)FLOW_SLICE_MIN_NS)
		sl = (u64)FLOW_SLICE_MIN_NS;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = READ_ONCE(t->vtime);
	rs->slice_rem = sl;
	rs->gen = ng;
	rs->llc_id = llc;
	rs->vd = READ_ONCE(t->vd);
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	/* The stored time did not move, refresh the mirror beside it. */
	scx_bpf_task_set_dsq_vtime(p, READ_ONCE(t->vd));
	/* The gauge was already dropped when the task moved to the local
	 * queue. Local inserts were never counted. Running only clears
	 * ownership. The core is busy now, so it runs at max. */
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	flow_cpuperf_mark(cpu, false);
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	u64 used;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	have = READ_ONCE(t->slice_rem);
	if (!have)
		have = (u64)FLOW_SLICE_MIN_NS;
	if (cur > have)
		cur = have;
	if (cur >= have)
		used = 0;
	else
		used = have - cur;
	/* Burnt time pays here, scaled by the share with saturation. The tick
	 * already moved the left slice forward, so this charges only the tail
	 * past the last tick. A runnable yield with no burnt time still moves
	 * the stored time forward by one, so repeated yields cannot hold the
	 * queue head. */
	if (used) {
		u64 cgid = READ_ONCE(t->cgrp_id);
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), used,
					  flow_combine(flow_cgroup_lookup(cgid),
						       flow_nice_weight(p)));
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
		if (!cur)
			flow_stat_inc(rs->llc_id, 9);
	} else if (runnable) {
		s64 nv = flow_fair_cap_add(READ_ONCE(t->vtime), 1);
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
	}
	rs->slice_rem = cur;
	t->slice_rem = cur;
	/* A sleeping task leaves the core idle at half. A runnable task
	 * keeps its count with no frequency change. */
	if (runnable)
		flow_stat_inc(rs->llc_id, 10);
	else
		flow_cpuperf_mark(cpu, true);
}
void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 have;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	rs = &flow_running_state[cpu];
	cur = p->scx.slice;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t) {
		rs->slice_rem = cur;
		return;
	}
	/* Charge the burnt delta, then move the left slice forward, so
	 * stopping later charges only the tail past this tick. */
	have = READ_ONCE(t->slice_rem);
	if (cur && cur < have) {
		u64 delta = have - cur;
		u64 cgid = READ_ONCE(t->cgrp_id);
		s64 nv = flow_fair_charge(READ_ONCE(t->vtime), delta,
					  flow_combine(flow_cgroup_lookup(cgid),
						       flow_nice_weight(p)));
		t->vtime = nv;
		t->slice_rem = cur;
		scx_bpf_task_set_dsq_vtime(p, nv);
	}
	rs->slice_rem = cur;
}
void BPF_STRUCT_OPS(flow_set_cpumask, struct task_struct *p, const struct cpumask *mask)
{
	struct flow_task_ctx *t;
	(void)mask;
	if (!p)
		return;
	scx_arena_subprog_init();
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(qllc))
			qllc = 0;
		if (owner < 0) {
			/* No usable CPU. The task waits in fallback
			 * until the mask widens, so count the skip. */
			flow_stat_inc(qllc, 8);
			return;
		}
		if (!flow_cpu_allowed(owner, p) || !flow_cpu_live((u32)owner)) {
			flow_stat_inc(qllc, 8);
			return;
		}
		flow_kick_idle_only(owner, p, qllc);
		flow_stat_inc(qllc, 11);
		return;
	}
	if (p->flags & PF_EXITING)
		t->slice_rem = (u64)FLOW_EXIT_SLICE_NS;
	{
		s32 tgt = flow_first_allowed(p);
		int v;
		if (tgt < 0)
			return;
		if (!flow_cpu_live((u32)tgt))
			return;
		v = topo_cpu_to_llc_id((u32)tgt);
		if (v < 0 || !flow_llc_ok((u32)v))
			return;
		t->llc_id = (u32)v;
	}
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;
	s64 v;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	v = (s64)p->scx.dsq_vtime;
	t->vtime = v;
	t->vd = v;
	t->slice_rem = (u64)FLOW_SLICE_MIN_NS;
	if (!t->cgrp_id) {
		struct cgroup *cg = scx_bpf_task_cgroup(p);

		/* The kfunc hands back a reference, drop it after the read. */
		if (cg) {
			t->cgrp_id = flow_cgroup_cgid(cg);
			bpf_cgroup_release(cg);
		}
	}
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
}
s32 BPF_STRUCT_OPS(flow_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;
	u64 cgid = 0;
	if (!p)
		return 0;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return 0;
	if (args && args->cgroup)
		cgid = flow_cgroup_cgid(args->cgroup);
	t->vtime = 0;
	t->vd = 0;
	t->slice_rem = (u64)FLOW_SLICE_MIN_NS;
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
	t->cgrp_id = cgid;
	scx_bpf_task_set_dsq_vtime(p, 0);
	return 0;
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	s32 cpu;
	n = scx_bpf_nr_cpu_ids();
	scx_arena_subprog_init();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	/* The arena library must be ready before any queue is built.
	 * Userspace sets up the arena and the topology tree before load,
	 * so a missing tree fails closed here with no partial queues. */
	if (!topo_all) {
		scx_bpf_error("topology tree missing");
		return -ENODEV;
	}
	/* Thread shape keeps the userspace seed with the source default on miss. */
	flow_ccx_prefer = 1;
	if (n > 512ULL) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		scx_dhq_t *dhq;
		if ((u64)cpu >= n)
			break;
		if (cpu < 0)
			continue;
		if (!flow_cpu_live((u32)cpu))
			continue;
		/* One upstream queue per CPU in virtual time mode with
		 * no bound and at most one extra task on one side. */
		dhq = (scx_dhq_t *)scx_dhq_create_balanced(false, SCX_DHQ_INF_CAPACITY,
							   (u64)SCX_DHQ_MODE_BALANCED, 1ULL);
		if (!dhq) {
			scx_bpf_error("queue create failed");
			return -ENOMEM;
		}
		flow_dhqs[(u32)cpu] = (u64)dhq;
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	s32 cpu;
	UEI_RECORD(uei, info);
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		if (cpu < 0)
			continue;
		if (!READ_ONCE(flow_dhqs[(u32)cpu]))
			continue;
		flow_dhqs[(u32)cpu] = 0ULL;
	}
	scx_bpf_destroy_dsq((u64)FLOW_FALLBACK_DSQ);
}
#endif
