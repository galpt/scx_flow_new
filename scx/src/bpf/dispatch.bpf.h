// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own per CPU queues first, then queues on the
 * same LLC, then the same node, then distant queues, then fallback.
 * Each queue drains in queue order and strands drain balanced with
 * the larger side first and a long head promoted on ties.
 * Long waiting batch and idle heads drain before normal.
 * Overdue tasks stay on the first strand, so the first strand still
 * drains first on ties. A head that cannot run here
 * sends one wake to its owner and stays queued. Remote moves count
 * on the thief and drop the gauge on the source. Running records
 * the task snapshot with the slack at running time and counts the
 * enqueue to run wait. Dispatch
 * counts the enqueue to dispatch wait on the moving CPU with one
 * clock read in running. Stopping
 * burns the used time from remain down to a floor
 * and charges use into the stored time with the same value
 * mirrored beside it. A runnable yield with no burnt time still
 * moves the stored time forward by one. The tick charges the
 * burnt delta and burns
 * it from remain, then moves the remaining slice forward
 * with the same value mirrored beside it, so stopping charges
 * only the tail past the last tick. Frequency stays with the
 * governor and never steers placement. Only a fixed hint that
 * never sends zero may reach the governor. A mask change on a queued
 * task keeps the queue and wakes the new owner, counting the wake
 * when the owner is usable. Tasks that already ran favor their
 * first CPU. Init creates one queue per CPU and the fallback
 * queue. Queues use the upstream library in virtual time mode with
 * balanced drains. Liveness comes from the upstream tree, so CPUs
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
#include "lst.bpf.h"
#include "cgroup.bpf.h"
#include "lat.bpf.h"
#include <lib/dhq.h>
#include <lib/topology.h>
#include <lib/sdt_alloc.h>
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
	if (READ_ONCE(flow_home_stick)) {
		struct flow_task_ctx *ft = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
		if (ft) {
			s32 hm = READ_ONCE(ft->home_cpu);
			if (hm >= 0 && flow_cpu_allowed(hm, ph) && flow_cpu_live((u32)hm))
				owner = hm;
		}
	}
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
	flow_stat_inc(llc, 14);
	flow_kick_idle_only(owner, ph, llc);
}
static __always_inline int flow_try_move_dhq(u32 cpu, u32 llc, u32 vllc, scx_dhq_t *dhq,
					     u64 strand, u32 slot, int steal)
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
	if (!ph)
		return 0;
	if (!flow_cpu_allowed((s32)cpu, ph)) {
		flow_forward_from_peeked(ph, llc, slot);
		bpf_task_release(ph);
		return 0;
	}
	bpf_task_release(ph);
	popped = scx_dhq_pop_strand(dhq, strand);
	if (!popped)
		return 0;
	p = bpf_task_from_pid((s32)popped);
	if (!p)
		return 0;
	if (!flow_cpu_allowed((s32)cpu, p)) {
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
		bpf_task_release(p);
		return 0;
	}
	lt = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (lt)
		flow_lat_observe(cpu, lt, scx_bpf_now(), 0);
	slice = (u64)FLOW_SLICE_MIN_NS;
	if (lt) {
		u64 s = READ_ONCE(lt->slice_rem);
		if (s)
			slice = s;
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
	bpf_task_release(p);
	flow_stat_inc(llc, 1);
	flow_queued_dec(vllc);
	if (steal) {
		flow_stat_inc(llc, 3);
		flow_stat_inc(llc, 5);
	}
	return 1;
}
static __always_inline bool flow_wait_long(u64 enq, u64 now)
{
	if (!enq || !now)
		return false;
	if (now <= enq)
		return false;
	return now - enq > (u64)FLOW_LST_REL_NS;
}
static __always_inline bool flow_head_long_dhq(scx_dhq_t *dhq, u64 strand, u64 now)
{
	u64 peeked;
	struct task_struct *ph;
	struct flow_task_ctx *lt;
	u64 enq;
	bool out = false;
	if (!dhq || !now)
		return false;
	peeked = scx_dhq_peek_strand(dhq, strand);
	if (!peeked)
		return false;
	ph = bpf_task_from_pid((s32)peeked);
	if (!ph)
		return false;
	lt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
	if (!lt) {
		bpf_task_release(ph);
		return false;
	}
	enq = READ_ONCE(lt->enq_ns);
	out = flow_wait_long(enq, now);
	bpf_task_release(ph);
	return out;
}
static __always_inline int flow_drain_cpu(u32 cpu, u32 llc, u32 victim, int steal)
{
	scx_dhq_t *dhq;
	u64 h;
	int na;
	int nb;
	u64 ca;
	u64 cb;
	u64 first;
	u64 second;
	int vllc;
	u32 vuse;
	u32 slot;
	u64 now;
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
	slot = (u32)FLOW_MAX_LLCS;
	na = scx_dhq_nr_queued_strand(dhq, (u64)SCX_DHQ_STRAND_A);
	nb = scx_dhq_nr_queued_strand(dhq, (u64)SCX_DHQ_STRAND_B);
	ca = na < 0 ? 0ULL : (u64)na;
	cb = nb < 0 ? 0ULL : (u64)nb;
	if (!ca && !cb)
		return 0;
	/* Balanced drains take the larger strand first. Ties keep the
	 * first strand unless the second head waited long, so long
	 * batch and idle heads drain before normal on ties. */
	if (cb > ca) {
		first = (u64)SCX_DHQ_STRAND_B;
		second = (u64)SCX_DHQ_STRAND_A;
	} else if (ca > cb) {
		if (ca == cb + 1ULL) {
			now = scx_bpf_now();
			if (flow_head_long_dhq(dhq, (u64)SCX_DHQ_STRAND_B, now)) {
				first = (u64)SCX_DHQ_STRAND_B;
				second = (u64)SCX_DHQ_STRAND_A;
			} else {
				first = (u64)SCX_DHQ_STRAND_A;
				second = (u64)SCX_DHQ_STRAND_B;
			}
		} else {
			first = (u64)SCX_DHQ_STRAND_A;
			second = (u64)SCX_DHQ_STRAND_B;
		}
	} else {
		now = scx_bpf_now();
		if (flow_head_long_dhq(dhq, (u64)SCX_DHQ_STRAND_B, now)) {
			first = (u64)SCX_DHQ_STRAND_B;
			second = (u64)SCX_DHQ_STRAND_A;
		} else {
			first = (u64)SCX_DHQ_STRAND_A;
			second = (u64)SCX_DHQ_STRAND_B;
		}
	}
	if (flow_try_move_dhq(cpu, llc, vuse, dhq, first, slot, steal))
		return 1;
	if (flow_try_move_dhq(cpu, llc, vuse, dhq, second, slot, steal))
		return 1;
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 victim;
	u32 li;
	int v;
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
	if (flow_drain_cpu(c, llc, c, 0))
		return;
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || (u32)vl != llc)
			continue;
		if (flow_drain_cpu(c, llc, victim, 1))
			return;
	}
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		/* Node identity comes from the tree with no per-CPU walk here. */
		if (!hint_node || !topo_contains(hint_node, victim))
			continue;
		if (flow_drain_cpu(c, llc, victim, 1))
			return;
	}
	bpf_for(victim, 0, FLOW_MAX_CPUS) {
		int vl;
		if (victim == c)
			continue;
		if (!flow_cpu_live(victim))
			continue;
		vl = topo_cpu_to_llc_id(victim);
		if (vl < 0 || !flow_llc_ok((u32)vl) || (u32)vl == llc)
			continue;
		if (hint_node && topo_contains(hint_node, victim))
			continue;
		if (flow_drain_cpu(c, llc, victim, 1))
			return;
	}
	{
		struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);
		if (ph) {
			if (!flow_cpu_allowed((s32)c, ph)) {
				flow_forward_from_peeked(ph, llc, (u32)FLOW_MAX_LLCS);
			} else {
				struct flow_task_ctx *pt;
				u32 vllc = llc;
				int have_owner = 0;
				pt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
				if (pt) {
					u32 q = READ_ONCE(pt->llc_id);
					if (flow_llc_ok(q)) {
						vllc = q;
						have_owner = 1;
					}
				}
				if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
					if (pt)
						flow_lat_observe(c, pt, scx_bpf_now(), 0);
					flow_stat_inc(llc, 1);
					if (have_owner) {
						flow_queued_dec(vllc);
					} else {
						bpf_for(li, 0, FLOW_MAX_LLCS) {
							struct flow_llc_stats *st;
							if (!flow_llc_ok(li))
								continue;
							st = flow_stats_for(li);
							if (!st)
								continue;
							if (READ_ONCE(st->queued) == 0)
								continue;
							flow_queued_dec(li);
							break;
						}
					}
				}
			}
		}
	}
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
	u64 now;
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
	else if (sl > (u64)FLOW_SLICE_MIN_NS * 3)
		sl = (u64)FLOW_SLICE_MIN_NS * 3;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	now = scx_bpf_now();
	rs->vtime = t->vtime;
	rs->slice_rem = sl;
	rs->gen = ng;
	rs->llc_id = llc;
	rs->prio = t->prio;
	rs->reserved = 0;
	rs->slack = flow_lst_slack(READ_ONCE(t->deadline_ns), now,
				   READ_ONCE(t->remain_ns));
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	if (READ_ONCE(flow_home_stick) && READ_ONCE(t->home_cpu) < 0)
		t->home_cpu = (s32)cpu;
	/* The stored time did not move, refresh the mirror beside it. */
	scx_bpf_task_set_dsq_vtime(p, t->vtime);
	flow_lat_observe(cpu, t, now, 1);
	/* The gauge was already dropped when the task moved to the local
	 * queue. Local inserts were never counted. Running only clears
	 * ownership. */
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 remain;
	u64 len;
	u64 used;
	u64 rem;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	rs = &flow_running_state[cpu];
	remain = p->scx.slice;
	len = t->slice_rem;
	if (!len)
		len = (u64)FLOW_SLICE_MIN_NS;
	if (remain > len)
		remain = len;
	if (remain >= len)
		used = 0;
	else
		used = len - remain;
	rem = READ_ONCE(t->remain_ns);
	if (!rem)
		rem = (u64)FLOW_LST_INIT_NS;
	rem = flow_lst_clamp_rem(rem);
	if (used) {
		if (used >= rem)
			rem = (u64)FLOW_LST_FLOOR_NS;
		else
			rem -= used;
		rem = flow_lst_clamp_rem(rem);
	}
	t->remain_ns = rem;
	/* Use pays here, scaled by the share with saturation. The tick
	 * already moved the remaining slice forward, so this charges
	 * only the tail past the last tick. A runnable yield with no
	 * burnt time still moves the stored time forward by one, so
	 * repeated yields cannot hold the queue head. */
	if (used) {
		u64 cgid = READ_ONCE(t->cgrp_id);
		s64 nv = flow_fair_charge(t->vtime, used, flow_cgroup_lookup(cgid));
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
	} else if (runnable) {
		s64 nv = flow_fair_cap_add(t->vtime, 1);
		t->vtime = nv;
		scx_bpf_task_set_dsq_vtime(p, nv);
	}
	rs->slice_rem = remain;
	t->slice_rem = remain;
	if (runnable)
		flow_stat_inc(rs->llc_id, 11);
}
void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 cur;
	u64 last;
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
	/* Charge the burnt delta and burn it from remain, then move
	 * the remaining slice forward, so stopping later charges only
	 * the tail past this tick. */
	last = READ_ONCE(t->slice_rem);
	if (cur && cur < last) {
		u64 delta = last - cur;
		u64 cgid = READ_ONCE(t->cgrp_id);
		u64 rem = READ_ONCE(t->remain_ns);
		s64 nv = flow_fair_charge(t->vtime, delta, flow_cgroup_lookup(cgid));
		t->vtime = nv;
		if (!rem)
			rem = (u64)FLOW_LST_INIT_NS;
		rem = flow_lst_clamp_rem(rem);
		if (delta >= rem)
			rem = (u64)FLOW_LST_FLOOR_NS;
		else
			rem -= delta;
		t->remain_ns = flow_lst_clamp_rem(rem);
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
	t->home_cpu = -1;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);
		if (!flow_llc_ok(qllc))
			qllc = 0;
		if (owner < 0 || !flow_cpu_allowed(owner, p) || !flow_cpu_live((u32)owner)) {
			flow_kick_idle_only(owner, p, qllc);
			return;
		}
		flow_kick_idle_only(owner, p, qllc);
		flow_stat_inc(qllc, 13);
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
	t->slice_rem = (u64)FLOW_SLICE_MIN_NS;
	if (!t->cgrp_id) {
		struct cgroup *cg = scx_bpf_task_cgroup(p);

		/* The kfunc hands back a reference, drop it after the read. */
		if (cg) {
			t->cgrp_id = flow_cgroup_cgid(cg);
			t->cg_weight = flow_cgroup_lookup(t->cgrp_id);
			bpf_cgroup_release(cg);
		}
	}
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
	t->prio = (u32)FLOW_PRIO_NORM;
	t->remain_ns = (u64)FLOW_LST_INIT_NS;
	t->enq_ns = 0;
	t->lat_kind = (u32)FLOW_LAT_UNKNOWN;
	t->home_cpu = -1;
	t->deadline_ns = 0;
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
	t->slice_rem = 0;
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
	t->prio = (u32)FLOW_PRIO_NORM;
	t->cgrp_id = cgid;
	t->cg_weight = flow_cgroup_lookup(cgid);
	t->remain_ns = (u64)FLOW_LST_INIT_NS;
	t->enq_ns = 0;
	t->lat_kind = (u32)FLOW_LAT_UNKNOWN;
	t->home_cpu = -1;
	t->deadline_ns = 0;
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
	flow_wait_allow = 1;
	flow_home_stick = 1;
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
		 * balanced drains and a small imbalance cap. */
		dhq = (scx_dhq_t *)scx_dhq_create_balanced(false, 256ULL,
							   (u64)SCX_DHQ_MODE_BALANCED, 8ULL);
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
