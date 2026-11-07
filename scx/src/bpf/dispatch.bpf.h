// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and lifecycle for the flow scheduler.
 *
 * Each CPU drains its own LLC queues first, then queues on the same
 * node, then distant queues, then fallback. Each queue drains in
 * queue order with one peek per queue and prios drain in fixed
 * order. A head that cannot run here
 * sends one wake to its owner and stays queued. Remote moves count
 * on the thief and drop the gauge on the source. Running records
 * the task snapshot and counts the enqueue to run wait. Dispatch
 * counts the enqueue to dispatch wait on the moving CPU. Stopping
 * folds burnt time into the burst estimate through the half blend
 * and charges use into the stored time with the same value
 * mirrored beside it. The tick charges the burnt delta and folds
 * it into the estimate, then moves the remaining slice forward
 * with the same value mirrored beside it, so stopping charges
 * only the tail past the last tick. Frequency stays with the
 * governor and never steers placement. Only a fixed hint that
 * never sends zero may reach the governor. A mask change on a queued
 * task keeps the queue and wakes the new owner, counting the wake
 * when the owner is usable. Init creates four queues per LLC and
 * the fallback queue and records the node of each LLC. CPUs that
 * arrive late need a restart to be seen.
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
#include "sjf.bpf.h"
#include "cgroup.bpf.h"
#include "lat.bpf.h"
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
	flow_stat_inc(llc, 14);
	flow_kick_idle_only(owner, ph, llc);
}
static __always_inline int flow_try_move(u32 cpu, u32 llc, u32 victim, u64 dsq, u32 slot, int steal)
{
	struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek(dsq);
	if (!ph)
		return 0;
	if (!flow_cpu_allowed((s32)cpu, ph)) {
		flow_forward_from_peeked(ph, llc, slot);
		return 0;
	}
	if (scx_bpf_dsq_move_to_local(dsq, 0)) {
		struct flow_task_ctx *lt = bpf_task_storage_get(&task_ctx_stor, ph, 0, 0);
		if (lt)
			flow_lat_observe(cpu, lt, scx_bpf_now(), 0);
		flow_stat_inc(llc, 1);
		flow_queued_dec(victim);
		if (steal) {
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 5);
		}
		return 1;
	}
	return 0;
}
static __always_inline int flow_drain_llc(u32 cpu, u32 llc, u32 victim, int steal)
{
	u32 pr;
	for (pr = 0; pr < (u32)FLOW_PRIO_COUNT; pr++) {
		u64 dsq = flow_llc_dsq_prio(victim, pr);
		u32 slot = victim;
		if (!flow_dsq_ok(dsq))
			continue;
		if (slot > (u32)FLOW_MAX_LLCS)
			slot = (u32)FLOW_MAX_LLCS;
		if (flow_try_move(cpu, llc, victim, dsq, slot, steal))
			return 1;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 node = 0;
	u32 li;
	(void)prev;
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return;
	{
		u32 key = c;
		struct flow_cpu_ctx *cc;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			return;
		{
			u32 tmp = READ_ONCE(cc->llc_id);
			if (!flow_llc_ok(tmp))
				return;
			llc = tmp;
		}
		node = READ_ONCE(cc->node_id);
		if (!flow_node_ok(node))
			node = 0;
	}
	if (flow_drain_llc(c, llc, llc, 0))
		return;
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u32 nd;
		if (li == llc)
			continue;
		if ((u64)li >= READ_ONCE(flow_nr_llcs))
			break;
		if (!flow_llc_ok(li))
			continue;
		/* Node IDs are cached at init, no per-CPU walk here. */
		nd = READ_ONCE(flow_llc_node[li]);
		if (!flow_node_ok(nd))
			continue;
		if (nd != node)
			continue;
		if (flow_drain_llc(c, llc, li, 1))
			return;
	}
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u32 nd;
		if (li == llc)
			continue;
		if ((u64)li >= READ_ONCE(flow_nr_llcs))
			break;
		if (!flow_llc_ok(li))
			continue;
		nd = READ_ONCE(flow_llc_node[li]);
		if (flow_node_ok(nd) && nd == node)
			continue;
		if (flow_drain_llc(c, llc, li, 1))
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
							if ((u64)li >= READ_ONCE(flow_nr_llcs))
								break;
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
	struct flow_cpu_ctx *cc;
	u32 llc = 0;
	u32 key;
	struct flow_running_state *rs;
	u64 sl;
	u64 ng;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	key = cpu;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (cc) {
		u32 tmp = READ_ONCE(cc->llc_id);
		if (flow_llc_ok(tmp))
			llc = tmp;
	} else if (flow_llc_ok(t->llc_id)) {
		llc = t->llc_id;
	}
	sl = p->scx.slice;
	if (!sl)
		sl = (u64)FLOW_SLICE_MIN_NS;
	else if (sl > (u64)FLOW_SLICE_MIN_NS * 3)
		sl = (u64)FLOW_SLICE_MIN_NS * 3;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = t->vtime;
	rs->slice_rem = sl;
	rs->gen = ng;
	rs->llc_id = llc;
	rs->prio = t->prio;
	rs->reserved = 0;
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	/* The stored time did not move, refresh the mirror beside it. */
	scx_bpf_task_set_dsq_vtime(p, t->vtime);
	flow_lat_observe(cpu, t, scx_bpf_now(), 1);
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
	u64 est;
	(void)runnable;
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
	est = flow_sjf_next(t->burst_ns, used ? used : (u64)FLOW_SJF_FLOOR_NS);
	/* Pinned tasks keep the same fold with no separate path. */
	t->burst_ns = est;
	/* Use pays here, scaled by the share with saturation. The tick
	 * already moved the remaining slice forward, so this charges
	 * only the tail past the last tick. */
	if (used) {
		u64 cgid = READ_ONCE(t->cgrp_id);
		s64 nv = flow_fair_charge(t->vtime, used, flow_cgroup_lookup(cgid));
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
	/* Charge the burnt delta and fold it into the estimate, then move
	 * the remaining slice forward, so stopping later charges only
	 * the tail past this tick. */
	last = READ_ONCE(t->slice_rem);
	if (cur && cur < last) {
		u64 delta = last - cur;
		u64 cgid = READ_ONCE(t->cgrp_id);
		s64 nv = flow_fair_charge(t->vtime, delta, flow_cgroup_lookup(cgid));
		t->vtime = nv;
		t->burst_ns = flow_sjf_next(t->burst_ns, delta);
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
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
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
		u32 cpu;
		struct flow_cpu_ctx *cc;
		u32 llc;
		if (tgt < 0)
			return;
		if (!flow_cpu_live((u32)tgt))
			return;
		cpu = (u32)tgt;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
		if (!cc)
			return;
		llc = READ_ONCE(cc->llc_id);
		if (!flow_llc_ok(llc))
			return;
		t->llc_id = llc;
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
	t->burst_ns = (u64)FLOW_SJF_INIT_NS;
	t->enq_ns = 0;
	t->lat_kind = (u32)FLOW_LAT_UNKNOWN;
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
	t->burst_ns = (u64)FLOW_SJF_INIT_NS;
	t->enq_ns = 0;
	t->lat_kind = (u32)FLOW_LAT_UNKNOWN;
	scx_bpf_task_set_dsq_vtime(p, 0);
	return 0;
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u64 want = 0;
	s32 cpu;
	u32 llc;
	n = scx_bpf_nr_cpu_ids();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	flow_nr_cpus = n;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u32 key;
		struct flow_cpu_ctx *cc;
		u32 id;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		key = (u32)cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			continue;
		id = READ_ONCE(cc->llc_id);
		if (!flow_llc_ok(id))
			continue;
		if ((u64)id + 1 > want)
			want = (u64)id + 1;
	}
	if (want == 0)
		want = 1;
	if (want > (u64)FLOW_MAX_LLCS) {
		scx_bpf_error("LLC count over bound");
		return -E2BIG;
	}
	flow_nr_llcs = want;
	if (n + want * (u64)FLOW_PRIO_COUNT + 1 > 4096ULL) {
		scx_bpf_error("queue count over bound");
		return -E2BIG;
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 pr;
		if ((u64)llc >= want)
			break;
		for (pr = 0; pr < (u32)FLOW_PRIO_COUNT; pr++) {
			u64 dsq = flow_llc_dsq_prio(llc, pr);
			s32 ret;
			if (!flow_dsq_ok(dsq)) {
				scx_bpf_error("dsq id over bound");
				return -EINVAL;
			}
			ret = scx_bpf_create_dsq(dsq, -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("dsq create failed");
				return ret;
			}
		}
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 c2;
		if ((u64)llc >= want)
			break;
		bpf_for(c2, 0, FLOW_MAX_CPUS) {
			struct flow_cpu_ctx *cc;
			u32 key = c2;
			if ((u64)c2 >= n)
				break;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (!cc)
				continue;
			if (READ_ONCE(cc->llc_id) == llc) {
				u32 node = READ_ONCE(cc->node_id);
				if (flow_node_ok(node))
					flow_llc_node[llc] = node;
				break;
			}
		}
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
#endif
