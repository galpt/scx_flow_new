// SPDX-License-Identifier: GPL-2.0
/*
 * Flow task lifecycle and init.
 *
 * Init seeds the CPU view counts, the per LLC node index, and one
 * queue per LLC plus the fallback queue. Running snapshots the
 * task for the preempt compare and clears the queued flag.
 * Stopping records the yield bit, steps the streak, counts runnable
 * stops, samples the frequency hint, and scores the burn. Tick
 * refreshes the remaining slice. Select keeps the pick inside the
 * mask and the live range. Mask changes keep the queue and wake
 * the owner. Cgroup hooks track weight shares with fail open
 * reads as default. Hotplug needs a restart since tables are
 * seeded once.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_LIFECYCLE_BPF_H
#define __FLOW_LIFECYCLE_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "vtime.bpf.h"
#include "cgroup.bpf.h"
#include "freq.bpf.h"
#include "preempt.bpf.h"

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
	if (n + want + 1 > 4096ULL) {
		scx_bpf_error("queue count over bound");
		return -E2BIG;
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u64 dsq;
		s32 ret;
		if ((u64)llc >= want)
			break;
		dsq = flow_llc_dsq(llc);
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
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	/* One node index per LLC for drain order. The first CPU found */
	/* on the LLC lends its node. */
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 c;
		if ((u64)llc >= want)
			break;
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			struct flow_cpu_ctx *cc;
			u32 key = c;
			if ((u64)c >= n)
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

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;
	s64 v;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	v = (s64)p->scx.dsq_vtime;
	t->vtime = v;
	t->deadline = flow_vtime_add_slice(v);
	t->slice_rem = (u64)FLOW_SLICE_NS;
	t->gen = 0;
	t->llc_id = 0;
	t->flags = 0;
	t->hist3 = 0;
	t->pad[0] = 0;
	t->pad[1] = 0;
	t->pad[2] = 0;
	t->enq_ns = 0;
	/* History starts empty and reads as a hog, so a new task */
	/* proves latency with early yields first. */
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
	} else {
		if (flow_llc_ok(t->llc_id))
			llc = t->llc_id;
	}
	sl = p->scx.slice;
	/* Clamp keeps the award length while a bad read falls back */
	/* to one slice. Stopping and tick share the same clamp. */
	if (!sl)
		sl = (u64)FLOW_SLICE_NS;
	else if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = t->vtime;
	rs->deadline = t->deadline;
	rs->slice_rem = sl;
	rs->llc_id = llc;
	rs->gen = ng;
	/* A pinned start clears the hold since the wait reached the */
	/* CPU. A start with an old enqueue steps the hold down one, */
	/* while a recent requeue keeps it for consecutive full burns. */
	/* A tall hold clamps to twice the streak bound. The latency */
	/* flag follows the history with pinned always zero, so the */
	/* kick compares shifted keys on both sides with no lookup. An */
	/* old wait that steps the hold down counts a rescue. */
	if (flow_is_pinned(p)) {
		rs->hog_streak = 0;
		rs->lat = 0;
	} else {
		u32 cap = (u32)FLOW_STREAK_MAX * 2U;
		u64 enq = READ_ONCE(t->enq_ns);
		u64 now = bpf_ktime_get_ns();
		rs->lat = flow_hist_is_lat(t->hist3) ? 1 : 0;
		if (rs->hog_streak > cap)
			rs->hog_streak = cap;
		if (enq && now > enq) {
			u64 age = now - enq;
			if (age > (u64)FLOW_SLICE_NS * 4ULL) {
				if (rs->hog_streak > 0) {
					rs->hog_streak -= 1;
					flow_stat_inc(llc, 18);
				}
			}
		}
	}
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	/* Send the smoothed hint for this CPU only. */
	flow_freq_apply(task_cpu);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 sl;
	bool voluntary;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	/* One snapshot serves the score path below. Pinned and */
	/* exiting tasks bypass score effects. */
	voluntary = !runnable && sl > 0;
	t->slice_rem = sl;
	/* A stop with remain records an early yield, a full burn */
	/* records zero. Fresh zero reads as a hog. */
	t->hist3 = flow_hist_push(t->hist3, sl == 0 ? 0 : 1);
	rs = &flow_running_state[cpu];
	rs->slice_rem = sl;
	/* The step runs on the stop edge only with one add per run. */
	/* A full burn steps the hold by the award length capped at */
	/* twice the streak bound. A clean stop steps it down one. The */
	/* tick keeps remain with no step, so one burn never counts */
	/* twice. */
	if (sl == 0) {
		u32 s = rs->hog_streak;
		u32 cap = (u32)FLOW_STREAK_MAX * 2U;
		u64 step = 1;

		if (t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
			step = (u64)t->pad[0];
		if (s < cap) {
			u64 next = (u64)s + step;

			if (next > (u64)cap)
				next = (u64)cap;
			rs->hog_streak = (u32)next;
		}
	} else {
		if (rs->hog_streak > 0)
			rs->hog_streak -= 1;
	}
	/* A stop that leaves the task runnable waits elsewhere, which */
	/* covers preemptions plus slice expiry plus migrations. Count */
	/* it on the cached LLC with no time shift. An invalid cache */
	/* falls back to zero. */
	if (runnable) {
		u32 bllc = READ_ONCE(t->llc_id);

		if (!flow_llc_ok(bllc))
			bllc = 0;
		flow_stat_inc(bllc, 11);
	}
	/* Burnt nanos over wall feed the smoothed level. */
	if ((u64)FLOW_SLICE_NS >= sl)
		flow_freq_sample(cpu, (u64)FLOW_SLICE_NS - sl);
	else
		flow_freq_sample(cpu, 0);
	/* Pinned and exiting tasks never take a score here. Voluntary */
	/* stops and empty waits decay. A full awarded burn with a top */
	/* raw step grows, all else decays. Latency history feeds the */
	/* queue key only, never the score, so a latency task still */
	/* needs a full burn for growth. */
	{
		bool is_pinned = flow_is_pinned(p);
		bool is_exiting = (p->flags & PF_EXITING) != 0;
		struct flow_extra_state *es;
		u64 old;
		u64 now_s;
		u64 enq;
		u64 q_src = 1;
		if (!is_pinned && !is_exiting) {
			es = &flow_extra_state[cpu];
			/* The pad carries the last award length, so the */
			/* burn accounts against the slice just run. */
			if (t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
				q_src = (u64)t->pad[0];
			if (es->n_growth == 0 && es->n_decay == 0) {
				old = 0;
			} else {
				old = es->score;
				if (old > (u64)FLOW_SCORE_HMAX)
					old = (u64)FLOW_SCORE_HMAX;
			}
			enq = READ_ONCE(t->enq_ns);
			if (voluntary) {
				now_s = flow_score_decay(old);
				if (es->n_decay < 0xffffffffffffffffULL)
					es->n_decay += 1;
			} else if (!enq) {
				now_s = flow_score_decay(old);
				if (es->n_decay < 0xffffffffffffffffULL)
					es->n_decay += 1;
			} else {
				u64 used;
				u64 raw;
				u64 denom = q_src * (u64)FLOW_SLICE_NS;
				/* The q bound keeps the product small and */
				/* the guard saturates on overflow. Remain */
				/* past the award keeps used at zero. */
				if (denom / (u64)FLOW_SLICE_NS != q_src)
					denom = (u64)0xffffffffffffffffULL;
				if (denom >= sl)
					used = denom - sl;
				else
					used = 0;
				/* Zero through four steps with only the top */
				/* step at full taking growth. Used stays at */
				/* or below three slices, so used times four */
				/* cannot overflow. */
				raw = 0;
				if (denom)
					raw = used * (u64)FLOW_SCORE_RAW_MAX / denom;
				if (raw > (u64)FLOW_SCORE_RAW_MAX)
					raw = (u64)FLOW_SCORE_RAW_MAX;
				if (raw == (u64)FLOW_SCORE_RAW_MAX) {
					now_s = flow_score_growth(old);
					if (es->n_growth < 0xffffffffffffffffULL)
						es->n_growth += 1;
				} else {
					now_s = flow_score_decay(old);
					if (es->n_decay < 0xffffffffffffffffULL)
						es->n_decay += 1;
				}
			}
			if (now_s > (u64)FLOW_SCORE_HMAX)
				now_s = (u64)FLOW_SCORE_HMAX;
			es->score = now_s;
		}
	}
}

void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_running_state *rs;
	u64 sl;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	rs->slice_rem = sl;
	/* The stop edge owns the one add per run, so a burn that */
	/* ticks at zero remain then stops never counts twice. A mid */
	/* slice tick keeps the hold since only a clean stop decays. */
}

void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	(void)deq_flags;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
}

/**
 * flow_select_cpu - pick a CPU for a waking task.
 * @p: waking task.
 * @prev_cpu: CPU it ran on before.
 * @wake_flags: wakeup flags from the kernel.
 *
 * The hint and the pick stay inside the mask and the live range.
 * A stale hint falls back to the first allowed live CPU before the
 * shared pick, and a stale pick falls back the same way after.
 *
 * Returns: the picked CPU.
 */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	s32 eff_prev;
	s32 picked;
	s32 first;

	if (!p || !p->cpus_ptr)
		return prev_cpu;
	first = flow_first_allowed(p);
	eff_prev = prev_cpu;
	if (eff_prev < 0 || !flow_cpu_live((u32)eff_prev) || !flow_cpu_allowed(eff_prev, p)) {
		if (first >= 0)
			eff_prev = first;
		else
			return prev_cpu;
	}
	picked = scx_bpf_select_cpu_dfl(p, eff_prev, wake_flags, &idle);
	if (picked < 0 || !flow_cpu_live((u32)picked) || !flow_cpu_allowed(picked, p)) {
		if (first >= 0)
			return first;
		return eff_prev;
	}
	return picked;
}

/**
 * flow_set_cpumask - track a mask change.
 * @p: task whose mask changed.
 * @cpumask: new mask, unused beyond the hook itself.
 *
 * Keeps virtual time, deadline, generation, and queued state with
 * no fresh assign. A queued task keeps its queue and wakes the new
 * owner: pinned through the fast path, shared through the
 * constrained path with the latency key. The orphan count lands
 * only on a live allowed kick. An unqueued task reclamps its cached
 * LLC. Exiting tasks keep the minimal slice.
 */
void BPF_STRUCT_OPS(flow_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct flow_task_ctx *t;
	s32 tgt;
	u32 cpu;
	struct flow_cpu_ctx *cc;
	u32 llc;

	(void)cpumask;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);
		s64 hv;
		bool pinned = flow_is_pinned(p);
		int olat = 0;

		if (!flow_llc_ok(qllc))
			qllc = 0;
		hv = READ_ONCE(t->vtime);
		/* The kick boosts the running side from its flag, so */
		/* shift the raw stored time here for the waiter side. */
		/* Stored time stays raw. One pinned test serves the key */
		/* and the kick below. A latency preempt win counts with */
		/* the class already in hand. */
		if (!pinned)
			olat = flow_hist_is_lat(READ_ONCE(t->hist3)) ? 1 : 0;
		if (olat)
			hv = flow_vtime_boost(hv, 1);
		/* No queue rewrite, so accounting stays on the enqueue */
		/* LLC. A race that loses the owner between check and kick */
		/* stays a small stats skew with no move. */
		if (owner < 0 || !flow_cpu_allowed(owner, p) ||
		    !flow_cpu_live((u32)owner)) {
			flow_kick_constrained(owner, hv, p, qllc);
			return;
		}
		if (pinned)
			flow_kick_pinned(owner, hv, p, qllc);
		else if (flow_kick_constrained(owner, hv, p, qllc) && olat)
			flow_stat_inc(qllc, 17);
		flow_stat_inc(qllc, 13);
		return;
	}
	if (p->flags & PF_EXITING)
		t->slice_rem = (u64)FLOW_EXIT_SLICE_NS;
	tgt = flow_first_allowed(p);
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

/**
 * flow_cgroup_init - seed one weight entry.
 * @cgrp: cgroup being created.
 * @args: init args carrying the weight.
 *
 * Every path returns zero so shares never abort creation. A full
 * map reads as default. The live enqueue lookup heals a reversed
 * start with no sticky default.
 *
 * Returns: always zero.
 */
s32 BPF_STRUCT_OPS(flow_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	u64 cgid;
	u64 w;
	if (!cgrp || !args)
		return 0;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return 0;
	w = (u64)flow_cgroup_clamp(args->weight);
	(void)bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
	return 0;
}

/**
 * flow_cgroup_exit - drop the weight entry.
 * @cgrp: cgroup going away.
 *
 * A reused id never reads a stale share.
 */
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	bpf_map_delete_elem(&cgrp_weight_stor, &cgid);
}

/**
 * flow_cgroup_set_weight - track a weight change.
 * @cgrp: cgroup.
 * @weight: new weight.
 *
 * Update creates, so a set before init still lands. Values clamp
 * into range.
 */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgid;
	u64 w;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	w = (u64)flow_cgroup_clamp(weight);
	bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
}

/**
 * flow_cgroup_move - cache the destination share on a task.
 * @p: moving task.
 * @from: source cgroup, unused.
 * @to: destination cgroup, may be NULL.
 *
 * Null destination keeps defaults. Storage is created on miss.
 * Enqueue reads the live map by id, so the cache is a hint only.
 */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct flow_task_ctx *t;
	u64 cgid;
	(void)from;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	if (!to) {
		t->cgrp_id = 0;
		t->cg_weight = (u32)FLOW_CGROUP_WEIGHT_DFLT;
		return;
	}
	cgid = flow_cgroup_cgid(to);
	t->cgrp_id = cgid;
	t->cg_weight = flow_cgroup_lookup(cgid);
}

/**
 * flow_init_task - seed the task weight cache.
 * @p: new task.
 * @args: init args carrying the birth cgroup, may be NULL.
 *
 * Null cgroup keeps defaults. The live enqueue lookup heals a task
 * born before its cgroup weight lands.
 *
 * Returns: zero, or minus ENOMEM when storage fails.
 */
s32 BPF_STRUCT_OPS(flow_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;
	u64 cgid = 0;
	if (!p)
		return 0;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return -ENOMEM;
	if (args && args->cgroup)
		cgid = flow_cgroup_cgid(args->cgroup);
	t->cgrp_id = cgid;
	t->cg_weight = flow_cgroup_lookup(cgid);
	return 0;
}

#endif
