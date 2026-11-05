// SPDX-License-Identifier: GPL-2.0
/*
 * Flow task lifecycle plus init with cgroup shares.
 *
 * Moved from main with additive weight hooks only. Single ownership
 * through the queued flag is unchanged. Freq hint is neutral for
 * placement. Hotplug needs restart, same risk as the pinned path.
 * Unknown weights read as default with 5.0.8 behavior. Stats stay
 * frozen with no new counter for shares.
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

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u64 want = 0;
	s32 cpu;
	u32 llc;
	TOUCH_ARENA();
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
	if (want <= 1)
		return 0;
	/* Size the static area before the first pair queue use. */
	/* The pair queue draws from this area so it must be ready first. */
	/* Eight pages hold 32KiB. One pair with cap n times 4 needs the */
	/* queue header plus two heaps plus cap times 16 bytes of entries. */
	/* A 16 CPU host needs about one KiB per pair and fits with margin. */
	/* Overflow takes a fresh block and leaves old pages mapped, so an */
	/* oversize host still fails closed with no reuse. Single LLC above */
	/* uses only DSQs and creates no pair, so skipping init there is by */
	/* design. Enqueue and dispatch guard every pair use on more than one */
	/* LLC, so a future static user must move this init above that return. */
	{
		int ret = scx_static_init(8);
		if (ret) {
			scx_bpf_error("static init failed");
			return ret;
		}
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 node = 0;
		u32 cnt;
		u64 strand;
		u64 idx;
		u64 cap;
		bool first = false;
		u32 c;
		u64 got = (u64)-1;
		if ((u64)llc >= want)
			break;
		first = false;
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			struct flow_cpu_ctx *cc;
			u32 key = c;
			if ((u64)c >= n)
				break;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (!cc)
				continue;
			if (READ_ONCE(cc->llc_id) == llc) {
				node = READ_ONCE(cc->node_id);
				first = true;
				break;
			}
		}
		if (!first)
			node = 0;
		if (!flow_node_ok(node)) {
			scx_bpf_error("node over bound");
			return -EINVAL;
		}
		cnt = flow_node_count[node];
		strand = (u64)(cnt % 2);
		if (strand == (u64)SCX_DHQ_STRAND_A) {
			idx = flow_pair_count;
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			cap = n * 4;
			if (cap < 8)
				cap = 8;
			got = scx_dhq_create_balanced(false, cap,
						      SCX_DHQ_MODE_PRIORITY,
						      (u64)FLOW_DHQ_MAX_IMBALANCE);
			if (!got) {
				scx_bpf_error("pair create failed");
				return -ENOMEM;
			}
			flow_pair_dhqs[idx] = (scx_dhq_t *)got;
			if (idx < (u64)FLOW_MAX_PAIRS)
				flow_pair_cap[(u32)idx] = cap;
			flow_pair_count += 1;
			flow_node_last_pair[node] = idx;
		} else {
			idx = flow_node_last_pair[node];
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			if (!flow_pair_dhqs[idx]) {
				scx_bpf_error("pair null for strand B");
				return -EINVAL;
			}
		}
		flow_llc_pair[llc] = idx;
		flow_llc_strand[llc] = strand;
		flow_node_count[node] = cnt + 1;
		if (idx < (u64)FLOW_MAX_PAIRS)
			flow_pair_node[(u32)idx] = node;
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
	t->strand = (u32)FLOW_STRAND_A;
	t->llc_id = 0;
	t->flags = 0;
	t->pad = 0;
	/* Cgroup tail stays. Init plus move seed it, zero init reads as */
	/* default, and membership never changes on enable. */
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_cpu_ctx *cc;
	u32 llc = 0;
	u32 strand = (u32)FLOW_STRAND_A;
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
		if (flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
		if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
			u64 idx = flow_llc_pair[llc];
			if (idx < (u64)FLOW_MAX_PAIRS && flow_pair_dhqs[(u32)idx]) {
				u32 s = (u32)flow_llc_strand[llc];
				if (s == (u32)FLOW_STRAND_A || s == (u32)FLOW_STRAND_B)
					strand = s;
			}
		}
	} else {
		if (flow_llc_ok(t->llc_id))
			llc = t->llc_id;
		if (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B)
			strand = t->strand;
	}
	sl = p->scx.slice;
	if (!sl || sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = t->vtime;
	rs->deadline = t->deadline;
	rs->slice_rem = sl;
	rs->llc_id = llc;
	rs->strand = strand;
	rs->gen = ng;
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	t->strand = strand;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	/* Act at start. Send the smoothed hint for this one CPU only. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	flow_freq_apply(task_cpu);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 sl;
	(void)runnable;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	t->slice_rem = sl;
	rs = &flow_running_state[cpu];
	rs->slice_rem = sl;
	/* Sense load at stop. Burnt nanos over wall feed the smoothed level. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	if ((u64)FLOW_SLICE_NS >= sl)
		flow_freq_sample(cpu, (u64)FLOW_SLICE_NS - sl);
	else
		flow_freq_sample(cpu, 0);
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
	if (sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
	rs->slice_rem = sl;
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

/* No SMT probe runs. Each CPU stands single and a missing sibling */
/* fails closed with no move. Select stays through the shared picker. */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}

/* Seed one cgroup weight from the init args. Fires for every cgroup */
/* including root at load. Every path returns zero so a bad arg plus */
/* a missing id plus a full map never aborts cgroup creation or load. */
/* A miss reads as default with 5.0.8 behavior. Map holds 4096 entries */
/* with no eviction, so a full map also reads as default. Seeding order */
/* with init_task is documented at init_task, and the live enqueue */
/* lookup heals a reversed start with no sticky default. */
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

/* Drop the weight entry so a reused id never reads stale shares. */
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

/* Track cpu.weight changes. Update creates, so a weight set before */
/* init still lands. Clamp keeps the knob in range. */
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

/* Cache the destination weight on the moving task. Null dest keeps */
/* defaults with no move. Storage is created on miss so a task without */
/* context still caches the move, which stays sleepable safe. Enqueue */
/* reads the live map by id, so the cache is a hint only. */
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

/* Seed the task weight cache at task init. Args carry the birth */
/* cgroup the same way as flash/forge. Null cgroup keeps defaults. */
/* Cgroup init runs for every cgroup including root at load, but order */
/* against init_task before 6.12 is unverified. A task born before its */
/* cgroup weight lands reads default, and the live enqueue lookup heals */
/* on next enqueue with no sticky default. Needs 6.12 plus for the */
/* cgroup hooks, checked by the installer. Enqueue never reads this */
/* cache alone, so set_weight needs no move. */
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
