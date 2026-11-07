// SPDX-License-Identifier: GPL-2.0
/*
 * Placement for the flow scheduler.
 *
 * The pick first tries the previous CPU when it is allowed and
 * online. Otherwise it scans the seed view once and prefers the
 * same LLC, then the same node, then a distant CPU. Ties keep the
 * first CPU in fixed order. Within the same LLC the scan favors
 * the same cluster, with the tie favor kept even when threads
 * share cores and only the fast pick gated on single threads.
 * A task that already ran favors its first CPU
 * on ties. When no hint is usable, CPUs on the primary node are
 * preferred and a miss falls back to the scan. No sibling probe
 * runs and each CPU stands single with fail closed choice. Every
 * check returns minus one on failure. Masks are tested again before
 * each wake, so a task is never kicked toward a CPU outside its
 * current mask. Frequency stays with the governor and never steers
 * placement. The pick stores a provisional wait kind from the
 * last queue choice with pinned tasks keeping the pinned kind.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SELECT_BPF_H
#define __FLOW_SELECT_BPF_H
#include "intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "lat.bpf.h"
static __always_inline bool flow_is_pinned(struct task_struct *p)
{
	if (!p)
		return false;
	if (p->nr_cpus_allowed == 1)
		return true;
	return is_migration_disabled(p);
}
static __always_inline bool flow_cpu_allowed(s32 cpu, struct task_struct *p)
{
	u32 c;
	if (!p || !p->cpus_ptr)
		return false;
	if (cpu < 0)
		return false;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return false;
	return bpf_cpumask_test_cpu(c, p->cpus_ptr);
}
static __always_inline bool flow_cpu_live(u32 cpu)
{
	u64 n;
	if (!flow_cpu_ok(cpu))
		return false;
	n = READ_ONCE(flow_nr_cpus);
	if (n && (u64)cpu >= n)
		return false;
	return true;
}
static __always_inline s32 flow_first_allowed(struct task_struct *p)
{
	u32 first;
	if (!p || !p->cpus_ptr)
		return -1;
	first = bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_live(first))
		return -1;
	if (!flow_cpu_allowed((s32)first, p))
		return -1;
	return (s32)first;
}
static __always_inline s32 flow_constrained_target(s32 hint, struct task_struct *p)
{
	if (!p || !p->cpus_ptr)
		return -1;
	if (hint >= 0 && flow_cpu_allowed(hint, p) && flow_cpu_live((u32)hint))
		return hint;
	return flow_first_allowed(p);
}
static __always_inline bool flow_is_primary(u32 node)
{
	return node == 0;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 hint = prev_cpu;
	s32 tgt;
	u32 hint_llc = 0;
	u32 hint_node = 0;
	u32 hint_ccx = 0;
	bool have_hint_topo = false;
	s32 best = -1;
	int best_score = 99;
	bool best_same = false;
	bool best_home = false;
	s32 home = -1;
	bool use_home = false;
	bool use_ccx;
	bool smt_on;
	u32 c;
	u64 nr = READ_ONCE(flow_nr_cpus);
	struct flow_task_ctx *t;
	(void)wake_flags;
	if (!p)
		return hint;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (t) {
		int pinned = flow_is_pinned(p) ? 1 : 0;
		u32 pk = READ_ONCE(t->prio);
		flow_lat_store(t, pk, pinned);
		if (READ_ONCE(flow_home_stick)) {
			s32 h = READ_ONCE(t->home_cpu);
			if (h >= 0 && flow_cpu_allowed(h, p) && flow_cpu_live((u32)h))
				home = h;
			if (home >= 0)
				use_home = true;
		}
	}
	use_ccx = READ_ONCE(flow_ccx_prefer) ? true : false;
	smt_on = READ_ONCE(flow_smt_enabled) ? true : false;
	tgt = flow_constrained_target(hint, p);
	if (tgt >= 0)
		return tgt;
	{
		u32 key;
		struct flow_cpu_ctx *cc;
		if (hint >= 0 && flow_cpu_ok((u32)hint)) {
			key = (u32)hint;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (cc) {
				u32 l = READ_ONCE(cc->llc_id);
				u32 n = READ_ONCE(cc->node_id);
				if (flow_llc_ok(l) && flow_node_ok(n)) {
					hint_llc = l;
					hint_node = n;
					hint_ccx = READ_ONCE(cc->ccx_id);
					have_hint_topo = true;
				}
			}
		}
	}
	bpf_for(c, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_ctx *cc;
		u32 key = c;
		u32 l;
		u32 n;
		u32 cx;
		int score;
		if (nr && (u64)c >= nr)
			break;
		if (!flow_cpu_live(c))
			continue;
		if (!flow_cpu_allowed((s32)c, p))
			continue;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			continue;
		l = READ_ONCE(cc->llc_id);
		n = READ_ONCE(cc->node_id);
		cx = READ_ONCE(cc->ccx_id);
		if (!flow_llc_ok(l))
			continue;
		score = 3;
		if (have_hint_topo) {
			if (l == hint_llc)
				score = 0;
			else if (n == hint_node)
				score = 1;
			else
				score = 2;
			if (!smt_on && use_ccx && l == hint_llc && cx == hint_ccx)
				score = -1;
		} else if (flow_is_primary(n)) {
			score = 2;
		}
		if (score < best_score) {
			best_score = score;
			best = (s32)c;
			best_same = have_hint_topo && use_ccx && cx == hint_ccx;
			best_home = use_home && (s32)c == home;
			if (score == -1)
				break;
			if (score == 0 && (!use_ccx || best_same))
				break;
		} else if (score == best_score) {
			/* Tie favor stays even with threads on; only the fast pick is gated. */
			bool cur_same = have_hint_topo && use_ccx && cx == hint_ccx;
			bool cur_home = use_home && (s32)c == home;
			if (cur_same && !best_same) {
				best = (s32)c;
				best_same = true;
				best_home = cur_home;
				if (score == 0)
					break;
			} else if (cur_home && !best_home && cur_same == best_same) {
				best = (s32)c;
				best_home = true;
			}
		}
	}
	/* The mask can change while scanning, test the pick again. */
	if (best >= 0 && flow_cpu_allowed(best, p))
		return best;
	return flow_first_allowed(p);
}
#endif
