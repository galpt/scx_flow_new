// SPDX-License-Identifier: GPL-2.0
/*
 * Flat hint helpers for the core.
 *
 * Holds the id plus level plus ancestor helpers for the flat hint
 * view. The flat view tunes the period plus the weight only with single
 * weighting, and no group or pool shapes order. Id zero scopes to
 * defaults with no row. A zero cached id is the stale sentinel with miss
 * to the acquire path. The pid cache stays ABA safe via clear on migrate
 * plus enable plus disable plus exit, so a reused pid never reads a
 * stale id. The cache caps at 2048 entries with fail to the acquire
 * path and no eviction. Runs inline with no walk past one ancestor
 * step, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Id of one hierarchy with root at one on missing. */
/* Runs on an acquired or ops trusted pointer with a held view, */
/* so the node read stays valid. A missing pointer means the root, */
/* so the id stays one. */
static __always_inline u64 flow_cgrp_id(
	struct cgroup *cgrp)
{
	struct kernfs_node *kn;
	u64 id;
	if (!cgrp)
		return 1;
	kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return 1;
	id = BPF_CORE_READ(kn, id);
	if (!id)
		return 1;
	return id;
}
/* Clear one cached hierarchy id for a pid with no fail. */
/* Runs on migrate plus move plus enable plus disable plus task exit */
/* for ABA safety, so a reused pid never reads a stale id. A zero pid */
/* never caches, so it needs no clear. */
static __always_inline void flow_cgrp_cache_invalidate(u32 pid)
{
	if (!pid)
		return;
	bpf_map_delete_elem(&cgrp_cache_stor, &pid);
}
/* Hint of one task from its hierarchy with paired release. */
/* Reads the cached id first with one hash lookup and no acquire, so */
/* the hot path pays no hierarchy cost on hit. The pid cache caps at */
/* 2048 entries with fail to the acquire path and no eviction, so a */
/* full table still reads fresh with no stall. A miss takes the */
/* acquire path once and fills the cache best effort, so later joins */
/* hit with no walk. The flat row still reads fresh each time, so a */
/* weight change shows at once with no cache clear. A null hierarchy */
/* means the root, so the default period applies with no hint use. */
static __always_inline u32 flow_task_hint(
	struct task_struct *p)
{
	u32 pid = (u32)p->pid;
	u64 *cached;
	u64 id;
	u32 hint;
	if (pid) {
		cached = bpf_map_lookup_elem(&cgrp_cache_stor,
		    &pid);
		if (cached && *cached)
			return flow_hint_us(*cached);
	}
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (!cgrp)
			return 0;
		id = flow_cgrp_id(cgrp);
		flow_cgrp_put(cgrp);
		if (pid)
			bpf_map_update_elem(&cgrp_cache_stor,
			    &pid, &id, BPF_ANY);
		hint = flow_hint_us(id);
		return hint;
	}
}
/* Hint plus weight of one task with one cache plus one row read. */
/* Single fast path for fresh enqueues that need both values, so the */
/* hot path pays one cache lookup plus one hint row read instead of */
/* two of each with no behavior change. A null hierarchy means the */
/* root, so the default period plus neutral share apply. Requeues */
/* plus stopping plus leftover reuse the stored hint weight in task */
/* state with no lookup, so slice rotation keeps the heavy share with */
/* no neutral cliff and no acquire. */
static __always_inline void flow_task_hint_weight(
	struct task_struct *p, u32 *hint_us, u32 *weight)
{
	u32 pid = (u32)p->pid;
	u64 *cached;
	u64 id;
	struct flow_hint *h;
	if (hint_us)
		*hint_us = 0;
	if (weight)
		*weight = (u32)FLOW_WEIGHT_BASE;
	if (!p)
		return;
	if (pid) {
		cached = bpf_map_lookup_elem(&cgrp_cache_stor,
		    &pid);
		if (cached && *cached) {
			id = *cached;
			h = bpf_map_lookup_elem(&hint_stor, &id);
			if (!h)
				return;
			if (hint_us)
				*hint_us = READ_ONCE(h->period_us);
			if (weight) {
				u32 w = READ_ONCE(h->weight);
				*weight = w ? flow_weight_clamp(w) :
				    (u32)FLOW_WEIGHT_BASE;
			}
			return;
		}
	}
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (!cgrp)
			return;
		id = flow_cgrp_id(cgrp);
		flow_cgrp_put(cgrp);
		if (pid)
			bpf_map_update_elem(&cgrp_cache_stor,
			    &pid, &id, BPF_ANY);
		h = bpf_map_lookup_elem(&hint_stor, &id);
		if (!h)
			return;
		if (hint_us)
			*hint_us = READ_ONCE(h->period_us);
		if (weight) {
			u32 w = READ_ONCE(h->weight);
			*weight = w ? flow_weight_clamp(w) :
			    (u32)FLOW_WEIGHT_BASE;
		}
	}
}
