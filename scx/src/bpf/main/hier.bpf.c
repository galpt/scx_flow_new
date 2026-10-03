// SPDX-License-Identifier: GPL-2.0
/*
 * Flat hint helpers for the core.
 *
 * Holds the id plus level plus ancestor helpers for the flat hint
 * view. The flat view tunes the period plus the weight only, and no
 * group or pool shapes order. The pid cache stays ABA safe via clear
 * on migrate plus enable plus exit, so a reused pid never reads a
 * stale id. The cache caps at 1024 entries with fail to the acquire
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
/* Runs on migrate plus enable plus task exit for ABA safety, so a */
/* reused pid never reads a stale id. A zero pid never caches, so it */
/* needs no clear. */
static __always_inline void flow_cgrp_cache_invalidate(u32 pid)
{
	if (!pid)
		return;
	bpf_map_delete_elem(&cgrp_cache_stor, &pid);
}
/* Hint of one task from its hierarchy with paired release. */
/* Reads the cached id first with one hash lookup and no acquire, so */
/* the hot path pays no hierarchy cost on hit. The pid cache caps at */
/* 1024 entries with fail to the acquire path and no eviction, so a */
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
/* Weight of one task from its hierarchy with paired release. */
/* Follows the same cached id path as the hint with uniform handling */
/* for cgroup plus root tasks, so every task earns a clamped share with */
/* no special case. A null hierarchy means the root, so the neutral */
/* share applies with no hint use. Requeues reuse the stored weight */
/* with no acquire, so slice rotation pays no hierarchy cost. */
static __always_inline u32 flow_task_weight(
	struct task_struct *p)
{
	u32 pid = (u32)p->pid;
	u64 *cached;
	u64 id;
	if (pid) {
		cached = bpf_map_lookup_elem(&cgrp_cache_stor,
		    &pid);
		if (cached && *cached)
			return flow_hint_weight(*cached);
	}
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (!cgrp)
			return (u32)FLOW_WEIGHT_BASE;
		id = flow_cgrp_id(cgrp);
		flow_cgrp_put(cgrp);
		if (pid)
			bpf_map_update_elem(&cgrp_cache_stor,
			    &pid, &id, BPF_ANY);
		return flow_hint_weight(id);
	}
}
