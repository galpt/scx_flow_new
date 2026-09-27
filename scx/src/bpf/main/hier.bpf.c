// SPDX-License-Identifier: GPL-2.0
/*
 * Hierarchy share helpers for the core.
 *
 * Holds the hint ring plus flag plus identity plus share walk over
 * depth 8 with miss default. The share walk stays noinline with a
 * trusted pointer and no duplicate walk, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Record one parked chain of 8 ancestor ids with the leaf first. */
/* Uses a wrapping counter with one map update, so concurrent parks */
/* never tear and an overwrite only drops an older chain with the */
/* enqueue refill covering active groups. Outlined to keep the */
/* throttle and timer paths small. */
static __noinline void flow_hint_chain(u64 ids[8])
{
	u64 idx;
	u32 key;
	struct flow_park_chain chain;
	int i;
	bpf_for(i, 0, 8) {
		if ((u64)i >= (u64)FLOW_CGRP_DEPTH_MAX)
			break;
		chain.ids[i] = ids[i];
	}
	idx = __sync_fetch_and_add(&flow_hint_idx, 1);
	key = (u32)(idx % (u64)FLOW_PARK_HINT_NR);
	bpf_map_update_elem(&park_hint, &key, &chain, BPF_ANY);
}
/* Relaxed load of one hierarchy flags to match the flag stores. */
/* Pairs with the set and clear stores with no torn read. */
static __always_inline u32 flow_load_flags(
	struct flow_cgrp_ctx *e)
{
	return READ_ONCE(e->flags);
}
/* Set the throttle bit on one hierarchy entry with one try. */
/* Uses one compare and swap, so concurrent sets never tear. A lost */
/* try leaves the bit to the winner with no stall. */
static __always_inline void flow_flag_set(
	struct flow_cgrp_ctx *e)
{
	u32 cur = flow_load_flags(e);
	u32 want;
	if (cur & (u32)FLOW_CGRP_THROTTLED)
		return;
	want = cur | (u32)FLOW_CGRP_THROTTLED;
	__sync_val_compare_and_swap(&e->flags, cur, want);
}
/* Clear the throttle bit on one hierarchy entry with one try. */
/* Uses one compare and swap, so concurrent clears never tear. */
static __always_inline void flow_flag_clear(
	struct flow_cgrp_ctx *e)
{
	u32 cur = flow_load_flags(e);
	u32 want;
	if (!(cur & (u32)FLOW_CGRP_THROTTLED))
		return;
	want = cur & ~(u32)FLOW_CGRP_THROTTLED;
	__sync_val_compare_and_swap(&e->flags, cur, want);
}
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
/* Level of one hierarchy with root at zero on missing. */
/* Runs on an acquired or ops trusted pointer with a held view. */
/* The level never changes after creation, so the read stays valid. */
static __always_inline int flow_cgrp_level(
	struct cgroup *cgrp)
{
	if (!cgrp)
		return 0;
	return BPF_CORE_READ(cgrp, level);
}
/* Ancestor at one level with a reference and paired release. */
/* Uses the tryget lookup, so the caller releases when non null. */
/* A bad level fails closed to null with no trap. */
static __always_inline struct cgroup *flow_cgrp_ancestor(
	struct cgroup *cgrp, int level)
{
	if (!cgrp)
		return NULL;
	return bpf_cgroup_ancestor(cgrp, level);
}
/* Hierarchy share over depth 8 with miss default 100. */
/* Compounds each ancestor weight by base 100, so a light */
/* parent lowers the share. Misses use base with no trap. */
/* Depth 8 covers the nearest 8 levels from the leaf, so a deeper */
/* tree truncates the far root levels with the leaf order kept. */
/* Each ancestor carries a reference with a paired release. */
/* Outlined to keep enqueue small. */
static __noinline u32 flow_hier_weight(
	struct cgroup *cgrp)
{
	u64 hier = (u64)FLOW_CGRP_WEIGHT_DFL;
	int level;
	int i;
	if (!cgrp)
		return (u32)FLOW_CGRP_WEIGHT_DFL;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
		u32 w;
		int lvl;
		if (i > level)
			break;
		lvl = level - i;
		if (lvl < 0)
			break;
		anc = flow_cgrp_ancestor(cgrp, lvl);
		if (!anc)
			continue;
		id = flow_cgrp_id(anc);
		flow_cgrp_put(anc);
		if (!id)
			continue;
		e = flow_cgrp(id);
		if (!e)
			w = (u32)FLOW_CGRP_WEIGHT_DFL;
		else
			w = flow_weight_clamp(
			    READ_ONCE(e->weight));
		hier = hier * (u64)w / (u64)FLOW_WEIGHT_BASE;
		if (hier > (u64)FLOW_WEIGHT_MAX)
			hier = (u64)FLOW_WEIGHT_MAX;
		if (hier < (u64)FLOW_WEIGHT_MIN)
			hier = (u64)FLOW_WEIGHT_MIN;
		if (i == 0 && lvl == 0)
			break;
	}
	return (u32)hier;
}
