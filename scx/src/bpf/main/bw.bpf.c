// SPDX-License-Identifier: GPL-2.0
/*
 * Bandwidth pool helpers for the core.
 *
 * Holds the lazy refill plus throttle check plus consume with burst
 * cap and floor use. Each helper stays noinline with scalar inputs
 * and no duplicate walk, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Relaxed load of one pool rest to match the compare and swap stores. */
/* Pairs with the refill and consume loops with no torn read. */
static __always_inline u64 flow_load_pool(
	struct flow_cgrp_ctx *e)
{
	return READ_ONCE(e->pool_ns);
}
/* Relaxed load of one refill stamp to match the compare and swap stores. */
/* Pairs with the refill claim with no torn read. */
static __always_inline u64 flow_load_updated(
	struct flow_cgrp_ctx *e)
{
	return READ_ONCE(e->updated_at);
}
/* Lazy refill of one pool with burst cap and floor use. */
/* Unlimited pools stay zero with no time use. Elapsed time */
/* refills by quota over period with saturating math, capped at */
/* quota plus burst. Huge inputs clamp instead of wrapping, so the */
/* pool never collapses to a small cap. The stamp advances only when */
/* the refill adds, so tiny elapsed keeps its fraction for the next */
/* pass. The stamp claims with a compare and swap, so concurrent */
/* refills add once. The pool adds with one compare and swap try, so */
/* concurrent refills never tear. A lost try drops the add with the */
/* stamp advanced, so the next elapsed refills with no stall. */
static __noinline void flow_bw_refill(
	struct flow_cgrp_ctx *e, u64 now)
{
	u64 updated;
	u64 elapsed;
	u64 prod;
	u64 add;
	u64 max;
	u64 old;
	u64 cur;
	u64 sum;
	u64 want;
	if (!e)
		return;
	if (flow_bw_unlimited(
	    READ_ONCE(e->quota_us)))
		return;
	updated = flow_load_updated(e);
	if (flow_time_before(now, updated))
		return;
	elapsed = now - updated;
	if (!elapsed)
		return;
	if (!READ_ONCE(e->period_us))
		return;
	if (elapsed > 4294967295ULL ||
	    READ_ONCE(e->quota_us) > 4294967295ULL)
		prod = (u64)~0ULL;
	else
		prod = elapsed *
		    READ_ONCE(e->quota_us);
	add = prod / READ_ONCE(e->period_us);
	if (!add)
		return;
	old = __sync_val_compare_and_swap(&e->updated_at,
	    updated, now);
	if (old != updated)
		return;
	max = flow_bw_max_ns(
	    READ_ONCE(e->quota_us),
	    READ_ONCE(e->burst_us));
	if (!max)
		return;
	cur = flow_load_pool(e);
	if (cur >= max)
		return;
	sum = cur + add;
	if (sum < cur)
		sum = (u64)~0ULL;
	want = sum;
	if (want > max)
		want = max;
	__sync_val_compare_and_swap(&e->pool_ns, cur, want);
}
/* True when one hierarchy is throttled with lazy refill. */
/* Walks the nearest 8 ancestors with refill, and the tightest pool */
/* binds, so any drained pool parks the task. Unlimited walks */
/* pass at once with no pool use. A null hierarchy passes at once. */
/* Pool reads use relaxed loads to match the refill stores. The walked */
/* chain records to the hint ring on park with the leaf first, and */
/* the leaf flag sets on park else clears on pass, so the dispatch */
/* check stays a single lookup with no walk. */
/* Each ancestor carries a reference with a paired release. */
static __noinline bool flow_bw_throttled(
	struct cgroup *cgrp, u64 now)
{
	int level;
	int i;
	u64 chain[8] = {};
	struct flow_cgrp_ctx *leaf = NULL;
	if (!cgrp)
		return false;
	if (!flow_load_limited())
		return false;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
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
		chain[i] = id;
		e = flow_cgrp(id);
		if (!e)
			continue;
		if (i == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    READ_ONCE(e->quota_us)))
			continue;
		flow_bw_refill(e, now);
		if (flow_load_pool(e) == 0) {
			if (leaf)
				flow_flag_set(leaf);
			flow_hint_chain(chain);
			return true;
		}
		if (i == 0 && lvl == 0)
			break;
	}
	if (leaf)
		flow_flag_clear(leaf);
	return false;
}
/* Fused share plus throttle over one depth-8 walk with hint once. */
/* Compounds each ancestor weight by base 100 with miss default, so */
/* a light parent lowers the share. Refills each limited pool with */
/* cap, and the tightest pool binds, so any drained pool parks. */
/* Unlimited entries fold the share with no pool use. The walked */
/* chain records to the hint ring on park with the leaf first, and */
/* the leaf flag sets on park else clears on pass, so the dispatch */
/* check stays a single lookup with no walk. A null hierarchy writes */
/* base with no throttle. Relaxed loads match the share plus pool */
/* stores, and the flag protocol matches the split walks. The caller */
/* updates the share cache with the returned share even on park, so */
/* the next hit skips the walk. Each ancestor carries a reference */
/* with a paired release. Outlined to keep enqueue small with one */
/* walk instead of two on a cache miss. */
static __noinline bool flow_hier_checked(
	struct cgroup *cgrp, u64 now, u32 *hier_out)
{
	u64 hier = (u64)FLOW_CGRP_WEIGHT_DFL;
	int level;
	int i;
	u64 chain[8] = {};
	struct flow_cgrp_ctx *leaf = NULL;
	u64 limited;
	if (!hier_out)
		return false;
	if (!cgrp) {
		*hier_out = (u32)FLOW_CGRP_WEIGHT_DFL;
		return false;
	}
	limited = READ_ONCE(flow_bw_limited);
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
		if (limited)
			chain[i] = id;
		e = flow_cgrp(id);
		if (!e) {
			hier = hier * (u64)FLOW_CGRP_WEIGHT_DFL /
			    (u64)FLOW_WEIGHT_BASE;
			if (hier > (u64)FLOW_WEIGHT_MAX)
				hier = (u64)FLOW_WEIGHT_MAX;
			if (hier < (u64)FLOW_WEIGHT_MIN)
				hier = (u64)FLOW_WEIGHT_MIN;
			continue;
		}
		w = flow_weight_clamp(
		    READ_ONCE(e->weight));
		hier = hier * (u64)w / (u64)FLOW_WEIGHT_BASE;
		if (hier > (u64)FLOW_WEIGHT_MAX)
			hier = (u64)FLOW_WEIGHT_MAX;
		if (hier < (u64)FLOW_WEIGHT_MIN)
			hier = (u64)FLOW_WEIGHT_MIN;
		if (!limited)
			continue;
		if (i == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    READ_ONCE(e->quota_us)))
			continue;
		flow_bw_refill(e, now);
		if (flow_load_pool(e) == 0) {
			if (leaf)
				flow_flag_set(leaf);
			flow_hint_chain(chain);
			*hier_out = (u32)hier;
			return true;
		}
		if (i == 0 && lvl == 0)
			break;
	}
	if (limited && leaf)
		flow_flag_clear(leaf);
	*hier_out = (u32)hier;
	return false;
}
/* Limited pools drain saturating to zero with no wrap, and */
/* unlimited pools pass with no charge. Pool updates use one compare */
/* and swap try, so concurrent charges never tear. A lost try drops */
/* the charge with the next charge covering, so no stall. When any */
/* ancestor sits drained, the leaf flag sets, so the dispatch check */
/* holds later parks with no walk. A null hierarchy passes. */
/* Each ancestor carries a reference with a paired release. */
static __noinline void flow_bw_consume(
	struct cgroup *cgrp, u64 delta)
{
	int level;
	int i;
	struct flow_cgrp_ctx *leaf = NULL;
	bool drained = false;
	if (!cgrp)
		return;
	if (!delta)
		return;
	if (!flow_load_limited())
		return;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
		int lvl;
		u64 cur;
		u64 want;
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
			continue;
		if (i == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    READ_ONCE(e->quota_us)))
			continue;
		cur = flow_load_pool(e);
		if (cur == 0) {
			drained = true;
			if (i == 0 && lvl == 0)
				break;
			continue;
		}
		if (cur > delta)
			want = cur - delta;
		else
			want = 0;
		__sync_val_compare_and_swap(&e->pool_ns, cur,
		    want);
		if (want == 0)
			drained = true;
		if (i == 0 && lvl == 0)
			break;
	}
	if (drained && leaf)
		flow_flag_set(leaf);
}
