// SPDX-License-Identifier: GPL-2.0
/*
 * Flat hierarchy ops.
 *
 * The flat view holds one period plus weight hint per id with single
 * weighting through one shared band helper, and no group or pool shapes
 * order. The table holds 8192 rows with no eviction, so a full table
 * misses to the default period plus neutral weight with no stall. Id zero
 * scopes to defaults with no row, so a missing hierarchy stays neutral.
 * A zero cached id is the stale sentinel with miss to the acquire path.
 * Init runs sleepable with map create, the rest run without sleep with
 * lookup only. Moves carry vruntime plus deadline with no hint carry, so
 * the next enqueue reads the new hint plus weight after the move
 * invalidate clears the cached id. Weight sets the hint from fixed share
 * bands with no divide. See
 * intf.h for the hint helpers and enqueue.bpf.c for the hint plus
 * weight use.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Init one flat hint row with zero period plus neutral weight. */
/* Sleepable only, so map create runs here. A full table keeps the */
/* miss to the default period with no fail, so the update stays */
/* unchecked and init returns zero on purpose with no eviction. */
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
	struct scx_cgroup_init_args *args)
{
	u64 id;
	struct flow_hint h = {};
	(void)args;
	if (!cgrp)
		return -EINVAL;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return -EINVAL;
	h.weight = (u32)FLOW_WEIGHT_BASE;
	bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY);
	return 0;
}
/* Exit one flat hint row. */
/* Deletes the row, so later lookups miss to defaults. */
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 id;
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	bpf_map_delete_elem(&hint_stor, &id);
}
/* Prepare one flat move with no alloc and no fail. */
/* Always passes, so the move pairs one to one. */
s32 BPF_STRUCT_OPS(flow_cgroup_prep_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
	return 0;
}
/* Commit one flat move with vruntime plus deadline carry. */
/* The vruntime plus the deadline stay, so order survives the move. */
/* The hint plus the weight stay per id with no carry, so the next */
/* enqueue reads the new values. The cached id clears here, so the */
/* next read takes the new hierarchy with no stale use. */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)from;
	if (!p)
		return;
	if (!to)
		return;
	flow_cgrp_cache_invalidate((u32)p->pid);
}
/* Cancel one flat move with no state change. */
/* Preparation holds no state, so cancel stays empty. */
void BPF_STRUCT_OPS(flow_cgroup_cancel_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
/* Shared single share band for cgroup plus task paths. */
/* Maps one clamped share once to period plus weight bands with no divide. */
/* Single weighting keeps one clamp plus one band with no double count. */
/* Light shares map to long periods plus small weights and heavy shares */
/* map to short periods plus large weights, so the hint tunes the */
/* deadline period while the weight tunes vruntime speed. Bands sit on */
/* powers of two, so the scaler shifts exactly with no table walk. */
static __always_inline void flow_share_band(u32 w, u32 *period_us,
	u32 *weight)
{
	u32 p = 8000;
	u32 b = 256;
	u32 c = flow_weight_clamp(w);
	if (c < 64) {
		p = 32000;
		b = 32;
	} else if (c < 128) {
		p = 16000;
		b = 64;
	} else if (c < 512) {
		p = 8000;
		b = 256;
	} else {
		p = 4000;
		b = 1024;
	}
	if (period_us)
		*period_us = p;
	if (weight)
		*weight = b;
}
/* Update one flat hint from the share with fixed bands. */
/* Light shares map to long periods plus small weights and heavy shares */
/* map to short periods plus large weights, so the hint tunes the */
/* deadline period while the weight tunes vruntime speed with no divide. */
/* Bands sit on powers of two, so the scaler shifts exactly with no */
/* table walk. Creates the row on miss, so later reads see the new hint */
/* at once. A full table keeps the miss to defaults with no eviction. */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp,
	u32 weight)
{
	u64 id;
	struct flow_hint h = {};
	if (!cgrp)
		return;
	id = flow_cgrp_id(cgrp);
	if (!id)
		return;
	flow_share_band(weight, &h.period_us, &h.weight);
	if (bpf_map_update_elem(&hint_stor, &id, &h, BPF_ANY) < 0)
		return;
}
