// SPDX-License-Identifier: GPL-2.0
/*
 * Task weight for the core.
 *
 * Holds the per task base share stored by the set weight op. The base
 * stays clamped to range with neutral on missing state, and the
 * effective share stacks task times hint over 128 on the stack at
 * enqueue plus stopping time with no extra store. A missing task state
 * fails closed with no create and no count, so a weight change before
 * enable never allocates. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_set_weight - store one task base share with clamp.
 * @p: task to reweight, null fails closed.
 * @weight: raw share, clamped to range with fail closed to bounds.
 *
 * Stores the clamped base in task state with no hint use, so later
 * enqueues stack the effective share with the flat hint. A missing
 * task state fails closed with no create and no stall.
 */
void BPF_STRUCT_OPS(flow_set_weight, struct task_struct *p,
	u32 weight)
{
	struct flow_task_ctx *tctx;
	u32 w;
	if (!p)
		return;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	w = flow_weight_clamp(weight);
	__sync_lock_test_and_set(&tctx->weight, w);
}
