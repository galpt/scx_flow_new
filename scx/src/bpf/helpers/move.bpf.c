// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate helper for the dispatch pass.
 *
 * Holds one overflow task check plus move with single release through
 * one exit. Callers pass the iterator task with the expected key.
 * Checks strict equality on the stored key. Sequence, liveness,
 * affinity, order checks run in one place so every skip parks with
 * no tree drop. The core drops shares through stopping plus disable
 * plus exit with order delete idempotent. The task reference drops
 * once on every path through one exit so a missed release cannot
 * leak. The move reports the pid plus key on success so callers drop
 * the key with the stored match. Runs inline so the iterator stays
 * in the caller with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with acquire, checks, move, release in one place. */
/* Gives true with pid plus key on move else false with no state. */
/* Parks count once on missing order plus stale sequence. Keyed match */
/* checks the stored key. Callers pass the loop iterator so the move */
/* stays in iterator context. */
static __always_inline bool flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p,
	u32 key, u32 *out_pid, u32 *out_key)
{
	struct task_struct *t;
	u32 pid;
	u32 *kp;
	u32 k2;
	struct flow_task_ctx *tctx;
	struct flow_order_entry *ord;
	bool moved = false;
	t = bpf_task_from_pid(p->pid);
	if (!t)
		return false;
	pid = (u32)t->pid;
	if (pid == 0)
		goto out;
	kp = bpf_map_lookup_elem(&veb_pid, &pid);
	if (!kp)
		goto out;
	k2 = READ_ONCE(*kp);
	if (k2 != key)
		goto out;
	if (!flow_entry_ok(cpu, t, 0))
		goto out;
	tctx = flow_lookup(t);
	if (!tctx)
		goto out;
	ord = bpf_map_lookup_elem(&order_stor, &pid);
	if (!ord) {
		__sync_fetch_and_add(&flow_stats.parks, 1);
		goto out;
	}
	if (ord->seq == 0 || ord->seq != READ_ONCE(tctx->seq)) {
		__sync_fetch_and_add(&flow_stats.parks, 1);
		goto out;
	}
	if (scx_bpf_dsq_move(it, t,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
		moved = true;
		if (out_pid)
			*out_pid = pid;
		if (out_key)
			*out_key = k2;
	}
out:
	bpf_task_release(t);
	return moved;
}
