// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate helper for the dispatch pass.
 *
 * Holds one overflow task check plus move with single release through
 * one exit. Callers pass the iterator task with the expected key.
 * Checks strict equality on the stored key. Sequence, liveness,
 * affinity, order checks run in one place so every skip parks with
 * no tree drop. Foreign keys skip cheaply through the iterator pid
 * plus mask with no reference, so a deep tail never pays a reference
 * per entry for keys it cannot match. The reference lands solely on
 * key plus mask hits, then the same key plus mask recheck guards pid
 * reuse before sequence plus order plus move. The core drops shares
 * through stopping plus disable plus exit with order delete
 * idempotent. The task reference drops once on every taken path
 * through one exit so a missed release cannot leak. The move reports
 * the pid plus key on success so callers drop the key with the stored
 * match. Runs inline so the iterator stays in the caller with no
 * extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with cheap skip, acquire, checks, move in one place. */
/* Gives true with pid plus key on move else false with no state. */
/* Parks count once on missing order plus stale sequence. Keyed match */
/* checks the stored key first through the iterator pid with no */
/* reference, then mask through the iterator, so foreign keys never */
/* take a reference. Callers pass the loop iterator so the move stays */
/* in iterator context. */
static __always_inline bool flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p,
	u32 key, u32 *out_pid, u32 *out_key)
{
	struct task_struct *t;
	u32 iter_pid;
	u32 pid;
	u32 *kp;
	u32 k2;
	struct flow_task_ctx *tctx;
	struct flow_order_entry *ord;
	bool moved = false;
	if (!p)
		return false;
	/* Cheap skip with no reference for keys this entry cannot match. */
	/* Uses the existing per key count precheck at the caller plus */
	/* this pid plus mask hint here, so full tail walks stay cheap. */
	iter_pid = (u32)p->pid;
	if (iter_pid == 0)
		return false;
	kp = bpf_map_lookup_elem(&veb_pid, &iter_pid);
	if (!kp)
		return false;
	k2 = READ_ONCE(*kp);
	if (k2 != key)
		return false;
	if (!flow_entry_ok(cpu, p, 0))
		return false;
	t = bpf_task_from_pid(p->pid);
	if (!t)
		return false;
	pid = (u32)t->pid;
	if (pid == 0)
		goto out;
	if (pid != iter_pid)
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
