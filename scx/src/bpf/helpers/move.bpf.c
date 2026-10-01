// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate helper for the dispatch pass.
 *
 * Holds one overflow task check plus move with single release through
 * one exit. Callers pass the iterator task with the picked pid plus
 * key plus deadline plus owner from the global least scan. Checks
 * strict equality on pid plus key plus deadline plus owner with
 * affinity, liveness, share checks in one place and no sequence gate,
 * so any CPU takes the earliest work it may run. Key plus deadline
 * may match across tasks in the same instant, so the owner check
 * narrows the reuse window with one cheap read. Foreign pids skip
 * cheaply through the iterator pid with no reference, so only the
 * picked pid takes a reference. The same pid plus key plus deadline
 * plus owner recheck guards reuse before the move. Drops run at
 * teardown, so the hot path keeps no deletes.
 * The task reference drops once on every taken path through one exit
 * so a missed release cannot leak. Runs inline so the iterator stays
 * in the caller with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with cheap skip, acquire, checks, move in one place. */
/* Gives true with pid on move else false with no state. Pid match */
/* checks the iterator pid first with no reference, then entry gate */
/* through the iterator, so other entries never take a reference. */
/* Callers pass the loop iterator so the move stays in iterator context. */
static __always_inline bool flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p,
	u32 want_pid, u32 want_key, u64 want_deadline, u32 want_owner,
	u32 *out_pid)
{
	struct task_struct *t;
	u32 iter_pid;
	u32 pid;
	struct flow_task_ctx *tctx;
	bool moved = false;
	if (!p)
		return false;
	/* Cheap skip with no reference for pids this move cannot take. */
	/* Uses the picked pid from the least scan, so a deep tail pays */
	/* a reference solely on the one picked entry. */
	iter_pid = (u32)p->pid;
	if (iter_pid == 0)
		return false;
	if (iter_pid != want_pid)
		return false;
	if (!flow_entry_ok(cpu, p, 0))
		return false;
	t = bpf_task_from_pid(p->pid);
	if (!t)
		return false;
	pid = (u32)t->pid;
	if (pid == 0)
		goto out;
	if (pid != want_pid)
		goto out;
	if (!flow_entry_ok(cpu, t, 0))
		goto out;
	tctx = flow_lookup(t);
	if (!tctx)
		goto out;
	if (READ_ONCE(tctx->admit_share) == 0)
		goto out;
	if (READ_ONCE(tctx->key) != want_key)
		goto out;
	if (READ_ONCE(tctx->deadline) != want_deadline)
		goto out;
	if (READ_ONCE(tctx->admit_cpu) != want_owner)
		goto out;
	if (scx_bpf_dsq_move(it, t,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
		moved = true;
		if (out_pid)
			*out_pid = pid;
	}
out:
	bpf_task_release(t);
	return moved;
}
