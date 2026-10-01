// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open move for the dispatch batch drain.
 *
 * Holds one overflow task check plus move with single release through
 * one exit. Callers pass the iterator plus task from the single canary
 * scan, so one scan moves up to sixteen in queue order with no
 * rescan per move. Skips drop no tree state with no park count so
 * transient misses stay quiet. Moves count one FIFO park at the
 * decision point through the batch account, keeping the canary
 * meaningful while ordered moves carry every parked task. Moves clear
 * the head slot, so a fallback pid never lingers as a head for the
 * next ordered pick. Drops run at teardown, so the hot path keeps no
 * deletes. Stays as the empty or corrupt canary since task state plus
 * tree land synchronously and solely genuine misses reach here.
 * Live stays proven once at entry, so the check pays one mask test
 * on the acquired task with no live branch and no iterator test
 * beyond the acquire. Runs inline so the iterator stays in the
 * caller with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open move with mask plus head clear in one place. */
/* Gives true on move else false with no state. Iterator test skips */
/* references on misses with live proven by the caller, so the single */
/* scan pays one mask test on the acquired task. A move clears the head */
/* slot when it still names the pid, so a running pid never lingers */
/* while other keys stay. Callers pass the loop iterator so the move */
/* stays in iterator context. */
static __always_inline bool flow_fail_open_move(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	struct task_struct *t;
	u32 pid;
	/* Iterator never holds null here, so no null branch. */
	/* Live proven at entry, so mask gates the reference with */
	/* misses rare through synchronous rows. */
	if (!flow_mask_ok(cpu, p))
		return false;
	t = bpf_task_from_pid(p->pid);
	if (!t)
		return false;
	pid = (u32)t->pid;
	if (pid == 0) {
		bpf_task_release(t);
		return false;
	}
	if (!flow_mask_ok(cpu, t)) {
		bpf_task_release(t);
		return false;
	}
	if (scx_bpf_dsq_move(it, t,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
		struct flow_task_ctx *tctx = flow_lookup(t);
		if (tctx) {
			u32 k = READ_ONCE(tctx->key);
			/* Clear frees the slot when it still names this pid, */
			/* so the next ordered pick never sees a running head. */
			/* Other slots stay with an empty key as a no op. */
			flow_head_clear(pid, k);
		}
		bpf_task_release(t);
		return true;
	}
	bpf_task_release(t);
	return false;
}
