// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate for the dispatch pass.
 *
 * Holds one task move with no reference and no release. Callers pass
 * the iterator plus task from the single scan, so one scan moves up
 * to budget in queue order with no rescan per move. The kernel gates
 * affinity plus liveness on the move, so a mismatched entry skips
 * with no BPF mask test and no live branch, keeping the verifier
 * small while mask still wins on drain. Runs inline so the iterator
 * stays in the caller with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with move in one place. */
/* Gives one on move else zero with no state and no BPF mask test. */
/* The kernel gates the move with live proven by the caller, so the */
/* single scan pays one kfunc per entry with no extra branch. Callers */
/* add the result with no success branch, so the verifier keeps the */
/* loop small. Callers pass the loop iterator so the move stays in */
/* iterator context. */
static __always_inline u32 flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	return (u32)scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
