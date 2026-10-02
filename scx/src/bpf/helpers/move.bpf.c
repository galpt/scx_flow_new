// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate for the dispatch pass.
 *
 * Holds one task check plus move with no reference and no release.
 * Callers pass the iterator plus task from the single scan, so one scan
 * moves up to budget in queue order with no rescan per move. The mask
 * gates the move with live proven at entry, so other entries never
 * move. The kernel revalidates affinity plus liveness on the move, so
 * a changed affinity still fails closed with mask wins on drain. Runs
 * inline so the iterator stays in the caller with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with mask plus move in one place. */
/* Gives true on move else false with no state. Mask through the */
/* iterator gates the move with live proven by the caller, so the */
/* single scan pays one mask test per entry. Callers pass the loop */
/* iterator so the move stays in iterator context. */
static __always_inline bool flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	if (!flow_mask_ok(cpu, p))
		return false;
	return scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
