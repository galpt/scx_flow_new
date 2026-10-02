// SPDX-License-Identifier: GPL-2.0
/*
 * Move candidate for the dispatch pass.
 *
 * Holds one task move with no reference and no release. Callers pass
 * the iterator plus task from the scan, so the tier bounded skip plus
 * the overflow single scan share one move with no rescan per move.
 * The BPF mask test gates affinity with liveness proven by the caller,
 * so a mismatched entry skips with no kernel error while mask still
 * wins on drain. Runs inline so the iterator stays in the caller with
 * no extra cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* One candidate with BPF mask gate plus move in one place. */
/* Gives one on move else zero with no state and one mask test. */
/* The BPF test gates the move with live proven by the caller, so a */
/* mismatched entry skips with no kernel error while mask still wins */
/* on drain. Callers add the result with no success branch, so the */
/* verifier keeps the loop small. Callers pass the loop iterator so */
/* the move stays in iterator context. */
static __always_inline u32 flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	if (cpu < 0)
		return 0;
	if (!p)
		return 0;
	if (!bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr))
		return 0;
	return (u32)scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
