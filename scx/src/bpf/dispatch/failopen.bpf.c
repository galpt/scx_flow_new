// SPDX-License-Identifier: GPL-2.0
/*
 * Shared move for the dispatch pass.
 *
 * Holds the single affinity probe plus the single task move in one
 * place, so every tier shares one gate with no per tier copy. Live
 * stays proven once at entry, so the per element cost stays one mask
 * test with no live branch. The uniform tier skip gates affinity
 * through this one BPF test, so a miss skips with no kernel error
 * while mask still wins on drain. Moves carry deadline order for
 * tiers through the same move, so one foreign task never stalls live
 * work. Visits cap at sixty four per pass with resume next pass, so
 * a miss heavy queue never holds RCU across the whole queue while
 * moved progress stays work conserving across passes. Runs inline for
 * the probe plus move, so the verifier stays small with no unrolled
 * caller tree and no rescan per move. No fair.c helper is used and
 * the queue order stays in kernel priority queues.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one CPU may run one task through its mask. */
/* Live proven at entry, so mask alone gates here with no live branch. */
static __always_inline bool flow_mask_ok(s32 cpu,
	const struct task_struct *p)
{
	if (unlikely(cpu < 0))
		return false;
	if (unlikely(!p))
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* One candidate with the shared mask gate plus move in one place. */
/* Gives one on move else zero with no state and one mask test. */
/* The shared probe gates the move with live proven by the caller, so a */
/* mismatched entry skips with no kernel error while mask still wins */
/* on drain. Every tier shares this one gate, so every skip is */
/* uniform. Callers add the result with no success branch, so the */
/* verifier keeps the loop small. Callers pass the loop iterator so */
/* the move stays in iterator context. */
static __always_inline u32 flow_move_candidate(
	struct bpf_iter_scx_dsq *it, s32 cpu, struct task_struct *p)
{
	if (unlikely(cpu < 0))
		return 0;
	if (unlikely(!p))
		return 0;
	if (unlikely(!flow_mask_ok(cpu, p)))
		return 0;
	return (u32)scx_bpf_dsq_move(it, p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0);
}
