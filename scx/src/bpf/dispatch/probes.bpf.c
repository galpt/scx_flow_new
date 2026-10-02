// SPDX-License-Identifier: GPL-2.0
/*
 * Mask probe for the dispatch pass.
 *
 * Holds the single affinity check for shared tier plus overflow
 * checks. Live stays proven once at entry, so the per element cost
 * stays one mask test with no live branch. The overflow scan plus
 * the tier bounded skip gate affinity through this BPF test, so a
 * BPF miss skips with no kernel error while mask still wins on
 * drain. Runs inline so the iterator stays in the caller with no
 * extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one CPU may run one task through its mask. */
/* Live proven at entry, so mask alone gates here with no live branch. */
static __always_inline bool flow_mask_ok(s32 cpu,
	const struct task_struct *p)
{
	if (cpu < 0)
		return false;
	if (!p)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
