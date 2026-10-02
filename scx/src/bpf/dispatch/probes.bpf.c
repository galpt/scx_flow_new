// SPDX-License-Identifier: GPL-2.0
/*
 * Mask probe for the dispatch pass.
 *
 * Holds the single affinity check shared by the priority fill plus the
 * fail open drain. Live stays proven once at entry, so the per element
 * cost stays one mask test with no live branch. The kernel also gates
 * every move, so a BPF miss still fails closed with mask wins on drain.
 * Runs inline so the iterator stays in the caller with no extra call
 * cost.
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
