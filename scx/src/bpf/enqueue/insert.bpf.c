// SPDX-License-Identifier: GPL-2.0
/*
 * Queue inserts for the enqueue pass.
 *
 * Holds the local plus global inserts with the default slice and
 * no fixed quantum. The deadline tree owns order, so inserts carry
 * no virtual time. Runs inline with no walk, so the verifier stays
 * small. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Insert one task on one CPU local queue with default slice. */
/* Dispatch and the exiting fast path land here with mask already */
/* won, so no check runs past the insert. */
static __always_inline void flow_local_insert(
	struct task_struct *p, s32 cpu, u64 enq_flags)
{
	scx_bpf_dsq_insert(p,
	    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu,
	    (u64)SCX_SLICE_DFL, enq_flags);
}
/* Insert one homeless task into the kernel global queue. */
/* Tasks without state or without a live CPU rest here with */
/* mask wins on drain, and the drain counts the global moves. */
static __always_inline void flow_global_insert(
	struct task_struct *p)
{
	scx_bpf_dsq_insert(p, (u64)SCX_DSQ_GLOBAL,
	    (u64)SCX_SLICE_DFL, 0);
}
