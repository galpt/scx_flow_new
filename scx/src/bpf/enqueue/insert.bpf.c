// SPDX-License-Identifier: GPL-2.0
/*
 * Queue inserts for the enqueue pass.
 *
 * Holds the local, node, machine, overflow, and global inserts with
 * a fixed slice. Runs inline with no walk, so the verifier stays
 * small. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Insert one task into its local queue with its deadline. */
static __always_inline void flow_local_insert(
	struct task_struct *p, s32 cpu, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_local_dsq((u32)cpu),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into its node queue with its deadline. */
static __always_inline void flow_node_insert(
	struct task_struct *p, u32 node, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_node_dsq(node),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into the machine queue with its deadline. */
static __always_inline void flow_machine_insert(
	struct task_struct *p, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_machine_dsq(),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into the shared overflow tail. */
/* Pinned tasks plus missed parks rest here with mask wins on drain. */
static __always_inline void flow_over_insert(
	struct task_struct *p)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(),
	    (u64)FLOW_QUANTUM_NS, 0);
}
/* Insert one homeless task into the kernel global queue. */
/* Tasks without state or without a live CPU rest here with */
/* mask wins on drain, and the drain counts the global moves. */
static __always_inline void flow_global_insert(
	struct task_struct *p)
{
	scx_bpf_dsq_insert(p, (u64)SCX_DSQ_GLOBAL,
	    (u64)FLOW_QUANTUM_NS, 0);
}
