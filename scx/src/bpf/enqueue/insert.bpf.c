// SPDX-License-Identifier: GPL-2.0
/*
 * Queue inserts for the enqueue pass.
 *
 * Holds the local, node, machine, and tier inserts with a fixed
 * slice. Local plus node plus machine use the kernel priority queue
 * with the deadline as vtime, so each queue drains in deadline order
 * with no BPF scan. Homeless tasks wait in the machine queue with all
 * other shared work, so no insert touches the kernel global queue and
 * no queue mixes orders. Runs inline with no walk, so the verifier
 * stays small. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Insert one task into its local queue with its deadline. */
/* Uses the priority queue with the deadline as vtime, so the head */
/* holds the earliest deadline with mask wins on drain. EDF order via */
/* kernel priority queue: the vtime key holds the absolute deadline, */
/* so the earliest deadline wins with no lag compensation. */
static __always_inline void flow_local_insert(
	struct task_struct *p, s32 cpu, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_local_dsq((u32)cpu),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into its node queue with its deadline. */
/* Uses the priority queue the same way with mask wins on drain. */
static __always_inline void flow_node_insert(
	struct task_struct *p, u32 node, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_node_dsq(node),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into the machine queue with its deadline. */
/* Uses the priority queue the same way with mask wins on drain. */
static __always_inline void flow_machine_insert(
	struct task_struct *p, u64 deadline)
{
	scx_bpf_dsq_insert_vtime(p, flow_machine_dsq(),
	    (u64)FLOW_QUANTUM_NS, deadline, 0);
}
/* Insert one task into the best tier for one CPU with its deadline. */
/* Takes the local queue when the CPU drains before the deadline, else */
/* the node queue when the node is live, else the machine queue, so no */
/* task waits for a busy CPU while shared room stays open. Homeless */
/* tasks with no live CPU wait in the machine queue with mask wins on */
/* drain. The deadline already holds from the predictor or the */
/* fallback, so order stays correct with no extra wait. */
static __always_inline void flow_tier_insert(
	struct task_struct *p, s32 cpu, u64 deadline, u64 now)
{
	u32 node;
	if (cpu >= 0 && flow_cpu_meets((u32)cpu, deadline, now)) {
		flow_local_insert(p, cpu, deadline);
		return;
	}
	if (cpu >= 0) {
		node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES &&
		    (u64)node < nr_node_ids) {
			flow_node_insert(p, node, deadline);
			return;
		}
	}
	flow_machine_insert(p, deadline);
}
