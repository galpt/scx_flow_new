// SPDX-License-Identifier: GPL-2.0
/*
 * Global drain for the dispatch pass.
 *
 * Moves mask allowed homeless tasks to local with the batch bound
 * covering visits too, so one bad head never stalls the pass. Tasks
 * without state or without a live CPU rest here with mask wins on
 * drain. Each phase takes scalars only and verifies once. Runs
 * under the caller RCU read lock with the iterator trip bounded.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Global phase with narrow inputs. Returns the global moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
static __noinline u32 flow_phase_global(s32 cpu, u32 budget,
	u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 seen = 0;

	bpf_for_each(scx_dsq, p, (u64)SCX_DSQ_GLOBAL, 0) {
		if (moved + base >= budget)
			break;
		if (seen >= (u32)FLOW_GLOBAL_SCAN)
			break;
		seen++;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0)) {
			bpf_task_release(p);
			moved++;
		} else {
			bpf_task_release(p);
		}
	}
	return moved;
}
