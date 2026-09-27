// SPDX-License-Identifier: GPL-2.0
/*
 * Plain drain for the dispatch pass.
 *
 * Moves mask allowed tasks to local with a miss cap at 4.
 * One bad head never blocks later work with no full scan.
 * Serves deadline, global, overflow, and steal trips with
 * no throttle use. Runs under the caller RCU read lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;

	bpf_for_each(scx_dsq, p, dsq, 0) {
		if (moved + base >= budget)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;
		if (bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	return moved;
}
