// SPDX-License-Identifier: GPL-2.0
/*
 * Global drain for the dispatch pass.
 *
 * Moves mask allowed homeless tasks to local with the batch bound
 * covering visits plus moves plus skips too, so one bad head never
 * stalls the pass. Each visit without a move counts one skip.
 * Tasks without state or without a live CPU rest here with mask
 * wins on drain. Each phase takes scalars only and verifies once.
 * Runs under the caller RCU read lock with the iterator trip
 * bounded.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Global phase with narrow inputs. Returns the global moves. */
/* Takes CPU plus budget plus base scalars with no struct pass. */
/* Visits plus moves plus skips share the batch with an early exit. */
static __noinline u32 flow_phase_global(s32 cpu, u32 budget,
	u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 seen = 0;
	u32 skips = 0;

	bpf_for_each(scx_dsq, p, (u64)SCX_DSQ_GLOBAL, 0) {
		struct task_struct *t;
		bool ok = false;
		if (base + moved + seen + skips >= budget)
			break;
		if (seen >= (u32)FLOW_GLOBAL_SCAN)
			break;
		seen++;
		t = bpf_task_from_pid(p->pid);
		if (t) {
			if (bpf_cpumask_test_cpu((u32)cpu,
			    t->cpus_ptr) &&
			    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)(u32)cpu, 0)) {
				moved++;
				ok = true;
			}
			bpf_task_release(t);
		}
		if (!ok) {
			skips++;
			__sync_fetch_and_add(&flow_stats.global_skipped,
			    1);
		}
	}
	return moved;
}
