// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open single move for the dispatch pass.
 *
 * Moves the first live affinity match at the overflow head so one
 * runnable task always lands on the dispatch CPU even when a stale
 * entry holds no order row. Skips drop no tree state with no park
 * count so transient misses stay quiet. Moves count one FIFO park
 * at the decision point. Drops run at teardown, so the hot path
 * keeps no deletes. Stays rare since admits write rows
 * synchronously and solely genuine affinity misses reach here.
 * Runs noinline with scalar CPU so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open with liveness plus affinity solely and no order gate. */
/* Moves the first live affinity match at the overflow head so one */
/* runnable task always lands on the dispatch CPU even when a stale */
/* entry holds no order row. Skips drop no tree state with no park */
/* count so transient misses stay quiet. Moves count one FIFO park */
/* at the decision point. Drops run at teardown with no hot path */
/* delete. Stays rare since admits write rows synchronously and */
/* solely genuine affinity misses reach here. */
static __noinline bool veb_fail_open_one(s32 cpu)
{
	bool moved = false;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return false;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		u32 pid;
		if (moved)
			break;
		if (!flow_entry_ok(cpu, p, 0))
			continue;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		if (pid == 0) {
			bpf_task_release(t);
			continue;
		}
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0))
			moved = true;
		bpf_task_release(t);
		if (moved)
			break;
	}
	bpf_rcu_read_unlock();
	return moved;
}
