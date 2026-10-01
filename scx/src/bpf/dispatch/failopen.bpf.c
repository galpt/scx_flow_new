// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open single move for the dispatch pass.
 *
 * Moves the first live affinity match at the overflow head so one
 * runnable task always lands on the dispatch CPU even when a stale
 * entry holds no order row. Skips drop no tree state with no park
 * count so transient misses stay quiet. Moves count one FIFO park
 * at the decision point. The moved pid drops its key solely when
 * the stored key still matches. Stays rare since admits write rows
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
/* at the decision point. The moved pid drops its key solely when */
/* the stored key still matches. Stays rare since admits write rows */
/* synchronously and solely genuine affinity misses reach here. */
static __noinline bool veb_fail_open_one(s32 cpu)
{
	bool moved = false;
	u32 reap_pid = 0;
	u32 reap_key = (u32)FLOW_VEB_EMPTY;
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
		u32 *kp;
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
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			moved = true;
			reap_pid = pid;
			kp = bpf_map_lookup_elem(&veb_pid, &pid);
			if (kp && READ_ONCE(*kp) !=
			    (u32)FLOW_VEB_EMPTY &&
			    READ_ONCE(*kp) < (u32)FLOW_VEB_U)
				reap_key = READ_ONCE(*kp);
		}
		bpf_task_release(t);
		if (moved)
			break;
	}
	bpf_rcu_read_unlock();
	if (moved) {
		if (reap_pid != 0 && reap_key != (u32)FLOW_VEB_EMPTY)
			veb_remove_if_key(reap_pid, reap_key);
		return true;
	}
	return false;
}
