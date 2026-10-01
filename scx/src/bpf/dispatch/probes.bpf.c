// SPDX-License-Identifier: GPL-2.0
/*
 * Ordered probe for the dispatch pass.
 *
 * Scans the overflow tail for the first task whose stored key still
 * matches the expected key with sequence, liveness, affinity checks.
 * Foreign entries skip cheaply through the iterator pid plus mask
 * with no reference, so only key plus mask hits take a reference.
 * Duplicates leave in park order within one key. Per CPU mismatch,
 * missing order, stale sequence skip with no tree drop. Reports the
 * pid plus key on move so callers drop the key with the stored match.
 * Runs noinline with scalar key plus CPU so the verifier stays small.
 * The caller holds the outer RCU section through the iterator.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool veb_try_move_one(u32 key, s32 cpu)
{
	bool moved = false;
	struct task_struct *p;
	if (key >= (u32)FLOW_VEB_U)
		return false;
	if (cpu < 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		u32 pid = 0;
		u32 k2 = 0;
		if (moved)
			break;
		if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p, key,
		    &pid, &k2)) {
			moved = true;
			veb_remove_if_key(pid, k2);
			break;
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
