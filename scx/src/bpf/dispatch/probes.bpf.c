// SPDX-License-Identifier: GPL-2.0
/*
 * Ordered pick plus consume for the dispatch pass.
 *
 * Scans the overflow tail once to pick the least key then deadline
 * then owned then pid among entries the dispatch CPU may run. Task
 * state holds share plus key plus deadline from admit time, so the
 * entry check plus one state read gate admission with no extra index
 * lookup and no reference, and only the picked pid takes a reference
 * at move time. The move revalidates
 * pid plus key plus deadline plus owner with affinity, liveness,
 * share checks and no sequence gate, so any CPU takes the earliest
 * work it may run with pid reuse safe. Key plus deadline may match
 * across tasks in the same instant, so the owner check narrows the
 * reuse window with one cheap read. A recheck miss ends ordered work
 * and falls to FIFO, so one stale pick never burns extra scans with
 * ordered first keeping admitted preferred. Stale keys clear at
 * teardown with the next remove retrying, so a lingering key costs at
 * most one pick scan before FIFO. Drops run at teardown, so the hot
 * path keeps no deletes. Runs noinline with scalar CPU so the
 * verifier stays small. The caller holds no outer RCU section since
 * each helper takes its own.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool flow_pick_least(s32 cpu, u32 *out_pid,
	u32 *out_key, u64 *out_deadline, u32 *out_owner)
{
	u32 best_pid = 0;
	u32 best_key = (u32)FLOW_VEB_EMPTY;
	u64 best_deadline = (u64)~0ULL;
	u32 best_owned = 0;
	u32 best_owner = 0;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		u32 iter_pid;
		struct flow_task_ctx *tctx;
		u32 k;
		u64 d;
		u32 owner;
		u32 owned;
		if (!p)
			continue;
		/* Task state alone gates rejects with no extra lookup. */
		iter_pid = (u32)p->pid;
		if (iter_pid == 0)
			continue;
		if (!flow_entry_ok(cpu, p, 0))
			continue;
		tctx = flow_lookup(p);
		if (!tctx)
			continue;
		if (READ_ONCE(tctx->admit_share) == 0)
			continue;
		k = READ_ONCE(tctx->key);
		if (k >= (u32)FLOW_VEB_U)
			continue;
		d = READ_ONCE(tctx->deadline);
		if (d == 0)
			continue;
		owner = READ_ONCE(tctx->admit_cpu);
		owned = owner == (u32)cpu ? 1 : 0;
		if (best_pid == 0) {
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_owned = owned;
			best_owner = owner;
			continue;
		}
		if (k < best_key) {
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_owned = owned;
			best_owner = owner;
			continue;
		}
		if (k > best_key)
			continue;
		if (d < best_deadline) {
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_owned = owned;
			best_owner = owner;
			continue;
		}
		if (d > best_deadline)
			continue;
		if (owned > best_owned) {
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_owned = owned;
			best_owner = owner;
			continue;
		}
		if (owned < best_owned)
			continue;
		if (iter_pid < best_pid) {
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_owned = owned;
			best_owner = owner;
		}
	}
	bpf_rcu_read_unlock();
	if (best_pid == 0)
		return false;
	if (out_pid)
		*out_pid = best_pid;
	if (out_key)
		*out_key = best_key;
	if (out_deadline)
		*out_deadline = best_deadline;
	if (out_owner)
		*out_owner = best_owner;
	return true;
}
static __noinline bool veb_consume_best(s32 cpu)
{
	u32 pid = 0;
	u32 key = (u32)FLOW_VEB_EMPTY;
	u64 deadline = 0;
	u32 owner = 0;
	u32 moved_pid = 0;
	bool moved = false;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		return false;
	if (!flow_pick_least(cpu, &pid, &key, &deadline, &owner))
		return false;
	if (pid == 0 || key >= (u32)FLOW_VEB_U || deadline == 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		if (moved)
			break;
		if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p,
		    pid, key, deadline, owner, &moved_pid))
			moved = true;
	}
	bpf_rcu_read_unlock();
	return moved;
}
