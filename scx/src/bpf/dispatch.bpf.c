// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves admitted tasks in tree order up to sixteen per pass.
 * The pass starts from the least key and follows successors.
 * Each key scans the overflow tail and moves the first admitted
 * task with sequence plus liveness checks. Duplicates leave in
 * park order within one key. Missing order parks with no run.
 * Stale entries park and the daemon drops shares through complete
 * plus stale collection. Empty tree or stall fails open with one
 * head move so progress stays bounded. Over moves count progress.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool veb_try_move_one(u32 key, s32 cpu)
{
	bool moved = false;
	struct task_struct *p;
	if (key >= 65536)
		return false;
	if (cpu < 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		u32 pid;
		u32 *kp;
		u32 k2;
		struct flow_task_ctx *tctx;
		struct flow_order_entry *ord;
		if (moved)
			break;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		kp = bpf_map_lookup_elem(&veb_pid, &pid);
		if (!kp) {
			bpf_task_release(t);
			continue;
		}
		k2 = READ_ONCE(*kp);
		if (k2 != key) {
			bpf_task_release(t);
			continue;
		}
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			veb_remove(pid);
			continue;
		}
		tctx = flow_lookup(t);
		if (!tctx) {
			bpf_task_release(t);
			veb_remove(pid);
			continue;
		}
		ord = bpf_map_lookup_elem(&order_stor, &pid);
		if (!ord) {
			bpf_task_release(t);
			veb_remove(pid);
			continue;
		}
		if (ord->seq == 0 || ord->seq != READ_ONCE(tctx->seq)) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			veb_remove(pid);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			moved = true;
			bpf_task_release(t);
			veb_remove(pid);
			break;
		}
		bpf_task_release(t);
	}
	bpf_rcu_read_unlock();
	return moved;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	u32 cur;
	int attempt;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	cur = veb_min();
	if (cur == 0xFFFFFFFFU) {
		if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
			return;
		if (scx_bpf_dsq_move_to_local(flow_overflow_dsq(), 0))
			__sync_fetch_and_add(&flow_stats.over_moves, 1);
		return;
	}
	bpf_for(attempt, 0, 64) {
		bool got;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		if (cur == 0xFFFFFFFFU)
			break;
		got = veb_try_move_one(cur, cpu);
		if (got) {
			moved++;
			continue;
		}
		cur = veb_succ(cur);
	}
	if (moved) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
		return;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		return;
	if (scx_bpf_dsq_move_to_local(flow_overflow_dsq(), 0))
		__sync_fetch_and_add(&flow_stats.over_moves, 1);
}
