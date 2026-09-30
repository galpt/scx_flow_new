// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the thin core.
 *
 * Moves admitted tasks in daemon order up to sixteen per pass.
 * Iteration follows the deadline ordered tail so moves leave in
 * least deadline order. Each move checks the daemon order entry,
 * task state, CPU affinity. Missing order means park with no run.
 * Sequence gaps park and the daemon resyncs through the wire.
 * Stale, migrated, exited tasks park and the daemon drops shares
 * through complete plus stale collection. Empty order or stall
 * fails open with one head move so progress stays bounded. Over
 * moves count progress.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	struct task_struct *p;
	u32 moved = 0;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		struct flow_task_ctx *tctx;
		struct flow_order_entry *ord;
		u32 pid;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			continue;
		}
		tctx = flow_lookup(t);
		if (!tctx) {
			bpf_task_release(t);
			continue;
		}
		ord = bpf_map_lookup_elem(&order_stor, &pid);
		if (!ord) {
			bpf_task_release(t);
			continue;
		}
		if (ord->seq == 0 ||
		    ord->seq != READ_ONCE(tctx->seq)) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0))
			moved++;
		bpf_task_release(t);
	}
	bpf_rcu_read_unlock();
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
