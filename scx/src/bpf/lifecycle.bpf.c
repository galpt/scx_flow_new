// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops for the flow core.
 *
 * Running claims the segment start and tracks the CPU pid plus the on
 * CPU gauge. Stopping charges the segment to total runtime and counts
 * one requeue else one completion and emits one observability notify.
 * A requeue steps the repeat count toward the larger slice capped at
 * eight milliseconds, while a blocking end clears it, so steady work
 * keeps the base slice and repeat exhaust grows it with no extra map.
 * Stopping drops the tree key plus the ledger share plus the order
 * row so dispatched keys never linger and use never leaks. Gate fail
 * stopping drops plus notifies when queued like disable so shares
 * return at once with no stale wait. Stopping skips the notify when
 * the task never queued. Enable clears the task state with share plus
 * CPU plus deadline plus key plus repeat cleared and drops the tree
 * key plus the order row plus the head slot, so top key rejects never
 * linger. Disable plus exit charge leftovers, drop the tree key
 * plus the ledger share plus the order row, emit one observability
 * notify so every admit pairs one drop. One finish helper pairs key,
 * charge, pid, gauge, ledger, notify through one exit so a missed
 * cleanup cannot leak. Rings stay best effort with loss irrelevant.
 * Release clears stale pid views. Admission plus order live in the
 * core with the daemon as monitor solely.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	u64 prev;
	bool claimed = false;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	if (tctx) {
		stamp = now ? now : 1;
		prev = __sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
		claimed = prev == 0;
	}
	st = flow_cpu_state_for(cpu);
	if (st)
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
	if (claimed)
		__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	s32 cpu;
	u32 weight;
	bool charged;
	u32 run_flag = runnable ? 1 : 0;
	cpu = scx_bpf_task_cpu(p);
	weight = p->scx.weight;
	if (!flow_entry_ok(cpu, p, 0)) {
		struct flow_task_ctx *gtctx;
		u64 now;
		flow_gate_reject();
		veb_remove((u32)p->pid);
		gtctx = flow_lookup(p);
		now = flow_now();
		flow_admit_drop((u32)p->pid, gtctx, run_flag, now);
		if (!gtctx || READ_ONCE(gtctx->seq) != 0)
			flow_notify_complete((u32)p->pid,
			    cpu >= 0 ? (u32)cpu : 0, weight, run_flag);
		return;
	}
	charged = flow_finish_task(p, cpu, weight, run_flag);
	if (!charged)
		return;
	if (runnable) {
		struct flow_task_ctx *stctx = flow_lookup(p);
		if (stctx) {
			u32 cur = READ_ONCE(stctx->exhaust);
			if (cur < (u32)FLOW_QUANTUM_MAX_STEP)
				WRITE_ONCE(stctx->exhaust, cur + 1);
		}
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	{
		struct flow_task_ctx *ctctx = flow_lookup(p);
		if (ctctx)
			WRITE_ONCE(ctctx->exhaust, 0);
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	u32 pid;
	u32 key;
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	pid = (u32)p->pid;
	key = READ_ONCE(tctx->key);
	WRITE_ONCE(tctx->run_at, 0);
	WRITE_ONCE(tctx->seq, 0);
	WRITE_ONCE(tctx->admit_share, 0);
	WRITE_ONCE(tctx->admit_cpu, 0);
	WRITE_ONCE(tctx->deadline, 0);
	WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
	WRITE_ONCE(tctx->exhaust, 0);
	/* Fresh tasks drop any prior top key plus row plus head, so a */
	/* reused pid never leaves a stale ordered entry behind. */
	veb_remove(pid);
	flow_order_delete(pid);
	flow_head_clear(pid, key);
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	u32 weight = p->scx.weight;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		struct flow_task_ctx *gtctx;
		u64 now;
		flow_gate_reject();
		veb_remove((u32)p->pid);
		gtctx = flow_lookup(p);
		now = flow_now();
		flow_admit_drop((u32)p->pid, gtctx, 1, now);
		flow_notify_complete((u32)p->pid, 0, weight, 1);
		return;
	}
	flow_finish_task(p, cpu, weight, 1);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	u32 weight = p->scx.weight;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	flow_finish_task(p, cpu, weight, 1);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	if (cpu >= 0 && !flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	flow_clear_running(cpu);
}
