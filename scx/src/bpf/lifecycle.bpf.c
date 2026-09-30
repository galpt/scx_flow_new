// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops for the thin core.
 *
 * Running claims the segment start and tracks the CPU pid plus the on
 * CPU gauge. Stopping charges the segment to total runtime and counts
 * one requeue else one completion and emits one complete notify.
 * Stopping skips the notify when the task never queued. Enable clears
 * the task state. Disable plus exit charge leftovers plus emit one
 * complete notify so admission drops once. Ring reserve faults count
 * one park. Release clears stale pid views. Mechanism solely. Policy
 * lives in the daemon.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void flow_notify_complete(u32 pid,
	u32 cpu, u32 weight, u32 runnable)
{
	struct flow_event *ev;
	u64 seq;
	ev = bpf_ringbuf_reserve(&flow_cmp_rb, sizeof(*ev), 0);
	if (!ev) {
		__sync_fetch_and_add(&flow_stats.parks, 1);
		return;
	}
	seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
	ev->kind = (u64)FLOW_PROTO_COMPLETE;
	ev->seq = seq;
	ev->pid = pid;
	ev->cpu = cpu;
	ev->weight = weight;
	ev->pad = runnable;
	ev->at = flow_now();
	bpf_ringbuf_submit(ev, 0);
}
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
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st)
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
inc:
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
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	u32 weight;
	cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_lookup(p);
	now = flow_now();
	weight = p->scx.weight;
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		flow_notify_complete((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight,
		    runnable ? 1 : 0);
		return;
	}
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		u32 queued;
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		queued = READ_ONCE(tctx->seq) != 0;
		if (queued)
			flow_notify_complete((u32)p->pid,
			    cpu >= 0 ? (u32)cpu : 0, weight,
			    runnable ? 1 : 0);
		return;
	}
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	flow_on_cpu_dec();
	flow_notify_complete((u32)p->pid,
	    cpu >= 0 ? (u32)cpu : 0, weight,
	    runnable ? 1 : 0);
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		return;
	}
	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->run_at = 0;
	tctx->seq = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	u32 weight = p->scx.weight;
	s32 cpu = scx_bpf_task_cpu(p);
	if (!flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		flow_notify_complete((u32)p->pid, 0, weight, 1);
		return;
	}
	tctx = flow_lookup(p);
	flow_charge_leftover(p, tctx, cpu);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	if (!tctx || READ_ONCE(tctx->seq) != 0)
		flow_notify_complete((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, 1);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	u32 weight = p->scx.weight;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	tctx = flow_lookup(p);
	flow_charge_leftover(p, tctx, cpu);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	if (!tctx || READ_ONCE(tctx->seq) != 0)
		flow_notify_complete((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, 1);
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
