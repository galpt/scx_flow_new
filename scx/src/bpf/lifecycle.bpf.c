// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	if (tctx)
		tctx->run_at = flow_now();
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st)
		st->running_pid = (u32)p->pid;
inc:
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
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	/* Tasks that never ran keep no segment with no charge. */
	if (!tctx || !tctx->run_at) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		if (!tctx)
			flow_on_cpu_dec();
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	tctx->run_at = 0;
	tctx->vruntime += delta;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
	/* Idle CPUs reset the frontier to the waking time with no zero. */
	/* Queued work keeps the max so time never moves backward. */
	if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		if (st) {
			u64 nv = tctx->vruntime;
			u64 dsq_nr =
			    scx_bpf_dsq_nr_queued(
			    flow_slot_cpu_dsq((u32)cpu));
			dsq_nr += scx_bpf_dsq_nr_queued(
			    flow_slot_overflow_dsq());
			if (!runnable && dsq_nr == 0 &&
			    scx_bpf_dsq_nr_queued(
			    (u64)SCX_DSQ_LOCAL_ON |
			    (u64)cpu) == 0) {
				if (nv != 0)
					st->frontier =
					    flow_frontier_idle(nv);
			} else {
				st->frontier = flow_frontier_max(
				    st->frontier, nv);
			}
		}
	}
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->run_at = 0;
	tctx->vruntime = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	/* Charge a segment stopping never saw at most once. */
	flow_charge_leftover(cpu, tctx);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	/* Charge a segment stopping never saw at most once. */
	flow_charge_leftover(cpu, tctx);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
