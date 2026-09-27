// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Stopping charges one weight scaled segment to the ledger on every run,
 * then steps duty toward sleep or spin. Voluntary sleep records a waiter
 * for the PI correlate, and release clears any elevation. Enable anchors
 * fresh tasks with two probation wakes. See intf.h for the duty and clamp
 * helpers and enqueue.bpf.c for the matching admission side.
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
	if (tctx) {
		tctx->run_at = flow_now();
		/* Hold one count until stopping or leftover drops it. */
		tctx->on_cpu = 1;
	}
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
	u32 w;
	bool vol;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	/* Tasks that never ran keep no segment with no charge. */
	if (!tctx || !tctx->run_at) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		if (!tctx) {
			flow_on_cpu_dec();
		} else if (tctx->on_cpu) {
			/* Leftover cleared the start with count held. */
			/* Drop the count once with no second charge. */
			tctx->on_cpu = 0;
			flow_on_cpu_dec();
		}
		return;
	}
	/* A stopped task already dropped its count with no second charge. */
	/* The flag survives release clears, so release never leaks. */
	if (!tctx->on_cpu) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	/* Every segment charges scaled time, fast lane or not. */
	/* Heavy weights accrue less, so shares stay proportional. */
	w = flow_weight_clamp(p->scx.weight);
	tctx->vruntime += flow_scaled_delta(delta, w);
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	/* Voluntary sleep decays duty, runnable stops climb it. */
	/* Short bursts climb gently with the 1.5ms allowance. */
	vol = !runnable && !(p->flags & PF_EXITING);
	tctx->duty = flow_duty_step(tctx->duty, runnable, delta);
	/* Release drops any elevation with no second use. */
	tctx->elevated = 0;
	/* The sleep flag follows the stop cause with count kept. */
	tctx->prob = flow_prob_make(flow_prob_count(tctx->prob),
	    vol);
	/* Drop the count with the charge with no second use. */
	/* Owner only clears, so a migrated stop never clears a new owner. */
	tctx->on_cpu = 0;
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	flow_on_cpu_dec();
	/* Minimum keeps the high water mark with no queue read. */
	/* Stopping advances through the inner max with no guard while */
	/* enqueue guards idle plus empty through the shared helper with */
	/* the same max, so migration cannot drag the mark back. */
	if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
		struct flow_cpu_state *fst = flow_cpu((u32)cpu);
		if (fst) {
			fst->min_vruntime = flow_min_max(
			    fst->min_vruntime, tctx->vruntime);
		}
		/* Voluntary sleep records the waiter for the correlate. */
		/* The waking enqueue matches pid plus time on this CPU. */
		if (vol) {
			struct flow_pi_wait *pw = flow_pi((u32)cpu);
			if (pw) {
				pw->pid = (u32)p->pid;
				pw->at = now;
			}
		}
	}
	/* Stop time feeds the next wakeup with no extra field. */
	tctx->run_at = now;
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
	tctx->vruntime = 0;
	tctx->run_at = 0;
	tctx->wait_at = 0;
	tctx->slice_ns = 0;
	tctx->elev_at = 0;
	tctx->duty = 0;
	/* Fresh tasks hold two probation wakes as voluntary sleepers. */
	/* Forks share this path, so children anchor at the minimum. */
	/* Two low duty wakes graduate the task to the lane. */
	tctx->prob = flow_prob_make((u32)FLOW_PROB_CYCLES, true);
	tctx->on_cpu = 0;
	tctx->elevated = 0;
	tctx->cls = (u8)FLOW_CLS_INTERACTIVE;
	tctx->_pad[0] = 0;
	tctx->_pad[1] = 0;
	tctx->_pad[2] = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	flow_charge_leftover(cpu, p, tctx, (u32)p->pid);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	flow_charge_leftover(cpu, p, tctx, (u32)p->pid);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	struct flow_pi_wait *pw;
	(void)args;
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
	/* Drop the waiter window on the offline CPU until restart. */
	if (cpu >= 0 && (u32)cpu < (u32)FLOW_MAX_CPUS) {
		pw = flow_pi((u32)cpu);
		if (pw) {
			pw->pid = 0;
			pw->at = 0;
		}
	}
}
