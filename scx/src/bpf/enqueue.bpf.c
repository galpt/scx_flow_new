// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op for the flow core.
 *
 * Parks at the overflow tail and notifies for observability solely.
 * Exiting tasks run at once on the task CPU. The gate runs first
 * for other arrivals. One idle kick follows each park. The core
 * orders through the tree and admits under the bound in the core.
 * Dispatch moves admitted tasks in tree order. The tail parks with
 * plain insert and the tree holds the key so order never uses kernel
 * queues. Rings stay best effort with loss irrelevant to decisions.
 * One sequence allocation serves task state plus order row plus
 * observability notify so the wire stays dense. Admit writes tree
 * plus row synchronously with the same sequence, deadline, CPU so
 * dispatch needs no roundtrip. Reject parks with no key plus no row
 * plus no run. Placement picks with live checks alone and no
 * deadline quantize. The selected CPU wins when live plus allowed
 * with no drain check so warmth stays cheap. An idle CPU wins next
 * through the idle pick when live plus allowed so light work lands
 * with no scan. The first allowed live CPU wins last. The chosen
 * CPU holds the admitted share with per CPU rows and rejects park
 * with no run. Dispatch order stays least plus successor with no
 * change. Fail open stays rare since rows land synchronously.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void flow_notify_enqueue(u32 pid,
	u32 cpu, u32 weight, u64 seq)
{
	struct flow_event *ev;
	ev = bpf_ringbuf_reserve(&flow_enq_rb, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->kind = (u64)FLOW_PROTO_ENQUEUE;
	ev->seq = seq;
	ev->pid = pid;
	ev->cpu = cpu;
	ev->weight = weight;
	ev->pad = 0;
	ev->at = flow_now();
	bpf_ringbuf_submit(ev, 0);
}
static __always_inline void flow_park_plain(struct task_struct *p,
	u64 enq_flags)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(),
	    (u64)FLOW_QUANTUM_NS, enq_flags);
	__sync_fetch_and_add(&flow_stats.inserts, 1);
}
/* Park plus notify with BPF owned admission in one place. */
/* Allocates one sequence then stores it then admits synchronously */
/* with tree plus row or parks as reject with no key plus no row then */
/* parks at the tail then notifies for observability solely. Every */
/* park notifies best effort with loss irrelevant. Callers pass the */
/* chosen CPU with zero for unknown so fail closed parks still notify */
/* with no bypass. */
static __noinline void flow_enqueue_admit(struct task_struct *p,
	u64 enq_flags, u32 weight, u32 cpu,
	struct flow_task_ctx *tctx)
{
	u64 now = flow_now();
	u64 period = flow_period_ns(weight);
	u64 deadline = flow_deadline_at(now, period);
	u64 share = flow_share_permille(period);
	u64 seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
	u32 pid = (u32)p->pid;
	bool added = false;
	bool admitted = false;
	if (tctx)
		WRITE_ONCE(tctx->seq, seq);
	if (pid == 0) {
		flow_gate_reject();
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, 0);
		}
		flow_order_delete(pid);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS) {
		flow_gate_reject();
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, 0);
		}
		veb_remove(pid);
		flow_order_delete(pid);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	if (share == 0) {
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, cpu);
		}
		veb_insert(pid, deadline);
		if (flow_order_write(pid, seq, deadline, cpu)) {
			__sync_fetch_and_add(&flow_stats.admits, 1);
			admitted = true;
		} else {
			veb_remove(pid);
			if (tctx) {
				WRITE_ONCE(tctx->admit_share, 0);
				WRITE_ONCE(tctx->admit_cpu, 0);
			}
		}
	} else {
		if (flow_admit_try_add(cpu, share)) {
			added = true;
			if (tctx) {
				WRITE_ONCE(tctx->admit_share, (u32)share);
				WRITE_ONCE(tctx->admit_cpu, cpu);
			}
			veb_insert(pid, deadline);
			if (flow_order_write(pid, seq, deadline, cpu)) {
				__sync_fetch_and_add(&flow_stats.admits, 1);
				admitted = true;
			} else {
				veb_remove(pid);
				flow_admitted_sub(cpu, share);
				if (tctx) {
					WRITE_ONCE(tctx->admit_share, 0);
					WRITE_ONCE(tctx->admit_cpu, 0);
				}
			}
		}
	}
	if (admitted) {
		(void)added;
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	if (tctx) {
		WRITE_ONCE(tctx->admit_share, 0);
		WRITE_ONCE(tctx->admit_cpu, 0);
	}
	veb_remove(pid);
	flow_order_delete(pid);
	__sync_fetch_and_add(&flow_stats.rejects, 1);
	__sync_fetch_and_add(&flow_stats.parks, 1);
	flow_park_plain(p, enq_flags);
	flow_notify_enqueue(pid, cpu, weight, seq);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu;
	u32 weight;
	u64 seq_tmp;
	(void)enq_flags;
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    (u64)FLOW_QUANTUM_NS, enq_flags);
			__sync_fetch_and_add(&flow_stats.inserts, 1);
			return;
		}
	}
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	cpu = scx_bpf_task_cpu(p);
	weight = p->scx.weight;
	if (!tctx) {
		flow_gate_reject();
		seq_tmp = __sync_fetch_and_add(&flow_seq, 1) + 1;
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, seq_tmp);
		if (flow_cpu_ok(p, sel)) {
			scx_bpf_test_and_clear_cpu_idle(sel);
			scx_bpf_kick_cpu(sel, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
		return;
	}
	if (!flow_entry_ok(sel, p, 0) &&
	    !flow_entry_ok(cpu, p, 0)) {
		flow_gate_reject();
		seq_tmp = __sync_fetch_and_add(&flow_seq, 1) + 1;
		WRITE_ONCE(tctx->seq, seq_tmp);
		WRITE_ONCE(tctx->admit_share, 0);
		WRITE_ONCE(tctx->admit_cpu, 0);
		veb_remove((u32)p->pid);
		flow_order_delete((u32)p->pid);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, seq_tmp);
		return;
	}
	/* Placement with selected, idle, first in one place. */
	/* Gives selected when allowed and live else idle when allowed */
	/* and live else first when allowed and live else error with */
	/* no drain check so warmth stays cheap. The chosen CPU */
	/* holds the share with per CPU rows and rejects park with */
	/* no run. */
	{
		s32 idle;
		s32 first;
		if (sel >= 0 && flow_cpu_ok(p, sel)) {
			cpu = sel;
		} else {
			idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			if (flow_cpu_ok(p, idle)) {
				cpu = idle;
			} else {
				first = (s32)bpf_cpumask_first(
				    p->cpus_ptr);
				if (flow_cpu_ok(p, first)) {
					cpu = first;
				} else {
					flow_gate_reject();
					seq_tmp = __sync_fetch_and_add(
					    &flow_seq, 1) + 1;
					WRITE_ONCE(tctx->seq, seq_tmp);
					WRITE_ONCE(tctx->admit_share, 0);
					WRITE_ONCE(tctx->admit_cpu, 0);
					veb_remove((u32)p->pid);
					flow_order_delete((u32)p->pid);
					__sync_fetch_and_add(
					    &flow_stats.rejects, 1);
					__sync_fetch_and_add(
					    &flow_stats.parks, 1);
					flow_park_plain(p, enq_flags);
					flow_notify_enqueue((u32)p->pid,
					    0, weight, seq_tmp);
					return;
				}
			}
		}
	}
	if (!flow_cpu_ok(p, cpu)) {
		flow_gate_reject();
		seq_tmp = __sync_fetch_and_add(&flow_seq, 1) + 1;
		WRITE_ONCE(tctx->seq, seq_tmp);
		WRITE_ONCE(tctx->admit_share, 0);
		WRITE_ONCE(tctx->admit_cpu, 0);
		veb_remove((u32)p->pid);
		flow_order_delete((u32)p->pid);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue((u32)p->pid, 0, weight, seq_tmp);
		return;
	}
	flow_enqueue_admit(p, enq_flags, weight, (u32)cpu, tctx);
	{
		struct flow_cpu_state *st = flow_cpu_state_for(cpu);
		if (st && READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
