// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op for the flow core.
 *
 * Parks at the overflow tail and notifies the daemon. Exiting
 * tasks run at once on the task CPU. The gate runs first for other
 * arrivals. One idle kick follows each park. The core orders through
 * the tree and the daemon admits. Dispatch moves admitted tasks in
 * tree order. The tail parks with plain insert and the tree holds
 * the key so order never uses kernel queues. Ring reserve faults
 * count one park. One sequence allocation serves task state plus
 * wire notify so the wire stays dense.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void flow_notify_enqueue(u32 pid,
	u32 cpu, u32 weight, u64 seq)
{
	struct flow_event *ev;
	ev = bpf_ringbuf_reserve(&flow_enq_rb, sizeof(*ev), 0);
	if (!ev) {
		__sync_fetch_and_add(&flow_stats.parks, 1);
		return;
	}
	ev->kind = (u64)FLOW_PROTO_ENQUEUE;
	ev->seq = seq;
	ev->pid = pid;
	ev->cpu = cpu;
	ev->weight = weight;
	ev->pad = 0;
	ev->at = flow_now();
	bpf_ringbuf_submit(ev, 0);
}
static __always_inline void flow_park_tree(struct task_struct *p,
	u64 enq_flags, u32 weight)
{
	u64 period = flow_period_ns(weight);
	u64 deadline = flow_deadline_at(flow_now(), period);
	veb_insert((u32)p->pid, deadline);
	scx_bpf_dsq_insert(p, flow_overflow_dsq(),
	    (u64)FLOW_QUANTUM_NS, enq_flags);
	__sync_fetch_and_add(&flow_stats.inserts, 1);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu;
	u32 weight;
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
		u64 seq;
		flow_gate_reject();
		flow_park_tree(p, enq_flags, weight);
		seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
		flow_notify_enqueue((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, seq);
		if (flow_cpu_ok(p, sel)) {
			scx_bpf_test_and_clear_cpu_idle(sel);
			scx_bpf_kick_cpu(sel, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
		return;
	}
	if (!flow_entry_ok(sel, p, 0) &&
	    !flow_entry_ok(cpu, p, 0)) {
		u64 seq;
		flow_gate_reject();
		seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
		WRITE_ONCE(tctx->seq, seq);
		flow_park_tree(p, enq_flags, weight);
		flow_notify_enqueue((u32)p->pid,
		    cpu >= 0 ? (u32)cpu : 0, weight, seq);
		if (flow_cpu_ok(p, sel)) {
			scx_bpf_test_and_clear_cpu_idle(sel);
			scx_bpf_kick_cpu(sel, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
		return;
	}
	if (sel >= 0 && flow_cpu_ok(p, sel))
		cpu = sel;
	else if (!flow_cpu_ok(p, cpu))
		cpu = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_ok(p, cpu)) {
		u64 seq;
		flow_gate_reject();
		seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
		WRITE_ONCE(tctx->seq, seq);
		flow_park_tree(p, enq_flags, weight);
		flow_notify_enqueue((u32)p->pid, 0, weight, seq);
		return;
	}
	{
		u64 seq;
		seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
		WRITE_ONCE(tctx->seq, seq);
		flow_park_tree(p, enq_flags, weight);
		flow_notify_enqueue((u32)p->pid, (u32)cpu, weight, seq);
	}
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		if (st && READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
