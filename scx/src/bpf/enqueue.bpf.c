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
 * wire notify so the wire stays dense. One park helper pairs sequence,
 * tree insert, notify through one exit so a parked task never misses
 * its notify. Placement derives one deadline from weight derived
 * period plus now then quantizes to one key with the same quantize
 * as the tree so placement shares the order source with dispatch.
 * The selected CPU wins when live plus allowed with no drain check
 * so warmth stays cheap. An idle CPU wins next through the idle pick
 * when live plus allowed so light work lands with no scan. The first
 * allowed live CPU wins last. The chosen CPU feeds the notify so the
 * daemon admits against it with per CPU rows and rejects park with
 * no run. Dispatch order stays least plus successor with no change.
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
/* Park plus notify with sequence in one place. */
/* Allocates one sequence then stores it when state lives then parks */
/* with tree insert then notifies the daemon. Every park reaches the */
/* daemon with no missed notify. Callers pass zero for unknown CPUs */
/* so fail closed parks still notify with no bypass. */
static __noinline void flow_enqueue_park(struct task_struct *p,
	u64 enq_flags, u32 weight, u32 cpu_notify,
	struct flow_task_ctx *tctx)
{
	u64 seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
	if (tctx)
		WRITE_ONCE(tctx->seq, seq);
	flow_park_tree(p, enq_flags, weight);
	flow_notify_enqueue((u32)p->pid, cpu_notify, weight, seq);
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
		flow_gate_reject();
		flow_enqueue_park(p, enq_flags, weight,
		    cpu >= 0 ? (u32)cpu : 0, 0);
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
		flow_enqueue_park(p, enq_flags, weight,
		    cpu >= 0 ? (u32)cpu : 0, tctx);
		return;
	}
	/* Placement with selected, idle, first in one place. */
	/* Gives selected when allowed and live else idle when allowed */
	/* and live else first when allowed and live else error. Shares */
	/* the deadline source with the tree through the same quantize */
	/* with no drain check so warmth stays cheap. The chosen CPU */
	/* feeds the notify so the daemon admits against it with per CPU */
	/* rows and rejects park with no run. */
	{
		u64 period = flow_period_ns(weight);
		u64 deadline = flow_deadline_at(flow_now(), period);
		u32 key = veb_quant(deadline);
		s32 idle;
		s32 first;
		if (key >= (u32)FLOW_VEB_U) {
			flow_gate_reject();
			flow_enqueue_park(p, enq_flags, weight, 0,
			    tctx);
			return;
		}
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
					flow_enqueue_park(p, enq_flags,
					    weight, 0, tctx);
					return;
				}
			}
		}
	}
	if (!flow_cpu_ok(p, cpu)) {
		flow_gate_reject();
		flow_enqueue_park(p, enq_flags, weight, 0, tctx);
		return;
	}
	flow_enqueue_park(p, enq_flags, weight, (u32)cpu, tctx);
	{
		struct flow_cpu_state *st = flow_cpu_state_for(cpu);
		if (st && READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
