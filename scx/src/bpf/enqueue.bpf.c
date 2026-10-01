// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op for the flow core.
 *
 * Parks at the overflow tail and notifies for observability solely.
 * Exiting tasks run at once on the task CPU. The gate runs first
 * for other arrivals. One kick follows each admitted park to the chosen CPU
 * when its running view is empty else to one idle peer in the task
 * mask so backlog pulls work with no idle wait. The core orders
 * through the tree and admits under the bound in the core. Dispatch
 * moves admitted tasks in tree order. The tail parks with plain
 * insert and the tree holds the key so order never uses kernel
 * queues. Rings stay best effort with loss irrelevant to decisions.
 * One sequence allocation serves task state plus order row plus
 * observability notify so the wire stays dense. Admit writes tree
 * plus row synchronously with the same sequence, deadline, CPU so
 * dispatch needs no roundtrip. Reject parks with no key plus no row
 * plus no run. Placement picks with live checks alone and no
 * deadline quantize. An idle CPU wins first through the idle pick
 * when live plus allowed so load spreads with no scan. The selected
 * CPU wins next when live plus allowed with no drain check so warmth
 * stays cheap under load. The first allowed live CPU wins last. The
 * chosen CPU holds the admitted share with per CPU rows and rejects
 * park with no run. Dispatch order stays least plus successor with
 * no change. Fail open stays rare since rows land synchronously.
 *
 * The op splits across enqueue/notify, park, kick files. Notify plus
 * park plus admission stay noinline with scalar inputs and the kick
 * stays inline, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/notify.bpf.c"
#include "enqueue/park.bpf.c"
#include "enqueue/kick.bpf.c"
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
	/* Placement with idle, selected, first in one place. */
	/* Gives idle when allowed and live else selected when allowed */
	/* and live else first when allowed and live else error with */
	/* no drain check so spread stays cheap with warmth under load. */
	/* The chosen CPU holds the share with per CPU rows and rejects */
	/* park with no run. */
	{
		s32 idle;
		s32 first;
		idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (flow_cpu_ok(p, idle)) {
			cpu = idle;
		} else if (sel >= 0 && flow_cpu_ok(p, sel)) {
			cpu = sel;
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
	flow_kick_after_park(cpu, p);
}
