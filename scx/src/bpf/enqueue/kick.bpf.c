// SPDX-License-Identifier: GPL-2.0
/*
 * Kick after park for the enqueue path.
 *
 * Gives the chosen CPU the kick when its running view is empty else
 * one idle peer in the task mask so backlog pulls work with no idle
 * wait. The peer stays apart from the chosen CPU with mask wins and
 * the woken CPU takes the earliest key it may run so vEB order never
 * changes. When no idle peer stays live the wakeup may preempt its
 * owner directly with one directed kick so urgent arrivals never wait
 * behind a full slice on a busy CPU. The preempt fires solely when
 * the wakeup holds an order row and the owner runs a longer deadline
 * task, checked with the same deadline compare as dispatch order, so
 * equal or earlier owners never bounce. A running task with no row
 * counts as longer, so an admitted wakeup still preempts a reject
 * run. At most one kick lands per park with no call when the wakeup
 * holds no row or the owner already runs the earlier deadline, so no
 * storm forms under flood. Runs inline so the caller keeps task
 * context with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Kick with chosen plus idle peer plus owner preempt in one place. */
/* Gives the chosen CPU the kick when its running view is empty else */
/* one idle peer in the task mask so backlog pulls work with no idle */
/* wait. The peer stays apart from the chosen CPU with mask wins and */
/* the woken CPU takes the earliest key it may run so vEB order never */
/* changes. With no idle peer the owner takes one preempt kick solely */
/* when the wakeup holds a row and runs earlier than the owner task, */
/* so urgent arrivals preempt longer runs with no storm. At most one */
/* kick lands per park. */
static __always_inline void flow_kick_after_park(s32 cpu,
	struct task_struct *p)
{
	struct flow_cpu_state *st = flow_cpu_state_for(cpu);
	if (st && READ_ONCE(st->running_pid) == 0) {
		scx_bpf_test_and_clear_cpu_idle(cpu);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
		return;
	}
	{
		s32 peer = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (peer != cpu && flow_cpu_ok(p, peer)) {
			scx_bpf_test_and_clear_cpu_idle(peer);
			scx_bpf_kick_cpu(peer, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
	}
	/* No idle peer stays live, so consider one directed preempt. */
	/* No separate preempt compare lives elsewhere, so the deadline */
	/* compare here reuses the same earlier wins order as dispatch. */
	if (st) {
		u32 wpid = (u32)p->pid;
		u32 rpid = READ_ONCE(st->running_pid);
		u64 wdead;
		u64 rdead;
		if (wpid == 0)
			return;
		if (rpid == 0)
			return;
		wdead = flow_order_deadline(wpid);
		if (wdead == 0)
			return;
		rdead = flow_order_deadline(rpid);
		if (rdead == 0) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		if (flow_time_before(wdead, rdead)) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
