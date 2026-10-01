// SPDX-License-Identifier: GPL-2.0
/*
 * Kick after park for the enqueue path.
 *
 * Gives the chosen CPU the kick when its running view is empty else
 * one idle peer in the task mask so backlog pulls work with no idle
 * wait. The peer stays apart from the chosen CPU with mask wins and
 * the woken CPU takes the earliest key it may run so vEB order never
 * changes. At most one kick lands per park with no call when no idle
 * CPU stays live. Runs inline so the caller keeps task context with
 * no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Kick with chosen plus idle peer in one place. */
/* Gives the chosen CPU the kick when its running view is */
/* empty else one idle peer in the task mask so backlog pulls */
/* work with no idle wait. The peer stays apart from the chosen */
/* CPU with mask wins and the woken CPU takes the earliest key */
/* it may run so vEB order never changes. At most one kick lands */
/* per park with no call when no idle CPU stays live. */
static __always_inline void flow_kick_after_park(s32 cpu,
	struct task_struct *p)
{
	struct flow_cpu_state *st = flow_cpu_state_for(cpu);
	if (st && READ_ONCE(st->running_pid) == 0) {
		scx_bpf_test_and_clear_cpu_idle(cpu);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	} else {
		s32 peer = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (peer != cpu && flow_cpu_ok(p, peer)) {
			scx_bpf_test_and_clear_cpu_idle(peer);
			scx_bpf_kick_cpu(peer, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
