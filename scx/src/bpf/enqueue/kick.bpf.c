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
 * behind a full slice on a busy CPU. The preempt runs through a pure
 * earlier check plus a single kick entry, so no path kicks without
 * the check. The check uses the same deadline compare as dispatch
 * order, so equal or earlier owners never bounce. A running task
 * with no row counts as longer, so an admitted wakeup still preempts
 * a reject run. At most one kick lands per park with no call when
 * the wakeup holds no row or the owner already runs the earlier
 * deadline, so no storm forms under flood. Runs inline so the caller
 * keeps task context with no extra call cost.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Kick with chosen plus idle peer plus owner preempt in one place. */
/* Gives the chosen CPU the kick when its running view is empty else */
/* one idle peer in the task mask so backlog pulls work with no idle */
/* wait. The peer stays apart from the chosen CPU with mask wins and */
/* the woken CPU takes the earliest key it may run so vEB order never */
/* changes. With no idle peer the owner takes one preempt kick solely */
/* through the paired check plus kick entry, so urgent arrivals */
/* preempt longer runs with no storm. At most one kick lands per park. */
/* Pure earlier check with no map use in one place. */
/* Gives true when the arrival deadline runs strictly before the */
/* occupant deadline, with a missing occupant row counting as longer */
/* so an admitted arrival still preempts a reject run. A missing */
/* arrival row never preempts, so equal or earlier owners never bounce. */
static __always_inline bool flow_preempt_want(u64 arrival, u64 occupant)
{
	if (arrival == 0)
		return false;
	if (occupant == 0)
		return true;
	return flow_time_before(arrival, occupant);
}
/* Safe directed kick with every gate plus one kick site in one place. */
/* Holds target live plus allowed plus running plus earlier plus self */
/* plus exiting checks here, so callers cannot kick blindly. The target */
/* stays live plus allowed through the mask check, so a pinned arrival */
/* only preempts a CPU it may run on. A zero running pid skips, so an */
/* idle CPU never takes a directed kick. A self pid skips, so a task */
/* never preempts itself. An exiting arrival skips, so teardown never */
/* preempts. Task state gives the arrival deadline with the order */
/* row giving the occupant deadline, so the wakeup path pays one */
/* store lookup with the pure check deciding, and the kick stays */
/* strictly earlier with at most one kick per park through the */
/* single call site. */
static __always_inline void flow_preempt_kick(s32 cpu,
	struct task_struct *p)
{
	struct flow_cpu_state *st;
	struct flow_task_ctx *wtctx;
	u32 wpid;
	u32 rpid;
	u64 wdead;
	u64 rdead;
	if (!p)
		return;
	if (p->flags & PF_EXITING)
		return;
	if (!flow_cpu_ok(p, cpu))
		return;
	st = flow_cpu_state_for(cpu);
	if (!st)
		return;
	wpid = (u32)p->pid;
	if (wpid == 0)
		return;
	rpid = READ_ONCE(st->running_pid);
	if (rpid == 0)
		return;
	if (wpid == rpid)
		return;
	wtctx = flow_lookup(p);
	wdead = wtctx ? READ_ONCE(wtctx->deadline) : 0;
	rdead = flow_order_deadline(rpid);
	if (!flow_preempt_want(wdead, rdead))
		return;
	scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	__sync_fetch_and_add(&flow_stats.kicks, 1);
}
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
	/* No idle peer stays live, so try one safe directed preempt. */
	/* The paired entry holds every gate with one kick site, so this */
	/* call never kicks blindly and never exceeds one kick per park. */
	flow_preempt_kick(cpu, p);
}
