// SPDX-License-Identifier: GPL-2.0
/*
 * SMT sibling reservation for the flow scheduler, enabled by --performance.
 *
 * The two hardware threads of a core share its execution units and its
 * caches, so a game thread gets noticeably less done per millisecond while
 * its sibling computes without a break than while the sibling is idle.
 * Under load, that costs a game more frames than waiting for a CPU does.
 * While a task that flow considers urgent runs on one hardware thread, the
 * other one therefore does not run a hog, that is a task that has been
 * computing for a boosted slice or more and is less latency critical than
 * the urgent task. It runs any other task or goes idle instead, which
 * gives up some throughput on purpose. A hog of the same process as the
 * urgent task is not held back, since a game may be waiting for its own
 * heavy threads, and neither is a task that exits.
 *
 * Each CPU publishes in its own state whether its task guards the sibling,
 * the process of that task and from when the task counts as a hog. The
 * sibling reads these without locks. When an urgent task starts running,
 * a hog on the sibling is asked to switch, as soon as it has had a minimum
 * slice, by the urgent task or by the tick of the hog. ops.dispatch() of
 * the sibling neither gives a hog a new slice nor pulls one from any DSQ,
 * and a hog that it holds back is no reason for its tick or its
 * ops.dispatch() to take the CPU away from the task it runs. A hog that
 * wakes up or is queued again only claims an idle CPU next to no urgent
 * task, so that the idle CPUs next to urgent tasks are left to the
 * wakeups that may use them.
 *
 * A hog is held back for FLOW_HOLD_NS at most. After that, it may run next
 * to an urgent task, and it keeps its CPU for the slice it starts with. A
 * CPU that goes idle while a hog waits for it notes since when the hog
 * has been waiting. Its sibling wakes it up when it stops guarding it, or
 * from its tick once the wait reaches FLOW_HOLD_NS. The statistics timer
 * catches the wakeups that the sibling leaves out or misses.
 *
 * Since this leaves CPUs idle under load, a CPU picked for a wakeup may
 * already be on its way to run another task. Wakeups that go straight to
 * an idle CPU are therefore queued there only if they can run right away,
 * and go through ops.enqueue() otherwise, see flow_select_cpu().
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SIBLING_BPF_H
#define __FLOW_SIBLING_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

/* What a CPU sees of the urgent task on its sibling. */
struct flow_guard {
	u64	now;
	u64	held;		/* earliest wait of a hog held back, 0 if none */
	u32	tgid;		/* process of the urgent task, 0 if there is none */
	u32	lat_cri;	/* its latency criticality */
};

/*
 * The other hardware thread of @cpu, or -1 if there is none. Cores with
 * more than two threads are left alone, since their threads do not pair
 * up in the sibling table.
 */
static __always_inline s32 flow_smt_peer(s32 cpu)
{
	u32 sib;

	if (!flow_cpu_valid(cpu))
		return -1;
	sib = flow_cpu_sibling[cpu];
	if (sib == cpu || sib >= flow_nr_cpus || sib >= FLOW_MAX_CPUS ||
	    flow_cpu_sibling[sib] != cpu)
		return -1;
	return sib;
}

/* @t computes for a boosted slice or more at a time, if its burst is @acc. */
static __always_inline bool flow_long_runner(const struct flow_task_ctx *t, u64 acc)
{
	return flow_max(t->avg_runtime_ns, acc) >= FLOW_SLICE_BOOST_MAX_NS;
}

/* @t is urgent and no hog, so it keeps hogs off the sibling of its CPU. */
static __always_inline bool flow_guards(const struct flow_task_ctx *t)
{
	u64 bar = READ_ONCE(flow_sys_stat.thr_lat_cri);

	return bar && t->lat_cri >= bar && !flow_long_runner(t, t->acc_runtime_ns);
}

/*
 * Fill in @g from the state of the sibling of @cpu. An urgent task that
 * has computed for a boosted slice since it started counts as a hog
 * itself, and guards nothing anymore.
 */
static __always_inline void flow_read_guard(s32 cpu, struct flow_guard *g)
{
	s32 sib = flow_smt_peer(cpu);
	struct flow_cpu_state *cs;

	g->held = 0;
	g->tgid = 0;
	if (sib < 0 || sib >= FLOW_MAX_CPUS)
		return;
	cs = &flow_cpu_states[sib];
	g->tgid = READ_ONCE(cs->guard_tgid);
	if (!g->tgid)
		return;
	g->now = flow_now();
	g->lat_cri = READ_ONCE(cs->lat_cri);
	if (!g->lat_cri || !time_before(g->now, READ_ONCE(cs->hog_clk)))
		g->tgid = 0;
}

/*
 * @p, whose current burst is @acc, is a hog that the urgent task of @g
 * keeps off its sibling.
 */
static __always_inline bool flow_hog_held(const struct task_struct *p,
					  const struct flow_task_ctx *t, u64 acc,
					  const struct flow_guard *g)
{
	return g->tgid && (u32)p->tgid != g->tgid && t->lat_cri < g->lat_cri &&
	       flow_long_runner(t, acc) && !(p->flags & PF_EXITING);
}

/*
 * @p waits in a DSQ and is held back by @g, unless it has been waiting for
 * FLOW_HOLD_NS already. The earliest wait among the tasks held back goes to
 * @g.
 */
static bool flow_queued_held(struct task_struct *p, struct flow_guard *g)
{
	struct flow_task_ctx *t;
	u64 ready;

	if (!g->tgid || (u32)p->tgid == g->tgid)
		return false;
	t = flow_task_ctx(p);
	if (!t || !flow_hog_held(p, t, t->acc_runtime_ns, g))
		return false;
	ready = t->ready_clk;
	if (!time_before(g->now, ready + FLOW_HOLD_NS))
		return false;
	if (!g->held || time_before(ready, g->held))
		g->held = ready;
	return true;
}

/*
 * Claim an idle CPU for the hog @p, whose current burst is @acc, that no
 * urgent task next to it holds @p back from: a CPU of a fully idle core,
 * then @prev_cpu or one of a few random idle CPUs whose sibling guards
 * nothing against @p. CPUs are only claimed once they qualify, so that
 * idle CPUs next to urgent tasks are left to the wakeups that may use
 * them. Returns -EBUSY if there is no such CPU. @p then waits in its DSQ
 * until a CPU dispatches it, or notes its wait and holds it back, see
 * flow_guard_idle().
 */
static s32 flow_pick_hog_cpu(struct task_struct *p, const struct flow_task_ctx *t,
			     s32 prev_cpu, u64 wake_flags, u64 acc)
{
	const struct cpumask *idle;
	struct flow_guard g;
	s32 cpu, probe;
	u32 i;

	cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, SCX_PICK_IDLE_CORE);
	if (cpu >= 0)
		return cpu;

	cpu = -EBUSY;
	idle = scx_bpf_get_idle_cpumask();
	bpf_for(i, 0, FLOW_VICTIM_PROBES + 1) {
		probe = i ? bpf_cpumask_any_and_distribute(idle, p->cpus_ptr) : prev_cpu;
		if (!flow_cpu_valid(probe) || !bpf_cpumask_test_cpu(probe, idle) ||
		    !bpf_cpumask_test_cpu(probe, p->cpus_ptr))
			continue;
		flow_read_guard(probe, &g);
		if (flow_hog_held(p, t, acc, &g) || !scx_bpf_test_and_clear_cpu_idle(probe))
			continue;
		cpu = probe;
		break;
	}
	scx_bpf_put_idle_cpumask(idle);
	return cpu;
}

/*
 * Wake up @sib, which went idle for a hog held back by its sibling, now
 * that the sibling stops guarding it at @now. A hog that an urgent task
 * pushed off less than a minimum slice ago is left waiting. It would come
 * back each time that task sleeps, only to be pushed off again when the
 * task wakes up, which costs an IPI per wakeup to a task that runs in
 * tiny bursts. The tick of the sibling and the statistics timer wake @sib
 * up later if the sibling does not guard it anymore.
 */
static void flow_wake_holder(s32 sib, u64 now)
{
	u64 held;

	if (sib < 0 || sib >= FLOW_MAX_CPUS)
		return;
	held = READ_ONCE(flow_cpu_states[sib].hold_clk);
	if (held && !time_before(now, held + FLOW_SLICE_MIN_NS))
		scx_bpf_kick_cpu(sib, SCX_KICK_IDLE);
}

/*
 * @p starts running on @cpu at @now. Publish whether it guards the
 * sibling, and from when it counts as a hog. A hog that waited for
 * FLOW_HOLD_NS does not count as one for the slice it starts with, so
 * that an urgent task next to it cannot take its CPU away right after the
 * wait. When @p guards the sibling, a hog running there is asked to
 * switch once it has run for a minimum slice, see flow_guard_tick(). A hog
 * that is pushed off as soon as it starts makes no progress, and each
 * start would begin its wait anew. When the CPU stops guarding, a sibling
 * that went idle because of it is woken up.
 */
static void flow_guard_running(struct task_struct *p, const struct flow_task_ctx *t, s32 cpu,
			       struct flow_cpu_state *cs, u64 now)
{
	u32 tgid = p->tgid, prev = cs->guard_tgid, guard = 0;
	u64 acc = t->acc_runtime_ns, hog;
	s32 sib = flow_smt_peer(cpu);
	struct flow_cpu_state *scs;
	u32 lat;

	if (!flow_long_runner(t, acc))
		hog = now + FLOW_SLICE_BOOST_MAX_NS - acc;
	else if (time_before(now, t->ready_clk + FLOW_HOLD_NS))
		hog = now;
	else
		hog = now + p->scx.slice;
	if (sib >= 0 && flow_guards(t))
		guard = tgid;

	WRITE_ONCE(cs->tgid, tgid);
	WRITE_ONCE(cs->hog_clk, hog);
	if (cs->hold_clk)
		WRITE_ONCE(cs->hold_clk, 0);
	if (guard != prev)
		WRITE_ONCE(cs->guard_tgid, guard);
	if (sib < 0 || sib >= FLOW_MAX_CPUS)
		return;

	scs = &flow_cpu_states[sib];
	if (guard) {
		lat = READ_ONCE(scs->lat_cri);
		if (lat && lat < t->lat_cri && READ_ONCE(scs->tgid) != guard &&
		    !time_before(now, READ_ONCE(scs->hog_clk) + FLOW_SLICE_MIN_NS)) {
			scx_bpf_kick_cpu(sib, SCX_KICK_PREEMPT);
			flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
		}
	}
	if (prev && prev != guard)
		flow_wake_holder(sib, now);
}

/*
 * @cpu runs out of tasks or loses its CPU to a realtime or deadline task.
 * It notes since when a hog that it held back has been waiting, @held, or
 * zero, and wakes up its sibling if that went idle because of it.
 */
static void flow_guard_idle(s32 cpu, struct flow_cpu_state *cs, u64 held)
{
	WRITE_ONCE(cs->hold_clk, held);
	if (!cs->guard_tgid)
		return;
	WRITE_ONCE(cs->guard_tgid, 0);
	flow_wake_holder(flow_smt_peer(cpu), flow_now());
}

/*
 * The tick of a busy @cpu at @now wakes up its sibling if that went idle
 * for a hog that has now been waiting for FLOW_HOLD_NS, or if @cpu does
 * not guard it anymore. It also ends the slice of @p, which has computed
 * for @acc since it woke up, if @p is a hog that @g holds back and that
 * has had its minimum slice since it started counting as one, as the
 * urgent task on the sibling may have started too early to push it off.
 * Returns whether the slice of @p was ended.
 */
static bool flow_guard_tick(struct task_struct *p, const struct flow_task_ctx *t, u64 acc,
			    s32 cpu, const struct flow_cpu_state *cs, const struct flow_guard *g,
			    u64 now)
{
	s32 sib = flow_smt_peer(cpu);
	u64 held;

	if (sib < 0 || sib >= FLOW_MAX_CPUS)
		return false;
	held = READ_ONCE(flow_cpu_states[sib].hold_clk);
	if (held && (!time_before(now, held + FLOW_HOLD_NS) || !READ_ONCE(cs->guard_tgid) ||
		     !time_before(now, READ_ONCE(cs->hog_clk))))
		scx_bpf_kick_cpu(sib, SCX_KICK_IDLE);

	if (!flow_hog_held(p, t, acc, g) ||
	    time_before(now, READ_ONCE(cs->hog_clk) + FLOW_SLICE_MIN_NS))
		return false;
	scx_bpf_task_set_slice(p, 0);
	return true;
}

/*
 * The statistics timer wakes up @cpu at @now if it has been idle for a hog
 * that has now been waiting for FLOW_HOLD_NS, or whose sibling does not
 * guard it anymore. Its sibling may have left the wakeup to the timer, see
 * flow_wake_holder(), or missed it, as when the two stop guarding and
 * holding back at the same time.
 */
static void flow_guard_timer(s32 cpu, const struct flow_cpu_state *cs, u64 now)
{
	u64 held = READ_ONCE(cs->hold_clk);
	struct flow_guard g;

	if (!held)
		return;
	flow_read_guard(cpu, &g);
	if (!g.tgid || !time_before(now, held + FLOW_HOLD_NS))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

#endif /* __FLOW_SIBLING_BPF_H */
