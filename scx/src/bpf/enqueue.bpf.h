// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Pinned tasks wait in the DSQ of their CPU and everything else waits in
 * the DSQ of the LLC of its CPU, both ordered by virtual deadline. Every
 * path through ops.enqueue() inserts the task exactly once.
 *
 * After the insert, flow looks for an idle CPU to wake up. If there is
 * none and the task is urgent enough, it asks the running task with the
 * lowest latency criticality in the LLC to give up its CPU. The request
 * shortens the slice of that task instead of sending an IPI, so the CPU
 * switches at its next scheduling point. With --helicoprion, a short task
 * that wakes up while every CPU computes also interrupts a CPU whose task
 * has been computing for a long time, right away.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"

struct flow_victim {
	s32	cpu;
	u32	lat_cri;
	u64	est_stop;
};

static __always_inline void flow_mark_pinned(struct flow_task_ctx *t, s32 cpu)
{
	if (t->pinned_cpu >= 0)
		return;
	t->pinned_cpu = cpu;
	__sync_fetch_and_add(&flow_cpu_states[cpu].nr_pinned, 1);
}

static __always_inline void flow_clear_pinned(struct flow_task_ctx *t)
{
	s32 cpu = t->pinned_cpu;

	if (cpu < 0)
		return;
	t->pinned_cpu = -1;
	if (flow_cpu_valid(cpu))
		__sync_fetch_and_sub(&flow_cpu_states[cpu].nr_pinned, 1);
}

/*
 * Wake up an idle CPU that can run @p. A pinned task can only use @cpu.
 * When ops.select_cpu() already looked for an idle CPU and found none,
 * there is no point in searching again.
 */
static bool flow_kick_idle(struct task_struct *p, const struct flow_task_ctx *t, s32 cpu,
			   bool pinned, u64 enq_flags)
{
	s32 idle;

	if (pinned)
		idle = scx_bpf_test_and_clear_cpu_idle(cpu) ? cpu : -EBUSY;
	else if (!__COMPAT_is_enq_cpu_selected(enq_flags))
		idle = flow_pick_idle_cpu(p, t, cpu, 0);
	else
		return false;

	if (idle < 0)
		return false;
	scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
	flow_stat_inc(FLOW_STAT_KICK_IDLE);
	return true;
}

/*
 * A CPU is a victim candidate when its task is less latency critical than
 * the enqueued one and is expected to keep the CPU for longer. A CPU with
 * no stop stamp is idle or was already claimed by another enqueue.
 */
static bool flow_probe_victim(s32 cpu, u32 lat_cri, u64 est_stop, struct flow_victim *v)
{
	struct flow_cpu_state *cs;
	u64 stop;
	u32 victim_lat_cri;

	if (!flow_cpu_valid(cpu))
		return false;
	cs = &flow_cpu_states[cpu];
	stop = READ_ONCE(cs->est_stopping_clk);
	victim_lat_cri = READ_ONCE(cs->lat_cri);
	if (!stop || victim_lat_cri >= lat_cri || !time_after(stop, est_stop))
		return false;

	v->cpu = cpu;
	v->lat_cri = victim_lat_cri;
	v->est_stop = stop;
	return true;
}

/*
 * Claim the victim by clearing its stop stamp, so that concurrent
 * enqueues pick someone else, then shorten the slice of its task. A slice
 * of one nanosecond, rather than zero, keeps the kernel from refilling it
 * with the default slice.
 */
static bool flow_ask_yield(const struct flow_victim *v)
{
	struct task_struct *curr;
	bool asked = false;

	if (!flow_cpu_valid(v->cpu))
		return false;
	if (!__sync_bool_compare_and_swap(&flow_cpu_states[v->cpu].est_stopping_clk,
					  v->est_stop, 0))
		return false;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(v->cpu);
	if (curr && curr->pid)
		asked = scx_bpf_task_set_slice(curr, 1);
	bpf_rcu_read_unlock();
	return asked;
}

/*
 * Look for a victim among the CPUs of the LLC that @p can use. @cpu is
 * checked first, then a few random CPUs, and the better of the first two
 * candidates wins. Random probes keep enqueues on different CPUs from
 * all going after the same victim.
 */
static void flow_try_preempt(struct task_struct *p, struct flow_task_ctx *t, s32 cpu, u32 llc)
{
	struct flow_victim cand[2];
	struct bpf_cpumask *llc_mask;
	u64 thr = READ_ONCE(flow_sys_stat.thr_lat_cri);
	u64 est_stop;
	u32 nr = 0, i;

	if (!thr || t->lat_cri < thr)
		return;

	est_stop = flow_est_stop(t, t->acc_runtime_ns, READ_ONCE(flow_sys_stat.slice_ns),
				 scx_bpf_now());
	if (flow_probe_victim(cpu, t->lat_cri, est_stop, &cand[0]))
		nr = 1;

	llc_mask = MEMBER_VPTR(flow_llc_cpumask, [llc]);
	if (llc_mask) {
		bpf_for(i, 0, FLOW_VICTIM_PROBES) {
			s32 probe;

			if (nr >= 2)
				break;
			probe = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), p->cpus_ptr);
			if (probe == cpu || (nr && probe == cand[0].cpu))
				continue;
			if (flow_probe_victim(probe, t->lat_cri, est_stop,
					      nr ? &cand[1] : &cand[0]))
				nr++;
		}
	}

	if (!nr)
		return;
	if (nr == 2 && (cand[1].lat_cri < cand[0].lat_cri ||
			(cand[1].lat_cri == cand[0].lat_cri &&
			 time_after(cand[1].est_stop, cand[0].est_stop))))
		cand[0] = cand[1];
	if (flow_ask_yield(&cand[0]))
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
}

/*
 * The task on @cpu has been computing for longer than a boosted slice since
 * it last woke up and is less latency critical than @t.
 */
static bool flow_is_hog(const struct flow_task_ctx *t, s32 cpu, u64 now)
{
	return flow_cpu_valid(cpu) &&
	       now - READ_ONCE(flow_cpu_states[cpu].burst_start_clk) >= FLOW_SLICE_BOOST_MAX_NS &&
	       READ_ONCE(flow_cpu_states[cpu].lat_cri) < t->lat_cri;
}

/*
 * A task that runs in short bursts and wakes up while every CPU computes
 * would wait up to a tick for a CPU. It would get that CPU time at the tick
 * anyway, so the first hog among @cpu and a few random CPUs of the LLC is
 * interrupted right away instead, which costs the hog no more than an IPI.
 * Returns whether a CPU was interrupted, so that no other one is asked to
 * give up its CPU as well.
 */
static bool flow_preempt_hog(struct task_struct *p, const struct flow_task_ctx *t, s32 cpu,
			     u32 llc, u64 enq_flags)
{
	struct bpf_cpumask *llc_mask;
	u64 now;
	u32 i;

	if (!(enq_flags & SCX_ENQ_WAKEUP) || t->avg_runtime_ns >= FLOW_SLICE_MIN_NS)
		return false;

	now = scx_bpf_now();
	if (flow_is_hog(t, cpu, now)) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
		return true;
	}

	llc_mask = MEMBER_VPTR(flow_llc_cpumask, [llc]);
	if (!llc_mask)
		return false;
	bpf_for(i, 0, FLOW_VICTIM_PROBES) {
		s32 probe = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), p->cpus_ptr);

		if (probe == cpu || !flow_is_hog(t, probe, now))
			continue;
		scx_bpf_kick_cpu(probe, SCX_KICK_PREEMPT);
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
		return true;
	}
	return false;
}

void BPF_STRUCT_OPS(flow_runnable, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t, *wt;
	struct task_struct *waker;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;
	t = flow_task_ctx(p);
	if (!t)
		return;
	t->acc_runtime_ns = 0;

	waker = bpf_get_current_task_btf();
	wt = flow_task_ctx(waker);
	if (wt)
		flow_note_wakeup(t, wt, scx_bpf_now());
}

/*
 * @p was preempted by the wakee it just handed its CPU to, see
 * flow_sync_handoff(). It waits for the reply of the wakee as if it slept,
 * so its burst ends here, and it resumes on the same CPU after the wakee.
 * Pinned tasks waiting for the CPU get to run first if they are due
 * before it.
 */
static void flow_requeue_yielded(struct task_struct *p, struct flow_task_ctx *t, s32 cpu,
				 u64 enq_flags)
{
	u64 deadline;

	t->flags &= ~FLOW_FLAG_YIELDED;
	t->avg_runtime_ns = flow_calc_avg(t->avg_runtime_ns, t->acc_runtime_ns);
	deadline = flow_handoff_deadline(p, t, scx_bpf_now());
	if (READ_ONCE(flow_cpu_states[cpu].nr_pinned)) {
		scx_bpf_dsq_insert_vtime(p, FLOW_CPU_DSQ_BASE + cpu, FLOW_SYNC_SLICE_NS, deadline,
					 enq_flags);
		return;
	}
	scx_bpf_task_set_dsq_vtime(p, deadline);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, FLOW_SYNC_SLICE_NS, enq_flags);
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 deadline, slice, dsq_id;
	bool pinned;
	u32 llc;

	/*
	 * An affinity change re-enqueues the task before it is migrated, so
	 * its current CPU can be outside of the new mask.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		cpu = bpf_cpumask_first(p->cpus_ptr);

	if (!t || !flow_cpu_valid(cpu)) {
		scx_bpf_dsq_insert(p, FLOW_FALLBACK_DSQ, FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(FLOW_STAT_FALLBACK);
		return;
	}

	/*
	 * With --helicoprion, the work of ops.runnable() and ops.stopping() is
	 * done here for tasks that did not go through ops.select_cpu(), see
	 * flow_wake_task().
	 */
	if (flow_helicoprion) {
		if (!(enq_flags & SCX_ENQ_WAKEUP)) {
			flow_charge_exec(p, t);
			flow_stat_inc(FLOW_STAT_PREEMPTED);
			if (t->flags & FLOW_FLAG_YIELDED) {
				flow_requeue_yielded(p, t, cpu, enq_flags);
				return;
			}
		} else if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
			struct task_struct *waker = bpf_get_current_task_btf();

			flow_wake_task(p, t, waker, flow_task_ctx(waker), scx_bpf_now());
		}
	}

	pinned = flow_is_pinned(p);
	llc = flow_llc_of(cpu);
	deadline = flow_score_task(p, t);
	slice = flow_calc_slice(t, cpu);
	if (pinned) {
		flow_mark_pinned(t, cpu);
		dsq_id = FLOW_CPU_DSQ_BASE + cpu;
	} else {
		dsq_id = FLOW_LLC_DSQ_BASE + llc;
	}
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, deadline, enq_flags);

	/*
	 * The last runnable task of a CPU whose slice ran out is picked up
	 * again by that CPU, so waking another one would only migrate it.
	 */
	if (enq_flags & SCX_ENQ_LAST)
		return;
	if (flow_kick_idle(p, t, cpu, pinned, enq_flags))
		return;
	if (flow_helicoprion && flow_preempt_hog(p, t, cpu, llc, enq_flags))
		return;
	flow_try_preempt(p, t, cpu, llc);
}

void BPF_STRUCT_OPS(flow_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);

	if (!t)
		return;

	/* A pinned task can leave its DSQ without running, e.g. on an affinity change. */
	flow_clear_pinned(t);

	/* The burst ends here, so it can be folded in as a whole. */
	if (deq_flags & SCX_DEQ_SLEEP)
		flow_end_burst(t, scx_bpf_now());
}

/*
 * A pinned task that moves to another scheduling class while it is queued
 * never runs here again, so it stops counting as waiting for its CPU.
 * ops.quiescent() already does this, but --helicoprion leaves it out.
 */
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *t = flow_task_ctx(p);

	if (t)
		flow_clear_pinned(t);
}

#endif /* __FLOW_ENQUEUE_BPF_H */
