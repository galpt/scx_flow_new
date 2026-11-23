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
 * With --unslice, the central CPU of the domain of the task's CPU decides
 * where a queued task runs, so the enqueue only asks it for a pass. Tasks
 * that no worker may run wait in a DSQ of their own for the central cores.
 * A task that a central core preempted for a short task waits on its worker
 * for that task to finish. While the central CPU falls behind, an idle
 * worker is woken up or a victim asked to yield as above.
 *
 * When a realtime or deadline task takes a CPU, the tasks waiting in its
 * local DSQ are queued again from ops.cpu_release(), like any other task.
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
 * Count @t as waiting for @cpu. With --helicoprion, ops.quiescent() does
 * not clear the count of a pinned task whose CPU changes while it waits,
 * so the count moves with it here.
 */
static __always_inline void flow_mark_pinned(struct flow_task_ctx *t, s32 cpu)
{
	if (t->pinned_cpu == cpu)
		return;
	flow_clear_pinned(t);
	t->pinned_cpu = cpu;
	__sync_fetch_and_add(&flow_cpu_states[cpu].nr_pinned, 1);
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
 * the enqueued one and is expected to keep the CPU for longer than until
 * @est_stop. A CPU without a stop stamp is idle or was already claimed by
 * another enqueue. With --unslice, a central core is never a victim, and
 * a worker whose task is past its expected stop at @now is one, as nothing
 * but the preemption timer stops a task that has no slice.
 */
static bool flow_probe_victim(s32 cpu, u32 lat_cri, u64 est_stop, u64 now,
			      struct flow_victim *v)
{
	struct flow_cpu_state *cs;
	u64 stop;
	u32 victim_lat_cri;

	if (!flow_cpu_valid(cpu) || flow_on_central_core(cpu))
		return false;
	cs = &flow_cpu_states[cpu];
	stop = READ_ONCE(cs->est_stopping_clk);
	victim_lat_cri = READ_ONCE(cs->lat_cri);
	if (!stop || victim_lat_cri >= lat_cri ||
	    !(time_after(stop, est_stop) || (flow_unslice && time_before(stop, now))))
		return false;

	v->cpu = cpu;
	v->lat_cri = victim_lat_cri;
	v->est_stop = stop;
	return true;
}

/*
 * Claim the victim by clearing its stop stamp, so that concurrent
 * enqueues pick someone else.
 */
static __always_inline bool flow_claim_victim(const struct flow_victim *v)
{
	return flow_cpu_valid(v->cpu) &&
	       __sync_bool_compare_and_swap(&flow_cpu_states[v->cpu].est_stopping_clk,
					    v->est_stop, 0);
}

/*
 * Claim the victim, then shorten the slice of its task. A slice of one
 * nanosecond, rather than zero, keeps the kernel from refilling it with the
 * default slice.
 */
static bool flow_ask_yield(const struct flow_victim *v)
{
	struct task_struct *curr;
	bool asked = false;

	if (!flow_claim_victim(v))
		return false;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(v->cpu);
	if (curr && curr->pid)
		asked = scx_bpf_task_set_slice(curr, 1);
	bpf_rcu_read_unlock();
	return asked;
}

/* @t is latency critical enough to make another task give up its CPU. */
static __always_inline bool flow_is_urgent(const struct flow_task_ctx *t)
{
	u64 thr = READ_ONCE(flow_sys_stat.thr_lat_cri);

	return thr && t->lat_cri >= thr;
}

/*
 * Look for a victim for @p among the CPUs of the LLC that @p can use. @cpu
 * is checked first, then a few random CPUs, and the better of the first
 * two candidates goes to @v. Random probes keep enqueues on different CPUs
 * from all going after the same victim.
 */
static bool flow_pick_victim(struct task_struct *p, struct flow_task_ctx *t, s32 cpu, u32 llc,
			     struct flow_victim *v)
{
	struct flow_victim cand[2];
	struct bpf_cpumask *llc_mask;
	u64 now, est_stop;
	u32 nr = 0, i;

	now = flow_now();
	est_stop = flow_est_stop(t, t->acc_runtime_ns, READ_ONCE(flow_sys_stat.slice_ns), now);
	if (flow_probe_victim(cpu, t->lat_cri, est_stop, now, &cand[0]))
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
			if (flow_probe_victim(probe, t->lat_cri, est_stop, now,
					      nr ? &cand[1] : &cand[0]))
				nr++;
		}
	}

	if (!nr)
		return false;
	if (nr == 2 && (cand[1].lat_cri < cand[0].lat_cri ||
			(cand[1].lat_cri == cand[0].lat_cri &&
			 time_after(cand[1].est_stop, cand[0].est_stop))))
		cand[0] = cand[1];
	*v = cand[0];
	return true;
}

/* Ask the best victim for an urgent @p, if there is one, to give up its CPU. */
static void flow_try_preempt(struct task_struct *p, struct flow_task_ctx *t, s32 cpu, u32 llc)
{
	struct flow_victim v;

	if (flow_is_urgent(t) && flow_pick_victim(p, t, cpu, llc, &v) && flow_ask_yield(&v))
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

	now = flow_now();
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

/* True when at least one worker may run @p. Only meaningful with --unslice. */
static __always_inline bool flow_runs_on_workers(const struct task_struct *p)
{
	return p->nr_cpus_allowed >= flow_nr_cpus ||
	       bpf_cpumask_intersects(p->cpus_ptr, cast_mask(&flow_worker_cpumask));
}

/*
 * With --unslice, get @p, just queued in @dsq_id, running. @pinned tells
 * that @p can only run on @cpu. Everything waits for a pass of the central
 * CPU of the domain of @cpu, except for a task that may only run on other
 * CPUs of the central cores, which wakes up one of those. While the central
 * CPU falls behind, a worker that @p may use is woken up, or a victim found
 * as without --unslice, and the workers then schedule for themselves.
 */
static void flow_wake_central(struct task_struct *p, struct flow_task_ctx *t, s32 cpu,
			      bool pinned, u64 dsq_id, u32 llc)
{
	bool central = dsq_id == FLOW_CENTRAL_DSQ || (pinned && flow_cpu_central[cpu]);
	u32 dom = flow_domain_of(cpu);
	s32 idle;

	if (central && cpu != flow_central_cpu(dom) &&
	    (pinned || !bpf_cpumask_test_cpu(flow_central_cpu(dom), p->cpus_ptr))) {
		flow_kick_idle(p, t, cpu, pinned, 0);
		return;
	}
	if (central || !flow_central_relieved(dom)) {
		flow_kick_central(dom);
		return;
	}

	idle = scx_bpf_select_cpu_and(p, cpu, 0, cast_mask(&flow_worker_cpumask), 0);
	if (idle >= 0) {
		scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
		flow_stat_inc(FLOW_STAT_KICK_IDLE);
		return;
	}
	flow_try_preempt(p, t, cpu, llc);
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
		flow_note_wakeup(t, wt, flow_now());
}

/*
 * @p was preempted by the wakee it just handed its CPU to, see
 * flow_sync_handoff(). It waits for the reply of the wakee as if it slept,
 * so its burst ends here, and it resumes on the same CPU after the wakee.
 * Tasks waiting in the DSQ of the CPU get to run first if they are due
 * before it.
 */
static void flow_requeue_yielded(struct task_struct *p, struct flow_task_ctx *t, s32 cpu,
				 u64 enq_flags)
{
	u64 deadline;

	t->flags &= ~FLOW_FLAG_YIELDED;
	t->avg_runtime_ns = flow_calc_avg(t->avg_runtime_ns, t->acc_runtime_ns);
	deadline = flow_handoff_deadline(p, t, flow_now());
	if (READ_ONCE(flow_cpu_states[cpu].nr_pinned) ||
	    scx_bpf_dsq_nr_queued(FLOW_CPU_DSQ_BASE + cpu) > 0) {
		scx_bpf_dsq_insert_vtime(p, FLOW_CPU_DSQ_BASE + cpu, FLOW_SYNC_SLICE_NS, deadline,
					 enq_flags);
		return;
	}
	scx_bpf_task_set_dsq_vtime(p, deadline);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, FLOW_SYNC_SLICE_NS, enq_flags);
}

/*
 * With --unslice, @p was just preempted on worker @cpu for a short task,
 * see flow_note_resume(). It waits behind that task in the local DSQ of
 * @cpu and resumes there once the short task is done, which needs no
 * placement by the central CPU. Tasks queued again by the kernel, see
 * ops.cpu_release(), go back to the central core instead.
 */
static bool flow_resume_local(const struct task_struct *p, s32 cpu, u64 enq_flags)
{
	struct flow_cpu_state *cs = &flow_cpu_states[cpu];

	if ((enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_REENQ)) || flow_cpu_central[cpu] ||
	    READ_ONCE(cs->resume_pid) != p->pid)
		return false;
	WRITE_ONCE(cs->resume_pid, 0);
	return scx_bpf_task_cpu(p) == cpu;
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 deadline, slice, dsq_id;
	bool pinned, fresh;
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
		/*
		 * With --unslice, the workers only look at it when a central CPU
		 * asks, and the workers of every domain may take it.
		 */
		if (flow_unslice) {
			u32 dom;

			bpf_for(dom, 0, flow_nr_domains)
				flow_kick_central(dom);
		}
		return;
	}

	/*
	 * With --helicoprion, the work of ops.runnable() and ops.stopping() is
	 * done here for tasks that did not go through ops.select_cpu(), see
	 * flow_wake_task(). The first time a task is queued, or when the kernel
	 * queues it again from ops.cpu_release(), it was not preempted.
	 */
	fresh = t->flags & FLOW_FLAG_NEW;
	t->flags &= ~FLOW_FLAG_NEW;
	if (flow_helicoprion) {
		if (!(enq_flags & SCX_ENQ_WAKEUP)) {
			flow_charge_exec(p, t);
			if (!fresh && !(enq_flags & SCX_ENQ_REENQ))
				flow_stat_inc(FLOW_STAT_PREEMPTED);
			if ((t->flags & FLOW_FLAG_YIELDED) && !(enq_flags & SCX_ENQ_REENQ)) {
				flow_requeue_yielded(p, t, cpu, enq_flags);
				return;
			}
			t->flags &= ~FLOW_FLAG_YIELDED;
		} else if (!__COMPAT_is_enq_cpu_selected(enq_flags)) {
			struct task_struct *waker = bpf_get_current_task_btf();

			flow_wake_task(p, t, waker, flow_task_ctx(waker), flow_now());
		}
	}

	pinned = flow_is_pinned(p);
	llc = flow_llc_of(cpu);
	deadline = flow_score_task(p, t);
	slice = flow_calc_slice(t, cpu);
	if (flow_unslice && flow_resume_local(p, cpu, enq_flags)) {
		t->flags |= FLOW_FLAG_RESUMED;
		scx_bpf_task_set_dsq_vtime(p, deadline);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   flow_central_relieved(flow_domain_of(cpu)) ? slice : SCX_SLICE_INF,
				   enq_flags);
		return;
	}
	if (pinned) {
		flow_mark_pinned(t, cpu);
		dsq_id = FLOW_CPU_DSQ_BASE + cpu;
	} else if (flow_unslice && !flow_runs_on_workers(p)) {
		flow_clear_pinned(t);
		dsq_id = FLOW_CENTRAL_DSQ;
	} else {
		flow_clear_pinned(t);
		dsq_id = FLOW_LLC_DSQ_BASE + llc;
	}
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, deadline, enq_flags);

	/*
	 * With --unslice, the CPU of the last runnable task does not pick it
	 * up again by itself, so this case needs the central CPU as well.
	 */
	if (flow_unslice) {
		flow_wake_central(p, t, cpu, pinned, dsq_id, llc);
		return;
	}

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
		flow_end_burst(t, flow_now());
}

/*
 * A pinned task that moves to another scheduling class while it is queued
 * never runs here again, so it stops counting as waiting for its CPU.
 * ops.quiescent() already does this, but --helicoprion leaves it out. What
 * the task learned about its partner no longer holds once it runs in
 * another class either.
 */
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *t = flow_task_ctx(p);

	if (!t)
		return;
	flow_clear_pinned(t);
	t->sync_score = 0;
	t->last_waker = 0;
}

/*
 * A realtime or deadline task took @cpu. The tasks waiting in its local
 * DSQ would wait behind it, so they are queued again, and the CPU no
 * longer counts as running a task of the scheduler, so it is not picked as
 * a victim or a hog. With --unslice, the tasks of a worker go back to its
 * central core this way.
 */
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	if (flow_cpu_valid(cpu)) {
		struct flow_cpu_state *cs = &flow_cpu_states[cpu];

		WRITE_ONCE(cs->lat_cri, 0);
		WRITE_ONCE(cs->est_stopping_clk, 0);
		WRITE_ONCE(cs->burst_start_clk, flow_now());
		WRITE_ONCE(cs->resume_pid, 0);
		WRITE_ONCE(cs->want, 0);
	}
	scx_bpf_reenqueue_local();
}

#endif /* __FLOW_ENQUEUE_BPF_H */
