// SPDX-License-Identifier: GPL-2.0
/*
 * Scheduling from central cores, enabled by --unslice.
 *
 * The loader splits the CPUs into central domains of whole LLCs, or of
 * parts of a very large one, and gives each domain a central core. The
 * central CPU of a domain makes every scheduling decision for its workers,
 * the other CPUs of the domain. A worker that runs out of work runs a task
 * pinned to it if there is one, as such a task has nowhere else to go.
 * Otherwise it marks itself as waiting and kicks the central CPU of its
 * domain, which then gives each waiting or idle worker of the domain the
 * task that the worker would have picked for itself: a task pinned to it or
 * one of its LLC, whichever is due first, then a task of another LLC of the
 * domain, then one of another domain. The task goes straight to the local
 * DSQ of the worker with an infinite slice, so a busy worker can stop its
 * tick. When the most urgent task of an LLC finds no worker free, a victim
 * of the domain chosen as for an urgent enqueue gives up its CPU to it at
 * once. Tasks that a pass leaves over are offered to the domains with an
 * idle worker, see flow_share_leftovers().
 *
 * A timer on the other hardware thread of each central core, or on the
 * central CPU itself without SMT, replaces the slice. Once the task
 * running on a worker has run for a minimum slice, a waiting task preempts
 * it if the deadline of the waiting task is earlier than the one the
 * running task started with. Once the running task has run for the slice
 * it would get without --unslice, the deadline of the waiting task only
 * has to be earlier than the one the running task has reached by now. The
 * waiting task moves into the local DSQ of the worker and takes over the
 * CPU in one step. If the preempting task runs in short bursts, the task
 * it preempted waits on the worker and resumes there, so the central CPU
 * does not have to place it again. A worker without such a waiting task
 * is left alone. The timer also refreshes the performance target of busy
 * workers, which no longer do it from their own tick.
 *
 * A central CPU must not hold up its workers when it falls behind, see
 * flow_central_relieved(). The workers then dispatch for themselves, and
 * the timer wakes up the idle workers that wait for the central CPU.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_CENTRAL_BPF_H
#define __FLOW_CENTRAL_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "stats.bpf.h"
#include "enqueue.bpf.h"

/*
 * @p is about to preempt the task on worker @cpu. If @p runs in short
 * bursts, the preempted task waits for it on @cpu instead of going back to
 * the central core, see flow_resume_local(), so that one short wakeup
 * costs the central CPU one placement rather than two.
 */
static void flow_note_resume(struct task_struct *p, s32 cpu)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	struct task_struct *curr;
	s32 pid = 0;

	if (t && t->avg_runtime_ns < FLOW_SLICE_MIN_NS) {
		bpf_rcu_read_lock();
		curr = __COMPAT_scx_bpf_cpu_curr(cpu);
		if (curr)
			pid = curr->pid;
		bpf_rcu_read_unlock();
	}
	WRITE_ONCE(flow_cpu_states[cpu].resume_pid, pid);
}

/*
 * Move the task @p, found by iterating a DSQ with @it, to the local DSQ of
 * @cpu without a slice. With SCX_ENQ_PREEMPT in @enq_flags, it takes over
 * the CPU right away. Returns whether the task was moved.
 */
static __always_inline bool flow_move_to(struct bpf_iter_scx_dsq *it, struct task_struct *p,
					 s32 cpu, u64 enq_flags)
{
	bool preempt = enq_flags & SCX_ENQ_PREEMPT;

	if (preempt)
		flow_note_resume(p, cpu);
	scx_bpf_dsq_move_set_slice(it, SCX_SLICE_INF);
	if (scx_bpf_dsq_move(it, p, SCX_DSQ_LOCAL_ON | cpu, enq_flags))
		return true;
	if (preempt)
		WRITE_ONCE(flow_cpu_states[cpu].resume_pid, 0);
	return false;
}

/*
 * Move the first task of @dsq_id that may run on @cpu to the local DSQ of
 * @cpu without a slice, with @enq_flags. Unless @before is zero, the task
 * must be due before it. Only the first FLOW_SCAN_DEPTH tasks are looked
 * at, so a head of tasks that cannot run on @cpu does not make a pass
 * long. Those tasks leave once the CPUs they may use free up, and the
 * tasks behind them move up.
 */
static bool flow_move_first(u64 dsq_id, s32 cpu, u64 before, u64 enq_flags)
{
	struct task_struct *p;
	u32 seen = 0;

	if (scx_bpf_dsq_nr_queued(dsq_id) <= 0)
		return false;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if ((before && !time_before(p->scx.dsq_vtime, before)) ||
		    seen++ >= FLOW_SCAN_DEPTH)
			break;
		if (flow_task_fits(p, cpu) && flow_move_to(BPF_FOR_EACH_ITER, p, cpu, enq_flags))
			return true;
	}
	return false;
}

/*
 * Move a task pinned to @cpu or a task of @llc to the local DSQ of @cpu,
 * with the order of flow_consume_local() and with @enq_flags. Unless
 * @before is zero, the task must be due before it.
 */
static bool flow_feed_local(s32 cpu, u32 llc, u64 before, u64 enq_flags)
{
	u64 cpu_dsq = FLOW_CPU_DSQ_BASE + cpu, llc_dsq = FLOW_LLC_DSQ_BASE + llc;
	struct task_struct *pinned = __COMPAT_scx_bpf_dsq_peek(cpu_dsq);
	u64 limit = 0;

	if (pinned)
		limit = pinned->scx.dsq_vtime - FLOW_SLICE_MAX_NS;
	if (limit) {
		if (before && time_before(before, limit))
			limit = before;
		if (flow_move_first(llc_dsq, cpu, limit, enq_flags))
			return true;
	}
	return flow_move_first(cpu_dsq, cpu, before, enq_flags) ||
	       flow_move_first(llc_dsq, cpu, before, enq_flags);
}

/*
 * Move a task of another LLC to @cpu, a worker of @dom in @llc. The other
 * LLCs of @dom come first, then the LLCs of other domains, whose tasks
 * would otherwise wait while @cpu idles. Within both, the LLCs in the node
 * of @llc come before those outside of it. Bit 0 of the pass selects other
 * nodes and bit 1 other domains.
 */
static bool flow_feed_steal(s32 cpu, u32 llc, u32 dom)
{
	u32 node, pass, i;

	if (llc >= FLOW_MAX_LLCS)
		return false;
	node = flow_llc_node[llc];
	bpf_for(pass, 0, flow_nr_domains > 1 ? 4 : 2) {
		bool remote = pass & 1, foreign = pass & 2;

		bpf_for(i, 1, flow_nr_llcs) {
			u32 other = (llc + i) % flow_nr_llcs;

			if (other >= FLOW_MAX_LLCS || (flow_llc_node[other] != node) != remote ||
			    flow_llc_in_domain(other, dom) == foreign)
				continue;
			if (flow_move_first(FLOW_LLC_DSQ_BASE + other, cpu, 0, 0))
				return true;
		}
	}
	return false;
}

/*
 * Give worker @cpu the task it would take for itself without --unslice,
 * see flow_dispatch_cpu(). Unless @shared is set, only the tasks pinned to
 * @cpu wait. Returns whether a task was moved.
 */
__hidden int flow_feed_worker(u32 cpu, u32 shared)
{
	u32 llc;

	if (cpu >= FLOW_MAX_CPUS || cpu >= flow_nr_cpus)
		return 0;
	llc = flow_llc_of(cpu);

	if (!shared) {
		if (!flow_move_first(FLOW_CPU_DSQ_BASE + cpu, cpu, 0, 0))
			return 0;
		goto moved;
	}
	if (flow_move_first(FLOW_FALLBACK_DSQ, cpu, 0, 0) || flow_feed_local(cpu, llc, 0, 0))
		goto moved;
	if (!flow_feed_steal(cpu, llc, flow_domain_of(cpu)))
		return 0;
	flow_stat_inc(FLOW_STAT_STEAL);
moved:
	flow_stat_inc(FLOW_STAT_DISPATCHED);
	return 1;
}

/*
 * The head of the DSQ of @llc found no free worker in @dom. If it is urgent
 * enough, the best victim among the workers it may use gives up its CPU to
 * it right away. So does a task that runs in short bursts, as the task it
 * preempts resumes on its CPU right after it, see flow_note_resume(). The
 * victim must be a worker of @dom, which only matters when @llc is split
 * between domains.
 */
__hidden int flow_preempt_for_head(u32 llc, u32 dom)
{
	struct task_struct *p;
	u64 dsq_id;

	if (llc >= FLOW_MAX_LLCS || llc >= flow_nr_llcs)
		return 0;
	dsq_id = FLOW_LLC_DSQ_BASE + llc;
	if (scx_bpf_dsq_nr_queued(dsq_id) <= 0)
		return 0;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		struct flow_task_ctx *t = flow_task_ctx(p);
		s32 cpu = scx_bpf_task_cpu(p);
		struct flow_victim v;

		if (!flow_cpu_valid(cpu) || !flow_may_run_on(p, cpu))
			cpu = -1;
		if (t && (flow_is_urgent(t) || t->avg_runtime_ns < FLOW_SLICE_MIN_NS) &&
		    flow_pick_victim(p, t, cpu, llc, &v) && flow_cpu_valid(v.cpu) &&
		    flow_domain_of(v.cpu) == dom && flow_claim_victim(&v) &&
		    flow_move_to(BPF_FOR_EACH_ITER, p, v.cpu, SCX_ENQ_PREEMPT))
			flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
		break;
	}
	return 0;
}

/*
 * Start a timer of a central core on the calling CPU. A pinned timer keeps
 * firing on the CPU that started it, so each CPU of a central core starts
 * its own timer when it first dispatches.
 */
static void flow_arm_timer(struct flow_timer *ft, u32 *armed, u64 interval)
{
	s32 ret;

	if (!ft)
		return;
	WRITE_ONCE(*armed, 1);
	ret = bpf_timer_start(&ft->timer, interval, BPF_F_TIMER_CPU_PIN);
	if (ret)
		scx_bpf_error("failed to start a timer on the central core (%d)", ret);
}

/* Tasks wait in the DSQ of an LLC or in the fallback DSQ. */
static bool flow_shared_queued(void)
{
	u32 llc;

	if (scx_bpf_dsq_nr_queued(FLOW_FALLBACK_DSQ) > 0)
		return true;
	bpf_for(llc, 0, flow_nr_llcs) {
		if (scx_bpf_dsq_nr_queued(FLOW_LLC_DSQ_BASE + llc) > 0)
			return true;
	}
	return false;
}

/* Tasks wait in the DSQ of an LLC of @dom. */
static bool flow_domain_queued(u32 dom)
{
	u32 llc;

	bpf_for(llc, 0, flow_nr_llcs) {
		if (flow_llc_in_domain(llc, dom) &&
		    scx_bpf_dsq_nr_queued(FLOW_LLC_DSQ_BASE + llc) > 0)
			return true;
	}
	return false;
}

/*
 * With several domains, a worker of @dom ran out of work. The mark tells
 * the central CPUs of the other domains that @dom can take their leftovers,
 * see flow_share_leftovers(). It is set before the worker kicks its central
 * CPU, so a pass that clears it by mistake is followed by one that sets it
 * again.
 */
static __always_inline void flow_mark_idle_worker(u32 dom)
{
	struct flow_central *c = flow_central_of(dom);

	if (flow_nr_domains > 1 && !READ_ONCE(c->has_idle))
		WRITE_ONCE(c->has_idle, 1);
}

/*
 * End of a pass of the central CPU of @dom, which left a worker waiting if
 * @waiting is set. If tasks of the LLCs of @dom are still queued, the
 * central CPUs of the domains with a waiting worker get a pass, and their
 * workers take those tasks, see flow_feed_steal(). A task then does not
 * wait for a busy domain while a worker it may use idles in another one.
 */
static void flow_share_leftovers(u32 dom, bool waiting, bool shared)
{
	struct flow_central *c = flow_central_of(dom);
	u32 i;

	if (READ_ONCE(c->has_idle) != waiting)
		WRITE_ONCE(c->has_idle, waiting);
	if (!shared || !flow_domain_queued(dom))
		return;
	bpf_for(i, 1, flow_nr_domains) {
		u32 other = (dom + i) % flow_nr_domains;

		if (READ_ONCE(flow_central_of(other)->has_idle))
			flow_kick_central(other);
	}
}

/*
 * A pass of the central CPU over the workers of @dom. Clearing the pending
 * kick first lets a CPU that queues work during the pass kick it again.
 * While the shared DSQs are empty, which is most of the time on an idle
 * system, a worker only needs a look at its own DSQ.
 */
static void flow_schedule_workers(u32 dom)
{
	struct flow_central *c = flow_central_of(dom);
	const struct cpumask *idle;
	u32 cpu, llc, zero = 0;
	bool shared, waiting = false;

	flow_note_lag(c, __sync_lock_test_and_set(&c->kick_clk, 0), flow_now());
	if (!dom && !READ_ONCE(c->stat_armed))
		flow_arm_timer(bpf_map_lookup_elem(&stat_timer, &zero), &c->stat_armed,
			       FLOW_STAT_INTERVAL_NS);

	shared = flow_shared_queued();

	/*
	 * A worker that has been idle since the scheduler started never
	 * marked itself as waiting, so idle workers count as waiting too.
	 */
	idle = scx_bpf_get_idle_cpumask();
	bpf_for(cpu, 0, flow_nr_cpus) {
		struct flow_cpu_state *cs;

		if (cpu >= FLOW_MAX_CPUS)
			break;
		if (flow_cpu_central[cpu] || flow_domain_of(cpu) != dom)
			continue;
		cs = &flow_cpu_states[cpu];
		if ((!READ_ONCE(cs->want) && !bpf_cpumask_test_cpu(cpu, idle)) ||
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu))
			continue;
		if (flow_feed_worker(cpu, shared))
			WRITE_ONCE(cs->want, 0);
		else
			waiting = true;
	}
	scx_bpf_put_idle_cpumask(idle);

	if (shared) {
		bpf_for(llc, 0, flow_nr_llcs) {
			if (flow_llc_in_domain(llc, dom))
				flow_preempt_for_head(llc, dom);
		}
	}
	if (flow_nr_domains > 1)
		flow_share_leftovers(dom, waiting, shared);
}

/*
 * Deadline that a waiting task must beat to preempt the task on @cpu at
 * @now: the deadline the task started with, or once its slice is @expired,
 * the deadline it would get if it stopped now. Returns false when @cpu
 * runs no task of the scheduler, or a realtime task that ops.cpu_release()
 * is about to make room for.
 */
static bool flow_curr_deadline(s32 cpu, u64 now, bool expired, u64 *deadline)
{
	struct task_struct *curr;
	struct flow_task_ctx *t;
	bool busy = false;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (curr && curr->pid && curr->prio >= FLOW_MAX_RT_PRIO) {
		t = flow_task_ctx(curr);
		if (t) {
			u64 ran = flow_ran(t, now), acc = t->acc_runtime_ns + ran;

			*deadline = expired ?
				flow_deadline(t, t->vtime + flow_charge(curr, ran, acc), acc) :
				curr->scx.dsq_vtime;
			busy = true;
		}
	}
	bpf_rcu_read_unlock();
	return busy;
}

/*
 * Look at worker @cpu from the preemption timer of @dom at @now. While the
 * workers of @dom are @relieved of the central CPU, an idle worker that
 * waits for it is woken up if there is work for it, @shared work or a task
 * pinned to it, so that it schedules for itself.
 */
__hidden int flow_check_worker(u32 cpu, u32 dom, u64 now, u32 relieved, u32 shared)
{
	struct flow_cpu_state *cs;
	u64 ran, deadline;
	bool expired;

	if (cpu >= FLOW_MAX_CPUS || cpu >= flow_nr_cpus || flow_cpu_central[cpu] ||
	    flow_domain_of(cpu) != dom)
		return 0;
	cs = &flow_cpu_states[cpu];
	if (READ_ONCE(cs->idle_start_clk)) {
		if (relieved && READ_ONCE(cs->want) &&
		    (shared || scx_bpf_dsq_nr_queued(FLOW_CPU_DSQ_BASE + cpu) > 0))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return 0;
	}

	ran = now - READ_ONCE(cs->slice_clk);
	expired = (s64)ran >= (s64)READ_ONCE(cs->slice_ns);
	if (!flow_curr_deadline(cpu, now, expired, &deadline))
		return 0;

	if (now - READ_ONCE(cs->cpuperf_commit_clk) >= FLOW_CPUPERF_REFRESH_NS)
		flow_cpuperf_commit(cpu, cs, SCX_CPUPERF_ONE, now);

	if ((s64)ran < FLOW_SLICE_MIN_NS)
		return 0;

	/* Tasks put in the local DSQ behind curr only run once it stops. */
	if (expired && scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) > 0) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
		return 0;
	}
	if (flow_feed_local(cpu, flow_llc_of(cpu), deadline, SCX_ENQ_PREEMPT))
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
	return 0;
}

/*
 * The preemption timer of the domain @key looks at its workers. It also
 * kicks the central CPU again when a kick has waited for a whole period,
 * in case it was lost, see flow_dispatch().
 */
static int flow_preempt_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	u32 dom = *key;
	u64 now = flow_now(), kick = READ_ONCE(flow_central_of(dom)->kick_clk);
	u32 relieved = flow_central_relieved(dom);
	u32 shared = relieved && flow_shared_queued();
	u32 cpu;
	s32 ret;

	if (kick && (s64)(now - kick) >= FLOW_PREEMPT_CHECK_NS)
		scx_bpf_kick_cpu(flow_central_cpu(dom), SCX_KICK_PREEMPT);
	bpf_for(cpu, 0, flow_nr_cpus)
		flow_check_worker(cpu, dom, now, relieved, shared);

	ret = bpf_timer_start(timer, FLOW_PREEMPT_CHECK_NS, BPF_F_TIMER_CPU_PIN);
	if (ret)
		scx_bpf_error("failed to restart the preemption timer (%d)", ret);
	return 0;
}

#endif /* __FLOW_CENTRAL_BPF_H */
