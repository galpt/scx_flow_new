// SPDX-License-Identifier: GPL-2.0
/*
 * Taking over busy CPUs for the flow scheduler.
 *
 * A task that wants a busy CPU first claims it as its victim: it clears
 * the stop stamp that the CPU published, so that concurrent enqueues pick
 * another one, see flow_claim_victim(). Without --lowlatency, the task of
 * the victim is then asked to give up its CPU, and the task that asked
 * waits in the queues for whichever CPU gets to it first, see
 * enqueue.bpf.h.
 *
 * With --lowlatency, a latency critical task does not wait in a queue
 * when it wakes up. A task is latency critical while its bursts average
 * under FLOW_LOWLAT_BURST_NS and it goes to sleep at least
 * FLOW_LOWLAT_WAIT_HZ times a second. The test does not depend on what
 * else runs, so a task that only sleeps and wakes up again, as a timer or
 * an audio thread does, counts as soon as its history shows it. Such a
 * task goes to an idle CPU if it has one. If not, it goes straight to the
 * local DSQ of a CPU in its LLC whose task is less latency critical, and
 * preempts that task on the spot, see flow_lowlat_takeover() for which CPU
 * it takes. Only a task that is not latency critical itself, or that has
 * been computing for longer than a latency critical task runs, is
 * preempted that way, so two latency critical tasks never push each other
 * off their CPUs. The task that runs the wakeup is not preempted either.
 *
 * The wait of the task is then at most the IPI to that CPU, the end of
 * whatever the kernel runs there with preemption disabled, and the switch
 * itself, however many tasks compute next to it. That holds while the
 * latency critical tasks that are awake in an LLC number fewer than its
 * CPUs less one, as the CPU of the waker does not count, and for a pinned
 * task while its CPU runs a task that is neither latency critical nor its
 * waker. Beyond that, or while realtime and deadline tasks hold the CPUs,
 * a latency critical task waits in the queues like any other task, ahead
 * of the tasks that compute, since its deadline is earlier.
 *
 * A task only takes over a CPU when nothing queued for that CPU or for its
 * LLC is due before it. A few latency critical tasks that keep waking up
 * could otherwise keep the tasks that compute away from the CPUs for
 * good, which the deadline order prevents.
 *
 * A SCHED_NORMAL task that becomes latency critical also gets the smallest
 * timer slack from userspace, see flow_lowlat_report(). The kernel then
 * fires the timers it sleeps on when they are due, rather than up to the
 * default 50 us later to serve them together with other timers, which no
 * placement on a CPU could make up for. Kernel threads are left out. The
 * threads and processes that such a task creates inherit its slack, so
 * userspace also resets those when the scheduler stops, to the slack of
 * the task they came from or else the default. A thread that later resets
 * its slack with prctl() can get the lowered one back, as the kernel
 * copied that as its default too. Userspace writes the old slack back when
 * the scheduler stops.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_LOWLAT_BPF_H
#define __FLOW_LOWLAT_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "helix.bpf.h"

/* The wakeup runs in an interrupt, not in a task that asked for it. */
static __always_inline bool flow_in_interrupt(void)
{
	return flow_in_hardirq() || bpf_in_serving_softirq();
}

struct flow_victim {
	s32	cpu;
	u32	lat_cri;
	u64	est_stop;
};

/* @t is latency critical enough to make another task give up its CPU. */
static __always_inline bool flow_is_urgent(const struct flow_task_ctx *t)
{
	u64 thr = READ_ONCE(flow_sys_stat.thr_lat_cri);

	return thr && t->lat_cri >= thr;
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

/* --lowlatency: @t is latency critical, see the top of this file. */
static __always_inline bool flow_lowlat_critical(const struct flow_task_ctx *t)
{
	return flow_in_lowlatency() && t->avg_runtime_ns < FLOW_LOWLAT_BURST_NS &&
	       t->wait_freq >= FLOW_LOWLAT_WAIT_HZ;
}

/*
 * --lowlatency: @p just became latency critical. If it is a user task
 * under SCHED_NORMAL, its thread id goes to userspace, which lowers the
 * slack so that the timers it sleeps on are not deferred, see slack.rs.
 * Kernel threads are never reported. A task is only looked at once, unless
 * the ring buffer was full. Userspace drains it on its own schedule, so
 * nothing wakes it up here.
 */
static void flow_lowlat_report(const struct task_struct *p, struct flow_task_ctx *t)
{
	u32 tid = p->pid;

	if (p->policy != FLOW_SCHED_NORMAL || (p->flags & PF_KTHREAD) ||
	    !bpf_ringbuf_output(&flow_slack_events, &tid, sizeof(tid), BPF_RB_NO_WAKEUP))
		t->flags |= FLOW_FLAG_SLACK;
}

/*
 * A latency critical task of @lat_cri, due at @deadline, may take over
 * @cpu at @now. The task of @cpu has to be less latency critical, and
 * either not latency critical at all or computing for longer than a
 * latency critical task runs. No task pinned to @cpu may be due first. A
 * CPU without a stop stamp is idle, runs a task of a higher class or was
 * claimed by another enqueue.
 */
static bool flow_lowlat_probe(s32 cpu, u32 lat_cri, u64 deadline, u64 now,
			      struct flow_victim *v)
{
	struct flow_cpu_state *cs;
	u32 victim_lat_cri;
	u64 stop, start;

	if (!flow_cpu_valid(cpu))
		return false;
	cs = &flow_cpu_states[cpu];
	stop = READ_ONCE(cs->est_stopping_clk);
	victim_lat_cri = READ_ONCE(cs->lat_cri);
	if (!stop || victim_lat_cri >= lat_cri)
		return false;
	if (READ_ONCE(cs->critical)) {
		start = READ_ONCE(cs->burst_start_clk);
		if (!time_after(now, start) || now - start < FLOW_LOWLAT_BURST_NS)
			return false;
	}
	if (READ_ONCE(cs->nr_pinned) &&
	    flow_queued_ahead(FLOW_CPU_DSQ_BASE + cpu, deadline, cpu))
		return false;

	v->cpu = cpu;
	v->lat_cri = victim_lat_cri;
	v->est_stop = stop;
	return true;
}

/* @a is the better victim: its task is less latency critical or stops later. */
static __always_inline bool flow_victim_better(const struct flow_victim *a,
					       const struct flow_victim *b)
{
	return a->lat_cri < b->lat_cri ||
	       (a->lat_cri == b->lat_cri && time_after(a->est_stop, b->est_stop));
}

/*
 * Look for the CPUs that @p, latency critical and due at @deadline, may
 * take over at @now in @llc: every CPU of @llc that @p may run on but
 * @skip, up to FLOW_LOWLAT_SCAN of them, from a random one on so that
 * wakeups at the same time spread out.
 * The best two go to @v, the best one first. Returns how many were found.
 */
static u32 flow_lowlat_scan(struct task_struct *p, const struct flow_task_ctx *t, u32 llc,
			    s32 skip, u64 deadline, u64 now, struct flow_victim *v)
{
	u32 first, nr, start, i, found = 0;
	struct flow_victim cand = {};

	if (llc >= FLOW_MAX_LLCS)
		return 0;
	first = flow_llc_first[llc];
	nr = flow_llc_nr_cpus[llc];
	if (!nr)
		return 0;
	start = bpf_get_prandom_u32() % nr;
	bpf_for(i, 0, flow_min(nr, FLOW_LOWLAT_SCAN)) {
		u32 idx = first + (start + i) % nr;
		s32 probe;

		if (idx >= FLOW_MAX_CPUS)
			break;
		probe = flow_llc_cpus[idx];
		if (probe == skip || !flow_task_fits(p, probe) ||
		    !flow_lowlat_probe(probe, t->lat_cri, deadline, now, &cand))
			continue;
		if (!found || flow_victim_better(&cand, &v[0])) {
			v[1] = v[0];
			v[0] = cand;
		} else if (found == 1 || flow_victim_better(&cand, &v[1])) {
			v[1] = cand;
		}
		/* Kept at two, so that the loop converges for the verifier. */
		found = flow_min(found + 1, 2);
	}
	return found;
}

/*
 * Claim a CPU that @p, latency critical and due at @deadline, takes over
 * as it wakes up on @cpu, see the top of this file.
 *
 * A task that wakes up another one runs the wakeup on its own CPU, and it
 * often goes to sleep right after, as the two sides of a request and its
 * reply do. Taking its CPU would preempt it just before that sleep, and it
 * would then wait in the queues while it still counts as runnable, so its
 * next wakeup would find it waiting there. Its CPU is never taken over.
 * An interrupt, on the other hand, wakes a task up on top of an unrelated
 * one, as a timer does on the CPU the task slept on. That CPU comes first
 * then, as it switches to @p as soon as it leaves the interrupt, without
 * waiting for an IPI. It has to be in the LLC of @cpu, whose queues are
 * weighed.
 *
 * Then comes @cpu, where @p still finds its cache, and then the rest of
 * the LLC. The queues are only weighed once there is a CPU to take over,
 * since that takes the lock of the double helix queue. Returns the CPU, or
 * a negative value if @p has to wait in the queues.
 */
static s32 flow_lowlat_takeover(struct task_struct *p, const struct flow_task_ctx *t, s32 cpu,
				bool pinned, u64 deadline)
{
	u64 now = flow_now();
	bool in_irq = flow_in_interrupt();
	s32 here = bpf_get_smp_processor_id();
	s32 waker = in_irq ? -1 : here;
	struct flow_victim v[2] = {};
	u32 llc, nr = 0, i;

	if (!flow_cpu_valid(cpu))
		return -EBUSY;
	llc = flow_llc_of(cpu);
	if (in_irq && !pinned && here != cpu && flow_cpu_valid(here) &&
	    flow_llc_of(here) == llc && flow_task_fits(p, here) &&
	    flow_lowlat_probe(here, t->lat_cri, deadline, now, &v[0]))
		nr = 1;
	if (cpu != waker && flow_task_fits(p, cpu) &&
	    flow_lowlat_probe(cpu, t->lat_cri, deadline, now, nr ? &v[1] : &v[0]))
		nr++;
	if (!nr && !pinned)
		nr = flow_lowlat_scan(p, t, llc, waker, deadline, now, v);
	if (!nr || flow_llc_ahead(llc, deadline, cpu))
		return -EBUSY;

	bpf_for(i, 0, nr) {
		if (i >= 2)
			break;
		if (flow_claim_victim(&v[i]))
			return v[i].cpu;
	}
	return -EBUSY;
}

#endif /* __FLOW_LOWLAT_BPF_H */
