// SPDX-License-Identifier: GPL-2.0
/*
 * Double helix queues for the flow scheduler, used by --performance and
 * --lowlatency.
 *
 * The LLCs of each NUMA node are paired up in the order of their ids, and
 * the two LLCs of a pair share one double helix queue from the arena
 * library of scx. Each LLC owns one strand of it. A task that is not
 * pinned and may run in both LLCs of its pair waits in the strand of the
 * LLC of its CPU, ordered by virtual deadline as in a DSQ. The CPUs of an
 * LLC weigh the head of their own strand against the heads of their DSQs.
 * Only once they have nothing of their own left do they take from the
 * strand and the DSQ of another LLC, first in their node and then in the
 * other nodes, so that tasks keep running next to their cache while work
 * queued in any pair still reaches every CPU that may run it.
 *
 * An LLC without a partner in its node, such as the only LLC of a machine
 * or the last one of an odd count, gets a queue of its own and is split
 * into two halves, each of which owns one strand. The halves are the two
 * core groups of the LLC if it has exactly two, and otherwise two runs of
 * its cores in id order with about as many CPUs each, so the hardware
 * threads of a core always land in the same half. A task that may run in
 * both halves waits in the strand of the half of its CPU, which is the
 * CPU it last ran on or the one it was woken up on. Both halves share the
 * cache of the LLC, so its CPUs do not favor their own strand: they take
 * whichever head of the two strands is due first, through the priority
 * order of the queue, and weigh it against the heads of their DSQs as if
 * the two strands were one. An LLC with a single core or fewer than three
 * CPUs is not split and only uses its DSQ.
 *
 * A strand takes no more tasks once it holds FLOW_HELIX_IMBALANCE more
 * than the other strand of its queue. That bound is loose on purpose: an
 * LLC or a half busy with a game can queue ten more of its threads than
 * its partner before any of them go to the DSQ of the LLC, so most of its
 * waiting threads share one deadline order, and the partner of an LLC
 * still only steals from it once it runs dry. A task that a strand does
 * not take, because the strand is that far ahead or the queue is full,
 * waits in the DSQ of its LLC as it does in the other modes. If the arena
 * cannot hold every queue when the scheduler loads, all LLCs use their
 * DSQs.
 *
 * The kernel does not see the tasks in a strand, so flow makes sure that
 * each of them reaches a CPU:
 *
 * - A strand holds pids. A waiting task that the kernel dequeues, as on
 *   an affinity or scheduling class change, leaves a stale entry behind,
 *   and is queued again if it remains with flow. Dispatching a stale entry
 *   does no harm: the kernel drops the insert unless the task waits for
 *   flow right then, in which case it runs early and its newer entry goes
 *   stale instead.
 * - A task taken off a strand is inserted into a DSQ and moved from there
 *   to the local DSQ, so that the kernel checks its affinity as it moves
 *   it. A task that may not run on the CPU that took it goes to the DSQ of
 *   an LLC in its mask instead, and a CPU of its mask there is kicked.
 * - An exiting task can lose its pid before it runs for the last time, so
 *   it never waits in a strand.
 * - A CPU does not go idle while the strand of its LLC holds entries, or
 *   either strand if its LLC is split. It takes up to FLOW_HELIX_POPS of
 *   them per dispatch and kicks itself for the rest.
 * - The tick and the choice to keep the previous task running look at the
 *   first entry of the queue of the LLC, see flow_helix_peek(), as they do
 *   at the heads of its DSQs.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_HELIX_BPF_H
#define __FLOW_HELIX_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

/*
 * Between two moves to a local DSQ, which flush the inserts of
 * ops.dispatch(), at most two takes of FLOW_HELIX_POPS entries add to
 * them, see flow_take_llc(). They have to fit in the dispatch buffer.
 */
_Static_assert(2 * FLOW_HELIX_POPS < SCX_DSP_DFL_MAX_BATCH,
	       "strand takes overflow the dispatch buffer");

/* The largest strand has to fit in one block of the static allocator. */
_Static_assert(FLOW_HELIX_SLOTS * FLOW_MAX_CPUS / 2 * sizeof(struct scx_minheap_elem) +
	       sizeof(scx_minheap_t) <= FLOW_HELIX_PAGES * 4096,
	       "a strand does not fit in the arena block");

/*
 * The queue that each LLC shares with its partner, or has to itself when
 * it is split, NULL if it has none. The table lives in the arena, so that
 * every program that reads it is tied to the arena, as the verifier
 * requires of programs that follow arena pointers.
 */
scx_dhq_t *__arena_global flow_helix[FLOW_MAX_LLCS];

static __always_inline scx_dhq_t *flow_helix_of(u32 llc)
{
	if (!flow_in_performance() || llc >= FLOW_MAX_LLCS)
		return NULL;
	return flow_helix[llc];
}

/* @llc owns both strands of its queue, see the top of this file. */
static __always_inline bool flow_helix_split(u32 llc)
{
	return llc < FLOW_MAX_LLCS && flow_llc_split[llc];
}

/* The half of a split LLC that @cpu is in. */
static __always_inline u32 flow_half_of(s32 cpu)
{
	return flow_cpu_valid(cpu) && flow_cpu_half[cpu] ? 1 : 0;
}

/* The strand of its queue that a task on @cpu of @llc waits in. */
static __always_inline u64 flow_strand_of(u32 llc, s32 cpu)
{
	if (flow_helix_split(llc))
		return flow_half_of(cpu) ? SCX_DHQ_STRAND_B : SCX_DHQ_STRAND_A;
	return llc < FLOW_MAX_LLCS && flow_llc_mate[llc] > llc ? SCX_DHQ_STRAND_A :
								SCX_DHQ_STRAND_B;
}

/*
 * Entries that the CPUs of @llc take first, stale ones too: those of the
 * strand of @llc, or of the whole queue if @llc is split. Zero without a
 * queue.
 */
static __always_inline u64 flow_helix_queued(u32 llc)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	s32 nr;

	if (!dhq)
		return 0;
	if (flow_helix_split(llc))
		nr = scx_dhq_nr_queued(dhq);
	else
		nr = scx_dhq_nr_queued_strand(dhq, flow_strand_of(llc, -1));
	return nr > 0 ? nr : 0;
}

/* The CPUs that share the queue of @llc with @cpu, from the other strand. */
static __always_inline struct bpf_cpumask *flow_helix_partner(u32 llc, s32 cpu)
{
	if (llc >= FLOW_MAX_LLCS)
		return NULL;
	if (flow_helix_split(llc))
		return MEMBER_VPTR(flow_half_cpumask, [2 * llc + !flow_half_of(cpu)]);
	return MEMBER_VPTR(flow_llc_cpumask, [flow_llc_mate[llc]]);
}

/*
 * Queue @p, due at @deadline with @slice, in the strand of @cpu of @llc.
 * The deadline and the slice are also set on @p, where they are read back
 * when a CPU takes it off the strand. Returns false if @p has to wait in
 * the DSQ of @llc instead.
 */
static bool flow_helix_queue(struct task_struct *p, u32 llc, s32 cpu, u64 deadline, u64 slice)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	struct bpf_cpumask *partner;

	if (!dhq || (p->flags & PF_EXITING))
		return false;
	if (p->nr_cpus_allowed < flow_nr_cpus) {
		partner = flow_helix_partner(llc, cpu);
		if (!partner || !bpf_cpumask_intersects(cast_mask(partner), p->cpus_ptr))
			return false;
	}
	scx_bpf_task_set_slice(p, slice);
	scx_bpf_task_set_dsq_vtime(p, deadline);
	if (scx_dhq_insert_vtime(dhq, (u64)p->pid, deadline, flow_strand_of(llc, cpu)))
		return false;
	flow_stat_inc(FLOW_STAT_HELIX);
	return true;
}

/*
 * The first entry that the CPUs of @llc would take off its queue: the head
 * of its strand, or the earlier of the two heads if @llc is split. The
 * entries are not checked against each other without a lock, so the
 * counts read first only spare the lock when nothing is there.
 */
static __always_inline u64 flow_helix_peek(scx_dhq_t *dhq, u32 llc)
{
	u64 strand;

	if (flow_helix_split(llc))
		return scx_dhq_nr_queued(dhq) > 0 ? scx_dhq_peek(dhq) : 0;
	strand = flow_strand_of(llc, -1);
	return scx_dhq_nr_queued_strand(dhq, strand) > 0 ? scx_dhq_peek_strand(dhq, strand) : 0;
}

/* Take the entry that flow_helix_peek() returns, or a later one. */
static __always_inline u64 flow_helix_pop(scx_dhq_t *dhq, u32 llc)
{
	u64 strand;

	if (flow_helix_split(llc))
		return scx_dhq_nr_queued(dhq) > 0 ? scx_dhq_pop(dhq) : 0;
	strand = flow_strand_of(llc, -1);
	return scx_dhq_nr_queued_strand(dhq, strand) > 0 ? scx_dhq_pop_strand(dhq, strand) : 0;
}

/*
 * If the entry that the CPUs of @llc take first may run on @cpu, return
 * true and its deadline in @vtime. A stale entry is judged by what its
 * task waits for now.
 */
static bool flow_helix_head(u32 llc, s32 cpu, u64 *vtime)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	struct task_struct *p;
	u64 pid;
	bool fits;

	if (!dhq)
		return false;
	pid = flow_helix_peek(dhq, llc);
	if (!pid)
		return false;
	p = bpf_task_from_pid((s32)pid);
	if (!p)
		return false;
	fits = flow_task_fits(p, cpu);
	*vtime = p->scx.dsq_vtime;
	bpf_task_release(p);
	return fits;
}

/* The first entry of @llc may run on @cpu and is due before @deadline. */
static __always_inline bool flow_helix_ahead(u32 llc, u64 deadline, s32 cpu)
{
	u64 vtime;

	return flow_helix_head(llc, cpu, &vtime) && time_before(vtime, deadline);
}

/*
 * True when a task of @dsq_id that can run on @cpu is due before @deadline.
 * The first FLOW_AHEAD_DEPTH tasks are looked at, so that a head that may
 * only run on other CPUs does not hide the tasks behind it. The walk takes
 * the lock of the DSQ at every step, while the head can be read without
 * it, so the walk only starts when the head is due first but cannot run on
 * @cpu.
 */
static bool flow_queued_ahead(u64 dsq_id, u64 deadline, s32 cpu)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	u32 seen = 0;

	if (!p || !time_before(p->scx.dsq_vtime, deadline))
		return false;
	if (flow_task_fits(p, cpu))
		return true;
	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if (!time_before(p->scx.dsq_vtime, deadline) || seen++ >= FLOW_AHEAD_DEPTH)
			return false;
		if (flow_task_fits(p, cpu))
			return true;
	}
	return false;
}

/*
 * A task of @llc, in its DSQ or its double helix queue, may run on @cpu
 * and is due before @deadline.
 */
static __always_inline bool flow_llc_ahead(u32 llc, u64 deadline, s32 cpu)
{
	return flow_queued_ahead(FLOW_LLC_DSQ_BASE + llc, deadline, cpu) ||
	       flow_helix_ahead(llc, deadline, cpu);
}

/*
 * Insert @p, just taken off a strand by @cpu of @llc, into a DSQ that it
 * can be run from. Returns true if that is the DSQ of @llc. Otherwise @p
 * goes to the DSQ of the LLC of a CPU in its mask, which is kicked in case
 * it is idle.
 */
static bool flow_helix_place(struct task_struct *p, s32 cpu, u32 llc)
{
	u64 slice = p->scx.slice ?: FLOW_SLICE_MIN_NS;
	s32 home;

	if (flow_may_run_on(p, cpu)) {
		scx_bpf_dsq_insert_vtime(p, FLOW_LLC_DSQ_BASE + llc, slice, p->scx.dsq_vtime, 0);
		return true;
	}
	home = scx_bpf_task_cpu(p);
	if (!bpf_cpumask_test_cpu(home, p->cpus_ptr))
		home = bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_valid(home)) {
		WRITE_ONCE(flow_fallback_used, true);
		scx_bpf_dsq_insert(p, FLOW_FALLBACK_DSQ, FLOW_SLICE_MIN_NS, 0);
		flow_stat_inc(FLOW_STAT_FALLBACK);
		return false;
	}
	scx_bpf_dsq_insert_vtime(p, FLOW_LLC_DSQ_BASE + flow_llc_of(home), slice,
				 p->scx.dsq_vtime, 0);
	scx_bpf_kick_cpu(home, SCX_KICK_IDLE);
	return false;
}

/*
 * Take up to FLOW_HELIX_POPS entries of @src, in the order of
 * flow_helix_pop(), for @cpu of @llc, until a task is moved to the local
 * DSQ of @cpu. Entries whose task is gone are dropped.
 */
static bool flow_helix_take(s32 cpu, u32 llc, u32 src)
{
	scx_dhq_t *dhq = flow_helix_of(src);
	struct task_struct *p;
	bool here;
	u64 pid;
	u32 i;

	if (!dhq)
		return false;
	bpf_for(i, 0, FLOW_HELIX_POPS) {
		pid = flow_helix_pop(dhq, src);
		if (!pid)
			return false;
		p = bpf_task_from_pid((s32)pid);
		if (!p)
			continue;
		here = flow_helix_place(p, cpu, llc);
		bpf_task_release(p);
		if (here && scx_bpf_dsq_move_to_local(FLOW_LLC_DSQ_BASE + llc, 0))
			return true;
	}
	return false;
}

/*
 * Move the most urgent task of @src that may run on @cpu of @llc to the
 * local DSQ of @cpu: the first entry of the queue of @src, see
 * flow_helix_peek(), if it is due before the head of the DSQ of @src,
 * which goes first otherwise. Most tasks wait in the queue, so the DSQ is
 * usually empty, and then there is nothing to weigh the entry against and
 * no reason to take the lock of the queue an extra time to peek at it.
 */
static bool flow_take_llc(s32 cpu, u32 llc, u32 src)
{
	u64 dsq_id = FLOW_LLC_DSQ_BASE + src, vtime;
	struct task_struct *head;

	if (!flow_helix_of(src))
		return scx_bpf_dsq_move_to_local(dsq_id, 0);
	head = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	if (!head)
		return flow_helix_take(cpu, llc, src) || scx_bpf_dsq_move_to_local(dsq_id, 0);
	if (flow_helix_head(src, cpu, &vtime) &&
	    time_before(vtime, head->scx.dsq_vtime) && flow_helix_take(cpu, llc, src))
		return true;
	return scx_bpf_dsq_move_to_local(dsq_id, 0) || flow_helix_take(cpu, llc, src);
}

/*
 * Create the queues before the scheduler is attached. Each queue gets
 * FLOW_HELIX_SLOTS entries for every online CPU of its two LLCs, or of its
 * LLC if that is split. If the arena cannot hold all of them, no LLC uses
 * one.
 */
SEC("syscall")
int flow_helix_init(void *ctx)
{
	u32 nr[FLOW_MAX_LLCS] = {};
	u32 i, llc, mate, slots;
	scx_dhq_t *dhq;
	s32 ret;

	bpf_for(i, 0, flow_nr_usable) {
		u32 cpu;

		if (i >= FLOW_MAX_CPUS)
			break;
		cpu = flow_cpu_ids[i];
		if (flow_cpu_valid(cpu))
			nr[flow_llc_of(cpu)]++;
	}

	ret = scx_static_init(FLOW_HELIX_PAGES);
	if (ret)
		return ret;

	bpf_for(llc, 0, flow_nr_llcs) {
		if (llc >= FLOW_MAX_LLCS)
			break;
		mate = flow_llc_mate[llc];
		if (flow_helix_split(llc) && mate == llc && flow_llc_nr_cpus[llc] > 2)
			slots = FLOW_HELIX_SLOTS * nr[llc];
		else if (!flow_helix_split(llc) && mate > llc && mate < flow_nr_llcs &&
			 mate < FLOW_MAX_LLCS && flow_llc_mate[mate] == llc &&
			 !flow_helix_split(mate))
			slots = FLOW_HELIX_SLOTS * (nr[llc] + nr[mate]);
		else
			continue;
		dhq = (scx_dhq_t *)scx_dhq_create_balanced(false, slots, SCX_DHQ_MODE_PRIORITY,
							   FLOW_HELIX_IMBALANCE);
		if (!dhq) {
			bpf_for(i, 0, FLOW_MAX_LLCS)
				flow_helix[i] = NULL;
			return -ENOMEM;
		}
		flow_helix[llc] = dhq;
		flow_helix[mate] = dhq;
	}
	return 0;
}

#endif /* __FLOW_HELIX_BPF_H */
