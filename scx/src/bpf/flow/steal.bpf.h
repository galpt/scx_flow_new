// SPDX-License-Identifier: GPL-2.0
/*
 * Flow pair steal helper with outcome split.
 *
 * Moved from main with 9 counted on the thief for pair steals. Queued
 * is charged to the enqueue LLC and dispatched stays on the dispatch
 * LLC. Victim queued_dec keeps the total correct with saturation at
 * zero. Steal aggregate 3 moves with 9 so steal equals 9 plus 10.
 * Predicates plus order plus bounded retry are unchanged. Single
 * ownership through the queued flag is unchanged with no loss.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STEAL_BPF_H
#define __FLOW_STEAL_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "vtime.bpf.h"
#include "preempt.bpf.h"

/*
 * Pop one entry from a pair queue into the local LLC queue.
 * Empty peek stays silent with no counter move. Peek is hint only,
 * pop is truth. A pop with no task is stale and counts through the
 * stale helper. Queued is charged to the enqueue LLC and dispatched
 * stays on the dispatch LLC. Thief counts steal plus fallback, victim
 * keeps the queued dec with saturation at zero. Returns 1 when a task
 * reached the local queue.
 * A task that cannot run on the thief goes back to the victim
 * queue with no counter move and no loss. Stale entries retry
 * bounded so one bad entry never stalls dispatch. Four attempts
 * cover a burst of stale entries. Each attempt is one pop plus
 * one lookup, so worst cost stays negligible. Exiting tasks use
 * the same victim path with a minimal slice and never use a full
 * slice on shared queues. Cpu bound checks are best effort.
 * Hotplug needs restart, same risk as the pinned path.
 */
static __always_inline int flow_pop_to_local(scx_dhq_t *dhq, u32 llc, u32 strand,
					     int always_steal, u32 cpu, u64 cap)
{
	u32 attempt;
	if (!dhq)
		return 0;
	if (!flow_llc_ok(llc))
		return 0;
	if (!flow_cpu_ok(cpu))
		return 0;
	bpf_for(attempt, 0, FLOW_POP_RETRY_MAX) {
		u64 pid;
		struct task_struct *p;
		struct flow_task_ctx *t;
		u32 tst;
		u32 victim;
		u64 ins_vtime;
		u64 dsq;
		if (scx_dhq_nr_queued(dhq) == 0)
			return 0;
		if (!scx_dhq_peek(dhq))
			return 0;
		pid = scx_dhq_pop(dhq);
		if (!pid)
			return 0;
		/* Occupancy samples post-pop depth for sizing. Placement */
		/* below stays unchanged. */
		flow_occupancy_set(llc, dhq, cap);
		p = bpf_task_from_pid((s32)pid);
		if (!p) {
			flow_stale_account(llc);
			continue;
		}
		tst = strand;
		victim = llc;
		ins_vtime = (u64)p->scx.dsq_vtime;
		t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
		if (t) {
			tst = t->strand;
			if (t->deadline == flow_vtime_add_slice(t->vtime))
				ins_vtime = (u64)t->vtime;
			if (flow_llc_ok(t->llc_id))
				victim = t->llc_id;
		}
		/* Exiting uses the same victim path with a minimal slice. */
		/* Allowed targets run on the thief local queue and count */
		/* as dispatched. Disallowed targets go back to the victim */
		/* queue with no counter move and no loss, so exit still */
		/* runs on an allowed CPU. Local uses FIFO, shared keeps */
		/* vtime order. Dispatch synthesizes zero flags, same as */
		/* the normal path. One victim lookup serves both paths. */
		/* A bounce wakes the victim owner with no move no loss. Both the */
		/* exiting and the disallowed bounce share the constrained kick */
		/* with no split. Preempt when the owner runs far ahead past the */
		/* tail, else wake idle, else count a skip with no wake. Owner */
		/* plus vtime are copied before release so the kick never touches */
		/* a released task, and the kick re-validates the mask. */
		if (p->flags & PF_EXITING) {
			if (flow_cpu_allowed((s32)cpu, p)) {
				u64 ldsq = (u64)SCX_DSQ_LOCAL_ON | (u64)cpu;
				scx_bpf_dsq_insert(p, ldsq, (u64)FLOW_EXIT_SLICE_NS, 0);
				bpf_task_release(p);
				flow_queued_dec(victim);
				flow_stat_inc(llc, 1);
				if (always_steal) {
					flow_stat_inc(llc, 3);
					flow_stat_inc(llc, 9);
				}
				return 1;
			}
			{
				u64 vdsq = flow_llc_dsq(victim);
				s32 owner = flow_first_allowed(p);
				if (!flow_dsq_ok(vdsq))
					vdsq = (u64)FLOW_FALLBACK_DSQ;
				scx_bpf_dsq_insert_vtime(p, vdsq,
							 (u64)FLOW_EXIT_SLICE_NS,
							 ins_vtime, 0);
				flow_kick_constrained(owner, (s64)ins_vtime, p, victim);
				bpf_task_release(p);
				return 0;
			}
		}
		if (!flow_cpu_allowed((s32)cpu, p)) {
			u64 vdsq = flow_llc_dsq(victim);
			s32 owner = flow_first_allowed(p);
			u64 bsl = (u64)FLOW_SLICE_NS;
			if (t && t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
				bsl = (u64)FLOW_SLICE_NS * (u64)t->pad[0];
			if (!flow_dsq_ok(vdsq))
				vdsq = (u64)FLOW_FALLBACK_DSQ;
			scx_bpf_dsq_insert_vtime(p, vdsq, bsl, ins_vtime, 0);
			flow_kick_constrained(owner, (s64)ins_vtime, p, victim);
			bpf_task_release(p);
			return 0;
		}
		dsq = flow_llc_dsq(llc);
		{
			u64 isl = (u64)FLOW_SLICE_NS;
			if (t && t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
				isl = (u64)FLOW_SLICE_NS * (u64)t->pad[0];
			scx_bpf_dsq_insert_vtime(p, dsq, isl, ins_vtime, 0);
		}
		bpf_task_release(p);
		flow_queued_dec(victim);
		if (scx_bpf_dsq_move_to_local(dsq, 0)) {
			flow_stat_inc(llc, 1);
			if (always_steal || tst != strand) {
				flow_stat_inc(llc, 3);
				flow_stat_inc(llc, 9);
			}
			return 1;
		}
		flow_stat_inc(victim, 0);
		return 0;
	}
	return 0;
}

/* Steal keeps bounded retry 4 with peek hint plus pop truth, */
/* victim accounting saturates at zero, exiting uses minimal slice on the */
/* same victim path. Awarded tasks keep one slice times q with no other */
/* scale and no weight scale on the extra part. Order plus retry stay frozen. */
/* Docs only, no logic change. */

#endif
