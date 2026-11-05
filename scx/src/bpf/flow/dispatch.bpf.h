// SPDX-License-Identifier: GPL-2.0
/*
 * Flow dispatch.
 *
 * Each CPU drains its own LLC queue first, then LLC queues on the
 * same node, then LLC queues on other nodes, then the fallback
 * queue. A head that cannot run here forwards one wake to the
 * owner with no move. Remote moves count steal on the thief and
 * drop the queued gauge on the victim. Queued keys already carry
 * the latency shift, so the forward kick compares shifted keys on
 * both sides.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DISPATCH_BPF_H
#define __FLOW_DISPATCH_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "preempt.bpf.h"

/**
 * flow_forward_from_peeked - forward one wake for a peeked head.
 * @ph: peeked head task, may be NULL.
 * @llc: LLC to charge.
 * @slot: coalescing slot, one per LLC plus one for fallback.
 *
 * Empty stays silent. One wake per head plus owner keeps wakes
 * bounded. A head with no valid owner keeps coalescing state
 * without counting, so a later valid head retries.
 */
static __always_inline void flow_forward_from_peeked(struct task_struct *ph,
						     u32 llc, u32 slot)
{
	s32 owner;
	s64 hv;
	u64 pid;

	if (!ph)
		return;
	if (slot > (u32)FLOW_MAX_LLCS)
		return;
	pid = (u64)ph->pid;
	hv = (s64)ph->scx.dsq_vtime;
	owner = flow_first_allowed(ph);
	{
		u64 last_p = READ_ONCE(flow_fwd_pid[slot]);
		s64 last_v = READ_ONCE(flow_fwd_vtime[slot]);
		s32 last_o = READ_ONCE(flow_fwd_owner[slot]);

		if (last_p == pid && last_v == hv && last_o == owner)
			return;
		flow_fwd_pid[slot] = pid;
		flow_fwd_vtime[slot] = hv;
		flow_fwd_owner[slot] = owner;
	}
	if (owner < 0) {
		flow_kick_constrained(owner, hv, ph, llc);
		return;
	}
	flow_stat_inc(llc, 14);
	flow_kick_constrained(owner, hv, ph, llc);
}

/**
 * flow_try_move - peek one queue and move its head when runnable here.
 * @cpu: dispatching CPU.
 * @llc: LLC to charge the move.
 * @victim: LLC that owns the queue, for the queued gauge.
 * @dsq: queue id.
 * @slot: coalescing slot for forwards.
 * @steal: non-zero when the queue is remote.
 *
 * Peeks once and serves the allowed test plus the move plus the
 * forward wake from that peek.
 *
 * Returns: one when a task reached the local queue, else zero.
 */
static __always_inline int flow_try_move(u32 cpu, u32 llc, u32 victim,
					 u64 dsq, u32 slot, int steal)
{
	struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek(dsq);

	if (!ph)
		return 0;
	if (!flow_cpu_allowed((s32)cpu, ph)) {
		flow_forward_from_peeked(ph, llc, slot);
		return 0;
	}
	if (scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_inc(llc, 1);
		flow_queued_dec(victim);
		if (steal) {
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 5);
		}
		return 1;
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 node = 0;
	u32 li;
	(void)prev;
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return;
	{
		u32 key = c;
		struct flow_cpu_ctx *cc;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			return;
		{
			u32 tmp = READ_ONCE(cc->llc_id);
			if (!flow_llc_ok(tmp))
				return;
			llc = tmp;
		}
		node = READ_ONCE(cc->node_id);
		if (!flow_node_ok(node))
			node = 0;
	}
	if (flow_try_move(c, llc, llc, flow_llc_dsq(llc), llc, 0))
		return;
	/* Same node queues before other nodes to keep work near. */
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u64 odsq;
		if (li == llc)
			continue;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		if (flow_llc_node[li] != node)
			continue;
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		if (flow_try_move(c, llc, li, odsq, li, 1))
			return;
	}
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u64 odsq;
		if (li == llc)
			continue;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		if (flow_llc_node[li] == node)
			continue;
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		if (flow_try_move(c, llc, li, odsq, li, 1))
			return;
	}
	/* Fallback holds tasks with no live target at insert. The */
	/* queued gauge was charged to the enqueue LLC, so the move */
	/* takes a best effort drop from a victim with backlog. */
	{
		struct task_struct *fph =
			__COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);

		if (fph) {
			if (!flow_cpu_allowed((s32)c, fph)) {
				flow_forward_from_peeked(fph, llc, (u32)FLOW_MAX_LLCS);
			} else if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
				u32 li2;

				flow_stat_inc(llc, 1);
				bpf_for(li2, 0, FLOW_MAX_LLCS) {
					struct flow_llc_stats *st;
					if ((u64)li2 >= flow_nr_llcs)
						break;
					if (!flow_llc_ok(li2))
						continue;
					st = flow_stats_for(li2);
					if (!st)
						continue;
					if (READ_ONCE(st->queued) == 0)
						continue;
					__sync_fetch_and_sub(&st->queued, 1ULL);
					break;
				}
				return;
			}
		}
	}
}

#endif
