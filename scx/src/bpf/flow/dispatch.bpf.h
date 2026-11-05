// SPDX-License-Identifier: GPL-2.0
/*
 * Flow dispatch with steal-outcome split.
 *
 * Moved from main with 10 counted on the thief for remote LLC steals.
 * Steal aggregate 3 moves with 10 so steal equals 9 plus 10. Order is
 * frozen: own pair, same node pairs, remote pairs, own LLC queue,
 * remote LLC queues, fallback safety net. A head that cannot run here
 * forwards one wake to the owner with no move no loss and counts hol
 * forward with a live allowed owner at pick on the dispatch LLC with
 * outcome split into preempt plus idle plus skip. Pair steals count through the steal
 * helper with 9. Queued_dec stays on the victim with saturation at zero.
 * No knob with fail closed choice.
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
#include "steal.bpf.h"

/* Forward one wake from an already peeked head with no second peek. */
/* Empty stays silent with no counter move. One wake per head plus owner */
/* keeps no storm with no move no loss. Preempt when the owner runs far */
/* ahead past the tail, else wake idle, else count a skip with no wake. */
/* Forward counts attempts with a live allowed owner at pick on the */
/* dispatch LLC with no order change, outcome splits into preempt plus */
/* idle plus skip so attempts never read as successes alone. No valid */
/* owner keeps coalescing with no forward count so a future valid head */
/* retries through the key mismatch. An owner change already forwards */
/* again through the key mismatch. A race that loses the owner between */
/* pick and kick stays a stats glitch. */
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
	flow_stat_inc(llc, 19);
	flow_kick_constrained(owner, hv, ph, llc);
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	TOUCH_ARENA();
	u32 c;
	u32 llc = 0;
	u32 node = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	u64 dsq;
	u64 own_idx = (u64)-1;
	scx_dhq_t *dhq = NULL;
	u32 pi;
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
	dsq = flow_llc_dsq(llc);
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)FLOW_STRAND_A &&
			    strand != (u32)FLOW_STRAND_B)
				strand = (u32)SCX_DHQ_STRAND_A;
			own_idx = idx;
		}
	}
	if (dhq) {
		{
			u64 cap = 0;
			if (own_idx < (u64)FLOW_MAX_PAIRS)
				cap = flow_pair_cap[(u32)own_idx];
			if (flow_pop_to_local(dhq, llc, strand, 0, c, cap))
				return;
		}
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			u64 cap;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] != node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			cap = flow_pair_cap[pi];
			if (flow_pop_to_local(cand, llc, strand, 1, c, cap))
				return;
		}
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			u64 cap;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] == node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			cap = flow_pair_cap[pi];
			if (flow_pop_to_local(cand, llc, strand, 1, c, cap))
				return;
		}
	}
	{
		struct task_struct *ph = __COMPAT_scx_bpf_dsq_peek(dsq);

		if (ph) {
			if (!flow_cpu_allowed((s32)c, ph)) {
				/* Head cannot run here. Forward one wake */
				/* to the owner with no move no loss. */
				flow_forward_from_peeked(ph, llc, llc);
			} else if (scx_bpf_dsq_move_to_local(dsq, 0)) {
				flow_stat_inc(llc, 1);
				flow_queued_dec(llc);
				return;
			}
		}
	}
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u64 odsq;
		struct task_struct *ph;
		if (li == llc)
			continue;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		ph = __COMPAT_scx_bpf_dsq_peek(odsq);
		if (!ph)
			continue;
		if (!flow_cpu_allowed((s32)c, ph)) {
			flow_forward_from_peeked(ph, llc, li);
			continue;
		}
		if (scx_bpf_dsq_move_to_local(odsq, 0)) {
			flow_stat_inc(llc, 1);
			flow_queued_dec(li);
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 10);
			return;
		}
	}
	/* Fallback DSQ is safety only. It stays empty unless no live target exists. */
	/* Queued was charged to the enqueue LLC at insert, zero when no live */
	/* target existed. The dec below takes a best effort victim with backlog */
	/* so the total stays close with no loss. Stats only best effort with */
	/* saturation at zero, a race stays a stats glitch. Single peek per */
	/* queue serves the allowed test plus the move plus the forward wake. */
	{
		struct task_struct *fph = __COMPAT_scx_bpf_dsq_peek((u64)FLOW_FALLBACK_DSQ);

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

/* Dispatch order stays frozen own pair, same node pairs, */
/* remote pairs, own LLC queue, remote LLC queues, fallback safety net. */
/* Steal 9 plus 10 plus hol forward 19 valid owner only accounting */
/* unchanged in order. Forward attempts with no valid owner keep */
/* coalescing with no count so a future valid head retries. */
/* Docs only, no logic change. */

#endif
