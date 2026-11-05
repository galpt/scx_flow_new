// SPDX-License-Identifier: GPL-2.0
/*
 * Flow dispatch with steal-outcome split.
 *
 * Moved from main with 10 counted on the thief for remote LLC steals.
 * Steal aggregate 3 moves with 10 so steal equals 9 plus 10. Order is
 * frozen: own pair, same node pairs, remote pairs, own LLC queue,
 * remote LLC queues, fallback safety net. Pair steals count through
 * the steal helper with 9. Queued_dec stays on the victim with
 * saturation at zero. No knob with fail closed choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DISPATCH_BPF_H
#define __FLOW_DISPATCH_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "steal.bpf.h"

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
		if (!flow_llc_ok(READ_ONCE(cc->llc_id)))
			return;
		llc = READ_ONCE(cc->llc_id);
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
	if (flow_dsq_head_allowed(dsq, c) && scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_inc(llc, 1);
		flow_queued_dec(llc);
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
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		if (!flow_dsq_head_allowed(odsq, c))
			continue;
		if (scx_bpf_dsq_move_to_local(odsq, 0)) {
			flow_stat_inc(llc, 1);
			flow_queued_dec(li);
			flow_stat_inc(llc, 3);
			flow_stat_inc(llc, 10);
			return;
		}
	}
	/* Fallback DSQ is safety only. It stays empty unless LLC validation fails. */
	if (flow_dsq_head_allowed((u64)FLOW_FALLBACK_DSQ, c) &&
	    scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
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

/* Dispatch order stays frozen own pair, same node pairs, */
/* remote pairs, own LLC queue, remote LLC queues, fallback safety net. */
/* Steal 9 plus 10 accounting unchanged. Docs only, no logic change. */

#endif
