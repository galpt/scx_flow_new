// SPDX-License-Identifier: GPL-2.0
/*
 * Flow per LLC counters.
 *
 * Offsets 0:queued 1:dispatched 2:fallback 3:steal 4:fb_pair_full
 * 5:fb_duplicate 6:fb_stale 7:dhq_depth 8:dhq_cap stay frozen for compat.
 * Tail 9:steal_pair 10:steal_llc 11:kick_preempt 12:kick_idle 13:kick_skip
 * 14:overrun 15:domino_penalty 16:blocked is append-only with no bound change. Fallback equals 4 plus
 * 5 plus 6. Steal equals 9 plus 10. Gauges 7:depth 8:cap use the
 * occupancy set helper, never inc. Unknown offsets return with no change.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STATS_BPF_H
#define __FLOW_STATS_BPF_H

#include "../intf.h"
#include "maps.bpf.h"

static __always_inline struct flow_llc_stats *flow_stats_for(u32 llc)
{
	return bpf_map_lookup_elem(&llc_stats_stor, &llc);
}

/* Offsets 0:queued 1:dispatched 2:fallback 3:steal stay stable. Tail 4:fb_pair_full */
/* 5:fb_duplicate 6:fb_stale split fallback by cause. Gauges 7:depth */
/* 8:cap use the occupancy set helper, never inc. Steal split 9:pair */
/* 10:llc plus kick split 11:preempt 12:idle 13:skip plus overrun split */
/* 14:overrun 15:domino_penalty plus 16:blocked are append-only. */
static __always_inline void flow_stat_inc(u32 llc, u64 off)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	u64 *cell;
	if (!st)
		return;
	if (off == 0)
		cell = &st->queued;
	else if (off == 1)
		cell = &st->dispatched;
	else if (off == 2)
		cell = &st->fallback;
	else if (off == 3)
		cell = &st->steal;
	else if (off == 4)
		cell = &st->fb_pair_full;
	else if (off == 5)
		cell = &st->fb_duplicate;
	else if (off == 6)
		cell = &st->fb_stale;
	else if (off == 9)
		cell = &st->steal_pair;
	else if (off == 10)
		cell = &st->steal_llc;
	else if (off == 11)
		cell = &st->kick_preempt;
	else if (off == 12)
		cell = &st->kick_idle;
	else if (off == 13)
		cell = &st->kick_skip;
	else if (off == 14)
		cell = &st->overrun;
	else if (off == 15)
		cell = &st->domino_penalty;
	else if (off == 16)
		cell = &st->blocked;
	else
		return;
	__sync_fetch_and_add(cell, 1ULL);
}

/* Count one fallback cause. Keeps fallback as the aggregate for compat */
/* while splitting the cause into the tail. tail_off is 4:pair-full */
/* 5:duplicate 6:stale. */
static __always_inline void flow_fb_inc(u32 llc, u64 tail_off)
{
	flow_stat_inc(llc, 2);
	flow_stat_inc(llc, tail_off);
}

/* Record last observed pair occupancy for sizing. Depth is post-op */
/* nr_queued, cap is the configured pair capacity. Null dhq or missing */
/* stats keeps prior gauges. Single LLC has no pair so gauges stay zero. */
static __always_inline void flow_occupancy_set(u32 llc, scx_dhq_t *dhq, u64 cap)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	int depth;
	if (!st || !dhq)
		return;
	depth = scx_dhq_nr_queued(dhq);
	if (depth < 0)
		depth = 0;
	st->dhq_depth = (u64)depth;
	st->dhq_cap = cap;
}

/* Decrement queued by one with saturation at zero. Stats only best effort. */
/* A concurrent dec race stays a stats glitch with no loss and no wrap */
/* beyond the zero check, so the total stays close. */
static __always_inline void flow_queued_dec(u32 llc)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	if (!st)
		return;
	if (READ_ONCE(st->queued) == 0)
		return;
	__sync_fetch_and_sub(&st->queued, 1ULL);
}

/* Stale discard. Queued belongs to an exited task so attribute the */
/* decrement to a victim with backlog. This keeps the total correct */
/* and avoids a wrap on an empty thief. Thief counts fallback plus stale, */
/* victim takes the queued dec. Fallback counts the discard as the */
/* aggregate plus the stale tail for the split. Queued stays charged to */
/* the enqueue LLC while dispatched stays on the dispatch LLC, so thief */
/* versus victim attribution stays explicit with no loss. */
static __always_inline void flow_stale_account(u32 thief)
{
	u32 li;
	flow_fb_inc(thief, 6);
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		struct flow_llc_stats *st;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		st = flow_stats_for(li);
		if (!st)
			continue;
		if (READ_ONCE(st->queued) == 0)
			continue;
		__sync_fetch_and_sub(&st->queued, 1ULL);
		break;
	}
}

/* Stats 0 through 13 stay frozen with tail 14 through 16 */
/* append only, fallback equals 4 plus 5 plus 6, steal equals 9 plus 10, */
/* gauges use set only. Docs only, no logic change. */

#endif
