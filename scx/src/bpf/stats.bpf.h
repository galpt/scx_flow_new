// SPDX-License-Identifier: GPL-2.0
/*
 * Counters for the flow scheduler.
 *
 * Each helper updates the counters of one LLC. The queued gauge
 * never drops below zero. It uses a short compare and swap loop.
 * If the loop does not win, the last observed value is written
 * back directly so a decrement is not lost under contention.
 * Award counters use plain adds. Extra and total move together
 * so the sums stay consistent. An unknown offset does nothing.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_STATS_BPF_H
#define __FLOW_STATS_BPF_H
#include "intf.h"
#include "maps.bpf.h"
static __always_inline struct flow_llc_stats *flow_stats_for(u32 llc)
{
	return bpf_map_lookup_elem(&llc_stats_stor, &llc);
}
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
		cell = &st->fb_duplicate;
	else if (off == 5)
		cell = &st->steal_llc;
	else if (off == 6)
		cell = &st->kick_preempt;
	else if (off == 7)
		cell = &st->kick_idle;
	else if (off == 8)
		cell = &st->kick_skip;
	else if (off == 9)
		cell = &st->overrun;
	else if (off == 10)
		cell = &st->domino_penalty;
	else if (off == 11)
		cell = &st->blocked;
	else if (off == 12)
		cell = &st->lst_escape;
	else if (off == 13)
		cell = &st->orphan_kick;
	else if (off == 14)
		cell = &st->hol_forward;
	else if (off == 15)
		cell = &st->lst_urgent;
	else if (off == 16)
		cell = &st->lst_hold;
	else if (off == 17)
		cell = &st->lst_preempt;
	else if (off == 18)
		cell = &st->lst_overdue;
	else
		return;
	__sync_fetch_and_add(cell, 1ULL);
}
static __always_inline void flow_stat_add(u32 llc, u64 off, u64 val)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	u64 *cell;
	if (!st || !val)
		return;
	if (off == 19)
		cell = &st->extra_award;
	else if (off == 20)
		cell = &st->total_quanta;
	else
		return;
	__sync_fetch_and_add(cell, val);
}
static __always_inline void flow_fb_inc(u32 llc, u64 tail_off)
{
	flow_stat_inc(llc, 2);
	flow_stat_inc(llc, tail_off);
}
static __always_inline void flow_queued_dec(u32 llc)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	int i;
	if (!st)
		return;
	for (i = 0; i < 4; i++) {
		u64 old = READ_ONCE(st->queued);
		u64 next;
		if (old == 0)
			return;
		next = old - 1;
		if (__sync_val_compare_and_swap(&st->queued, old, next) == old)
			return;
	}
	{
		u64 last = READ_ONCE(st->queued);
		if (last == 0)
			return;
		st->queued = last - 1;
	}
}
#endif
