// SPDX-License-Identifier: GPL-2.0
/*
 * Flow per LLC counters.
 *
 * Each helper attributes to one LLC so enqueue and dispatch sides
 * stay apart. The queued gauge saturates at zero on decrement. The
 * award tails take adds: extra takes q minus one, total takes q, so
 * total meets penalty plus extra on each award. Unknown offsets take
 * no action.
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

/**
 * flow_stat_inc - count one event.
 * @llc: LLC to charge.
 * @off: counter index matching the struct order.
 */
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
		cell = &st->hog_escape;
	else if (off == 13)
		cell = &st->orphan_kick;
	else if (off == 14)
		cell = &st->hol_forward;
	else if (off == 15)
		cell = &st->lat_boost;
	else if (off == 16)
		cell = &st->hog_hold;
	else if (off == 17)
		cell = &st->lat_preempt;
	else if (off == 18)
		cell = &st->age_rescue;
	else
		return;
	__sync_fetch_and_add(cell, 1ULL);
}

/**
 * flow_stat_add - add an award amount to a tail counter.
 * @llc: LLC to charge.
 * @off: counter index, 19 for extra or 20 for total.
 * @val: amount to add. Zero takes no action.
 */
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

/**
 * flow_fb_inc - count a fallback with its cause.
 * @llc: LLC to charge.
 * @tail_off: cause index, 4 for duplicate drops.
 *
 * Charges the aggregate and the cause together.
 */
static __always_inline void flow_fb_inc(u32 llc, u64 tail_off)
{
	flow_stat_inc(llc, 2);
	flow_stat_inc(llc, tail_off);
}

/**
 * flow_queued_dec - drop the queued gauge by one.
 * @llc: LLC to charge.
 *
 * Saturates at zero. A concurrent race between the check and the
 * subtract stays a small stats skew with no effect on placement,
 * healing on the next insert.
 */
static __always_inline void flow_queued_dec(u32 llc)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	if (!st)
		return;
	if (READ_ONCE(st->queued) == 0)
		return;
	__sync_fetch_and_sub(&st->queued, 1ULL);
}

#endif
