// SPDX-License-Identifier: GPL-2.0
/*
 * Per CPU queue helpers for the flow scheduler.
 *
 * Strand choice keeps urgent work apart from the rest so a busy
 * batch head never blocks an urgent task. Mode stays balanced so
 * the larger strand drains first. Imbalance checks use plain
 * compares with no division.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include "dhq.bpf.h"
__hidden u64 flow_dhq_strand_for_prio(u32 prio)
{
	if (prio == (u32)FLOW_PRIO_LAT)
		return (u64)FLOW_DHQ_STRAND_A;
	return (u64)FLOW_DHQ_STRAND_B;
}
__hidden u64 flow_dhq_pick_mode(void)
{
	return (u64)FLOW_DHQ_MODE_BALANCED;
}
__hidden u64 flow_dhq_max_imbalance(void)
{
	return (u64)FLOW_DHQ_MAX_IMBALANCE;
}
__hidden u64 flow_dhq_balanced_pick(u64 size_a, u64 size_b)
{
	if (size_b > size_a)
		return (u64)FLOW_DHQ_STRAND_B;
	return (u64)FLOW_DHQ_STRAND_A;
}
__hidden bool flow_dhq_over_imbalance(u64 my_size, u64 other_size)
{
	u64 cap = flow_dhq_max_imbalance();
	return my_size >= other_size + cap;
}
