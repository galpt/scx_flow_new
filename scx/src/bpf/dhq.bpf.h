// SPDX-License-Identifier: GPL-2.0
/*
 * Per CPU queue helpers for the flow scheduler.
 *
 * Urgent tasks take the first strand and the rest take the second
 * strand. Balanced mode drains the larger strand first with a long
 * head promoted on ties. Imbalance stays capped so no strand
 * starves.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DHQ_BPF_H
#define __FLOW_DHQ_BPF_H
#include "intf.h"
u64 flow_dhq_strand_for_prio(u32 prio);
u64 flow_dhq_pick_mode(void);
u64 flow_dhq_max_imbalance(void);
u64 flow_dhq_balanced_pick(u64 size_a, u64 size_b);
bool flow_dhq_over_imbalance(u64 my_size, u64 other_size);
#endif
