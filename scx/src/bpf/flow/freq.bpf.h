// SPDX-License-Identifier: GPL-2.0
/*
 * Flow frequency hint helpers.
 *
 * Moved from main with no behavior change. The hint needs the schedutil
 * governor and hardware support and never changes placement. Hint is
 * neutral for the verifier with bounded integer math only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FREQ_BPF_H
#define __FLOW_FREQ_BPF_H

#include "../intf.h"
#include "maps.bpf.h"

/* Blend prior level with a fresh sample. Keeps three parts prior plus */
/* one part fresh so a single spike never flips the hint. Integer only. */
static __always_inline u64 flow_freq_smooth(u64 prior, u64 fresh)
{
	return (prior - (prior >> 2)) + (fresh >> 2);
}

/* Fold one stop sample into the per CPU level. Used holds nanos burnt */
/* this run. Wall holds nanos since the prior stop. Caps the raw ratio */
/* at full speed then blends it. Zero time plus missing state plus zero */
/* wall keep the prior level with no change. */
static __always_inline void flow_freq_sample(u32 cpu, u64 used)
{
	struct flow_freq_state *st;
	u64 now;
	u64 wall;
	u64 raw;
	if (!flow_cpu_ok(cpu))
		return;
	st = &flow_freq_state[cpu];
	now = bpf_ktime_get_ns();
	if (!now)
		return;
	if (!st->last) {
		st->last = now;
		return;
	}
	if (now <= st->last)
		return;
	wall = now - st->last;
	if (!wall)
		return;
	st->last = now;
	raw = used * (u64)SCX_CPUPERF_ONE / wall;
	if (raw > (u64)SCX_CPUPERF_ONE)
		raw = (u64)SCX_CPUPERF_ONE;
	st->level = flow_freq_smooth(st->level, raw);
}

/* Map a smoothed level to a hint for the governor. At or above three */
/* quarters ask for full speed so a busy core stays ready. At or below */
/* one quarter ask for half speed so an idle core rests but stays awake. */
/* Between the bands keep the smoothed value to avoid rapid flips. */
static __always_inline u64 flow_freq_hint(u64 level)
{
	u64 low = (u64)SCX_CPUPERF_ONE / 4;
	u64 high = (u64)SCX_CPUPERF_ONE - low;
	u64 half = (u64)SCX_CPUPERF_ONE / 2;
	if (level >= high)
		return (u64)SCX_CPUPERF_ONE;
	if (level <= low)
		return half;
	return level;
}

/* Push the hint for one CPU to the governor. Reads the smoothed level, */
/* maps through the band, sets one CPU only. Never sends zero so wake */
/* stays bounded. Clamps at full speed. */
static __always_inline void flow_freq_apply(s32 cpu)
{
	u32 id;
	struct flow_freq_state *st;
	u64 hint;
	if (cpu < 0)
		return;
	id = (u32)cpu;
	if (!flow_cpu_ok(id))
		return;
	st = &flow_freq_state[id];
	hint = flow_freq_hint(st->level);
	if (!hint)
		hint = (u64)SCX_CPUPERF_ONE / 2;
	if (hint > (u64)SCX_CPUPERF_ONE)
		hint = (u64)SCX_CPUPERF_ONE;
	scx_bpf_cpuperf_set(cpu, (u32)hint);
}

#endif
