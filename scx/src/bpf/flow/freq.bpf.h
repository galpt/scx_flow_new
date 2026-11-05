// SPDX-License-Identifier: GPL-2.0
/*
 * Flow frequency hints and burn scoring.
 *
 * The frequency hint blends three parts prior with one part fresh
 * and feeds the cpuperf governor only. The burn score uses the same
 * blend shape on the zero through one hundred scale with separate
 * growth and decay counts. Both use integer math throughout.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FREQ_BPF_H
#define __FLOW_FREQ_BPF_H

#include "../intf.h"
#include "maps.bpf.h"

/**
 * flow_freq_smooth - blend a fresh sample into a level.
 * @prior: current level.
 * @fresh: new sample.
 *
 * Keeps three parts prior plus one part fresh so a single spike
 * cannot flip the hint.
 *
 * Returns: the new level.
 */
static __always_inline u64 flow_freq_smooth(u64 prior, u64 fresh)
{
	return (prior - (prior >> 2)) + (fresh >> 2);
}

/**
 * flow_freq_sample - fold one stop sample into the CPU level.
 * @cpu: CPU id.
 * @used: nanos burnt this run.
 *
 * Caps the raw ratio at full speed, blends it, and shifts it into
 * the four entry ring with newest at zero. The ring has no reader
 * in BPF and serves post mortem sizing. Zero or reversed time
 * keeps the prior level. Races across CPUs heal on the next stop.
 */
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
	st->hist[3] = st->hist[2];
	st->hist[2] = st->hist[1];
	st->hist[1] = st->hist[0];
	st->hist[0] = raw;
	st->level = flow_freq_smooth(st->level, raw);
}

/**
 * flow_freq_hint - map a level to a governor hint.
 * @level: smoothed level.
 *
 * Full speed at or above three quarters, half speed at or below
 * one quarter, else the smoothed value to avoid rapid flips.
 *
 * Returns: the hint.
 */
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

/**
 * flow_freq_apply - push the hint for one CPU.
 * @cpu: CPU id.
 *
 * Sets one CPU only and never sends zero.
 */
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

/**
 * flow_score_growth - blend toward full on a full burn.
 * @s: current score.
 *
 * Keeps three parts old plus one part full with the result cut
 * down, capped at the top.
 *
 * Returns: the new score.
 */
static __always_inline u64 flow_score_growth(u64 s)
{
	u64 v;
	if (s > (u64)FLOW_SCORE_HMAX)
		s = (u64)FLOW_SCORE_HMAX;
	v = (3ULL * s + 100ULL) / 4ULL;
	if (v > (u64)FLOW_SCORE_HMAX)
		v = (u64)FLOW_SCORE_HMAX;
	return v;
}

/**
 * flow_score_decay - blend toward zero.
 * @s: current score.
 *
 * Keeps three parts old with the result cut down. Voluntary
 * yields, empty waits, and partial burns take this path.
 *
 * Returns: the new score.
 */
static __always_inline u64 flow_score_decay(u64 s)
{
	if (s > (u64)FLOW_SCORE_HMAX)
		s = (u64)FLOW_SCORE_HMAX;
	return (3ULL * s) / 4ULL;
}

/**
 * flow_score_extra - award level from score plus hold.
 * @score: current score.
 * @prev: last award level.
 *
 * Top engages at or above seventy five. A held top keeps level
 * two at or above fifty. Middle keeps one at or above twenty
 * five. The rest keeps zero.
 *
 * Returns: extra quanta, zero through two.
 */
static __always_inline u64 flow_score_extra(u64 score, u64 prev)
{
	if (score > (u64)FLOW_SCORE_HMAX)
		score = (u64)FLOW_SCORE_HMAX;
	if (prev > (u64)FLOW_MAX_EXTRA)
		prev = 0;
	if (score >= (u64)FLOW_SCORE_ENGAGE)
		return 2;
	if (prev == 2 && score >= (u64)FLOW_SCORE_RELEASE)
		return 2;
	if (score >= (u64)FLOW_SCORE_Q)
		return 1;
	return 0;
}

/**
 * flow_score_quanta - total quanta from an award level.
 * @extra: extra quanta.
 *
 * Returns: one plus extra, capped at three.
 */
static __always_inline u64 flow_score_quanta(u64 extra)
{
	if (extra > (u64)FLOW_MAX_EXTRA)
		extra = (u64)FLOW_MAX_EXTRA;
	return 1ULL + extra;
}

#endif
