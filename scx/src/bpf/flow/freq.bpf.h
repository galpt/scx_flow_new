// SPDX-License-Identifier: GPL-2.0
/*
 * Flow frequency hint helpers.
 *
 * Moved from main with no placement change. The hint needs the schedutil
 * governor and hardware support and never changes placement. Hist keeps
 * the last four raw samples as a shift ring for sizing with no reader
 * in BPF by design as shadow verify for post mortem sizing only. Hint
 * is neutral for the verifier with bounded integer math only and a bound
 * of four.
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
/* at full speed then blends it. Writes the raw sample into the four */
/* entry shift ring with integer moves only, newest at zero. The ring */
/* has no reader in BPF and stays for sizing post mortem only with no */
/* placement use. Zero time plus missing state plus zero wall keep the */
/* prior level with no change. */
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

/* Score growth with floor and cap. Keeps three parts old plus one part */
/* full with integer cut down and never round up. Caps at the top with */
/* no wrap. Wide sum stays at or below four hundred. Full burn with raw */
/* top takes this path with a separate count. */
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

/* Score decay with floor and no added term. Keeps three parts old with */
/* integer cut down and never round up. Wide sum stays below the cap. */
/* Voluntary plus empty wait plus clean stop take this path with a */
/* separate count and no growth step on that stop. */
static __always_inline u64 flow_score_decay(u64 s)
{
	if (s > (u64)FLOW_SCORE_HMAX)
		s = (u64)FLOW_SCORE_HMAX;
	return (3ULL * s) / 4ULL;
}

/* Extra award from score plus hold with top first order. Top engages at */
/* or above seventy five. Hold keeps two while at or above fifty when the */
/* last award held two. Middle keeps one at or above twenty five. Rest */
/* keeps zero. Sticky top wins ties at the edge with no second path. */
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

/* Total quanta from extra with one base plus extra and no half step. */
/* Caps extra at two and total at three with no knob. */
static __always_inline u64 flow_score_quanta(u64 extra)
{
	if (extra > (u64)FLOW_MAX_EXTRA)
		extra = (u64)FLOW_MAX_EXTRA;
	return 1ULL + extra;
}

/* Freq hint stays neutral for placement with bounded */
/* integer math three parts prior plus one part fresh plus band full, */
/* half, keep, plus a four entry shift ring. Score blend keeps the same */
/* three plus one shape on zero through one hundred with floor both, wide */
/* cap four hundred, window about four, time about three and a half, and */
/* separate growth plus decay counts with no float. */
/* Docs only, no logic change. */

#endif
