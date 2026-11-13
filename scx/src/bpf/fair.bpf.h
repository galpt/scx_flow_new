// SPDX-License-Identifier: GPL-2.0
/*
 * Fair charging and lag-conserving EEVDF virtual deadline pricing
 * for the flow scheduler.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H

#include "intf.h"
#include "maps.bpf.h"
#include <lib/sdt_alloc.h>

/* Slab for BST entries with one entry per queued task at most through
 * the queued bit, so the backlog stays within the live task count.
 */
static struct scx_allocator flow_rb_alloc;

/* Nice weight on the weight scale from minus twenty to nineteen.
 * Strictly falls from ten thousand to one with one hundred at zero.
 * Fits in read only data with direct indexing and no loop.
 */
static const u32 flow_nice_table[40] = {
	10000, 7943, 6310, 5012, 3981, 3162, 2512, 1995, 1585, 1259,
	1000, 794, 631, 501, 398, 316, 251, 200, 158, 126,
	100, 78, 62, 48, 38, 30, 23, 18, 14, 11,
	10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
};

static __always_inline u32 flow_nice_weight(const struct task_struct *p)
{
	s32 prio;
	u32 idx;

	if (!p)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	prio = p->static_prio - 120;
	if (prio < -20 || prio > 19)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	idx = (u32)(prio + 20);
	if (idx >= 40U)
		return (u32)FLOW_CGROUP_WEIGHT_DFLT;
	return flow_nice_table[idx];
}

static __always_inline u32 flow_share_live(const struct task_struct *p)
{
	(void)p;
	return (u32)FLOW_CGROUP_WEIGHT_DFLT;
}

static __always_inline u32 flow_eff_w(u32 nw, u32 sw)
{
	u32 n = nw;
	u32 s = sw;

	if (n == (u32)FLOW_CGROUP_WEIGHT_INVALID || n < (u32)FLOW_CGROUP_WEIGHT_MIN)
		n = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	else if (n > (u32)FLOW_CGROUP_WEIGHT_MAX)
		n = (u32)FLOW_CGROUP_WEIGHT_MAX;

	if (s == (u32)FLOW_CGROUP_WEIGHT_INVALID || s < (u32)FLOW_CGROUP_WEIGHT_MIN)
		s = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	else if (s > (u32)FLOW_CGROUP_WEIGHT_MAX)
		s = (u32)FLOW_CGROUP_WEIGHT_MAX;

	if (s == (u32)FLOW_CGROUP_WEIGHT_DFLT)
		return n;
	if (n == (u32)FLOW_CGROUP_WEIGHT_DFLT)
		return s;
	return n < s ? n : s;
}

/* Context-aware effective task weight. Boosts kernel threads, interactive
 * frame/audio cadence threads, and urgent producer-consumer wakeups.
 */
static __always_inline u32 flow_task_weight(const struct task_struct *p,
					    struct flow_task_ctx *t)
{
	u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));

	if (!p)
		return w;
	if (p->flags & (PF_KTHREAD | PF_WQ_WORKER | PF_IO_WORKER))
		w += (w >> 1);
	if (t) {
		u32 fl = READ_ONCE(t->flags);

		if (fl & (u32)FLOW_FLAG_INTERACTIVE)
			w += (w >> 1);
		if (fl & (u32)FLOW_FLAG_URGENT)
			w += (w >> 1);
	}
	if (w > (u32)FLOW_CGROUP_WEIGHT_MAX)
		w = (u32)FLOW_CGROUP_WEIGHT_MAX;
	return w;
}

static __always_inline u64 flow_fair_step(u32 w)
{
	u32 cw = w;

	if (cw == (u32)FLOW_CGROUP_WEIGHT_INVALID || cw < (u32)FLOW_CGROUP_WEIGHT_MIN)
		cw = (u32)FLOW_CGROUP_WEIGHT_DFLT;
	if (cw > (u32)FLOW_CGROUP_WEIGHT_MAX)
		cw = (u32)FLOW_CGROUP_WEIGHT_MAX;
	if (!cw)
		return (u64)FLOW_SLICE_MIN_NS;
	return (u64)FLOW_SLICE_MIN_NS * (u64)FLOW_CGROUP_WEIGHT_DFLT / (u64)cw;
}

static __always_inline s64 flow_fair_cap_add(s64 base, u64 add)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;

	if (add > (u64)vmax)
		return vmax;
	if (base >= vmax - (s64)add)
		return vmax;
	return base + (s64)add;
}

static __always_inline u64 flow_lag_clamp(u64 lag)
{
	if (lag > (u64)FLOW_LAG_MAX_NS) {
		__sync_fetch_and_add(&m_lag_clamp, 1ULL);
		return (u64)FLOW_LAG_MAX_NS;
	}
	return lag;
}

static __always_inline u64 flow_rb_deadline(s64 vd)
{
	return (u64)vd + 0x8000000000000000ULL;
}

static __noinline s64 flow_fair_charge(s64 base, u64 used, u32 w)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	u64 st = flow_fair_step(w);
	u64 slice = (u64)FLOW_SLICE_MIN_NS;
	u64 hi;
	u64 lo;
	u64 scaled;

	if (!st)
		st = (u64)FLOW_SLICE_MIN_NS;
	if (!slice)
		slice = (u64)FLOW_SLICE_MIN_NS;
	hi = used / slice;
	lo = used % slice;
	if (hi > (u64)vmax / st)
		return vmax;
	scaled = hi * st + lo * st / slice;
	if (scaled > (u64)vmax)
		return vmax;
	return flow_fair_cap_add(base, scaled);
}

static __always_inline u64 flow_burst_clamp(u64 burst_ns)
{
	if (!burst_ns || burst_ns > (u64)FLOW_SLICE_MIN_NS)
		return (u64)FLOW_SLICE_MIN_NS;
	if (burst_ns < (u64)FLOW_SLICE_FLOOR_NS)
		return (u64)FLOW_SLICE_FLOOR_NS;
	return burst_ns;
}

u64 m_ewma_fold;
u64 m_ewma_sat;
u64 m_ewma_freeze;

static __always_inline u64 flow_ewma_next(u64 old, u64 sample)
{
	if (!sample)
		return old;
	if (!old)
		return sample;
	return (old + 3ULL * sample) >> 2;
}

static __always_inline s64 flow_vd_for(s64 floored, u64 burst_ns, u32 w)
{
	u64 b = flow_burst_clamp(burst_ns);
	s64 vd = flow_fair_charge(floored, b, w);

	if (vd <= floored)
		return flow_fair_cap_add(floored, 1);
	return vd;
}

static __noinline u64 flow_smoothed_ref(struct flow_task_ctx *t)
{
	u64 ref;

	if (!t)
		return 0;
	if (!READ_ONCE(t->run_known))
		return 0;
	ref = READ_ONCE(t->run_max);
	__sync_fetch_and_add(&m_ewma_fold, 1ULL);
	if (!ref)
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
	return ref;
}

static __noinline u64 flow_smoothed_eff(u64 ref, u64 burst_ns)
{
	u64 b = flow_burst_clamp(burst_ns);
	u64 e = ref > b ? ref : b;

	if (e > (u64)FLOW_SLICE_MIN_NS) {
		__sync_fetch_and_add(&m_ewma_sat, 1ULL);
		e = (u64)FLOW_SLICE_MIN_NS;
	}
	return e;
}

/* Unified Lag-Conserving EEVDF Virtual Deadline.
 * Prices tasks by their smoothed burst estimate, adds a bounded penalty for
 * continuous non-sleeping CPU hogs, and deducts bounded virtual lag credit.
 * When no lag credit applies the due time stays bound above the floor by a
 * multiple of the fair step derived from existing bounds only, so a task
 * far ahead in service cannot hold a distant due time past a stall.
 * The multiple reuses LAG_MAX divided by SLICE_MIN with integer math only.
 */
static __noinline s64 flow_eevdf_vd(struct flow_task_ctx *t, s64 floored,
				    u64 lag_ns, u32 w)
{
	u64 burst = t ? flow_burst_clamp(READ_ONCE(t->burst_ns)) :
			(u64)FLOW_SLICE_MIN_NS;
	u64 sref = flow_smoothed_ref(t);
	u64 req_ns = sref ? flow_smoothed_eff(sref, burst) : burst;
	u64 tot = t ? READ_ONCE(t->run_total) : 0;
	u64 clamped_lag = lag_ns > (u64)FLOW_LAG_MAX_NS ?
			  (u64)FLOW_LAG_MAX_NS : lag_ns;
	u64 credit;
	s64 vd;

	if (tot > (u64)FLOW_SLICE_MIN_NS) {
		u64 extra = tot - (u64)FLOW_SLICE_MIN_NS;

		if (extra > (u64)FLOW_SLICE_MIN_NS)
			extra = (u64)FLOW_SLICE_MIN_NS;
		req_ns += extra;
	}

	credit = ((req_ns >> 1) * clamped_lag) / (u64)FLOW_LAG_MAX_NS;
	if (req_ns > credit + (u64)FLOW_SLICE_FLOOR_NS)
		req_ns -= credit;
	else
		req_ns = (u64)FLOW_SLICE_FLOOR_NS;

	vd = flow_fair_charge(floored, req_ns, w);
	if (vd <= floored)
		return flow_fair_cap_add(floored, 1);
	if (!clamped_lag) {
		u64 k = (u64)FLOW_LAG_MAX_NS / (u64)FLOW_SLICE_MIN_NS;
		u64 st = flow_fair_step(w);
		u64 hi = st / (u64)FLOW_SLICE_MIN_NS;
		u64 lo = st % (u64)FLOW_SLICE_MIN_NS;
		u64 kstep = k * hi * (u64)FLOW_SLICE_MIN_NS + k * lo;
		s64 bound = flow_fair_cap_add(floored, kstep);

		if (vd > bound)
			return bound;
	}
	return vd;
}

/* Load-adaptive time slice calculation.
 * Never truncates slices below FLOW_SLICE_MIN_NS (1ms). Expands slices up to
 * FLOW_SLICE_MAX_NS (3ms) when the target CPU's tree is empty.
 */
static __always_inline u64 flow_calc_slice(struct flow_task_ctx *t, bool q_empty)
{
	if (!q_empty)
		return (u64)FLOW_SLICE_MIN_NS;
	if (!t)
		return (u64)FLOW_SLICE_MAX_NS;
	if (READ_ONCE(t->flags) & ((u32)FLOW_FLAG_INTERACTIVE | (u32)FLOW_FLAG_URGENT))
		return (u64)FLOW_SLICE_MAX_NS;
	if (READ_ONCE(t->burst_ns) >= ((u64)FLOW_SLICE_MIN_NS >> 1))
		return (u64)FLOW_SLICE_MAX_NS;
	return (u64)FLOW_SLICE_MIN_NS * 2ULL;
}

static __always_inline u64 flow_burst_update(u64 old_burst, u64 total_used,
					     u64 cur, bool runnable)
{
	u64 b = flow_burst_clamp(old_burst);
	u64 u = total_used;

	if (!cur && u < (u64)FLOW_SLICE_MIN_NS)
		u = (u64)FLOW_SLICE_MIN_NS;
	if (u > (u64)FLOW_SLICE_MIN_NS)
		u = (u64)FLOW_SLICE_MIN_NS;
	if (runnable) {
		if (u > b)
			b = flow_ewma_next(u, b);
		return flow_burst_clamp(b);
	}
	b = flow_ewma_next(b, u);
	return flow_burst_clamp(b);
}

/* Per LLC floor with bound catch-up. A stale base returns last plus one
 * for uniqueness. A fresh base advances at most one STEP past last, so a
 * single enqueue cannot lift the floor past a stall. Pricing stays
 * unchanged. Zero means unseeded and reads fail open in callers. */
static __noinline s64 flow_seq_floor(u32 llc, s64 v)
{
	const s64 vmax = (s64)0x7fffffffffffffffLL;
	int i;

	if (!flow_llc_ok(llc))
		return v;
	for (i = 0; i < 4; i++) {
		s64 last = READ_ONCE(flow_llc_seq[llc]);
		s64 want = v;
		s64 next;

		if (want <= last) {
			if (last == vmax)
				want = last;
			else
				want = last + 1;
			next = want;
		} else {
			s64 cap = flow_fair_cap_add(last, (u64)FLOW_SEQ_FLOOR_STEP_NS);

			if (want < cap)
				next = want;
			else
				next = cap;
		}
		if (__sync_val_compare_and_swap(&flow_llc_seq[llc], last, next) == last)
			return want;
	}
	s64 last = READ_ONCE(flow_llc_seq[llc]);

	if (v <= last) {
		if (last >= vmax - 1)
			return vmax;
		return __sync_add_and_fetch(&flow_llc_seq[llc], 1LL);
	}
	return v;
}

static __always_inline void flow_run_reset(struct flow_task_ctx *t)
{
	int i;

	if (!t)
		return;
	for (i = 0; i < 8; i++) {
		t->run_dur[i] = 0;
		t->run_stamp[i] = 0;
	}
	t->run_min = 0;
	t->run_max = 0;
	t->run_total = 0;
	t->run_head = 0;
	t->run_pruned = 0;
	t->run_known = 0;
	t->run_pad = 0;
}

static __always_inline void flow_run_add(struct flow_task_ctx *t, u64 delta)
{
	u64 cur;
	u64 win;

	if (!t || !delta)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	if (delta > win)
		delta = win;
	cur = READ_ONCE(t->run_total);
	if (cur >= win)
		return;
	if (delta >= win - cur)
		t->run_total = win;
	else
		t->run_total = cur + delta;
}

static __noinline void flow_run_recalc(struct flow_task_ctx *t)
{
	u64 min_d = 0;
	u64 max_d = 0;
	u64 min_s = 0;
	u64 max_s = 0;
	u64 kept = 0;
	u64 s_min_d;
	u64 s_max_d;
	bool have = false;
	int i;

	if (!t)
		return;
	__sync_fetch_and_add(&m_ewma_fold, 1ULL);
	#pragma unroll
	for (i = 0; i < 8; i++) {
		u64 d = READ_ONCE(t->run_dur[i]);
		u64 s = READ_ONCE(t->run_stamp[i]);

		if (!d || !s)
			continue;
		if (!have) {
			min_d = d;
			max_d = d;
			min_s = s;
			max_s = s;
			have = true;
		} else {
			if (d < min_d)
				min_d = d;
			if (d > max_d)
				max_d = d;
			if (s < min_s)
				min_s = s;
			if (s > max_s)
				max_s = s;
		}
		kept++;
	}
	if (!have) {
		t->run_min = 0;
		t->run_max = 0;
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	s_min_d = flow_ewma_next(READ_ONCE(t->run_min), min_d);
	s_max_d = flow_ewma_next(READ_ONCE(t->run_max), max_d);
	if (s_max_d < s_min_d)
		s_max_d = s_min_d;
	t->run_min = s_min_d;
	t->run_max = s_max_d;
	if (s_max_d < (u64)FLOW_SLICE_FLOOR_NS) {
		t->run_known = 1;
		__sync_fetch_and_add(&m_ewma_sat, 1ULL);
		return;
	}
	if (kept < (u64)FLOW_RUN_NEED) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	if (max_s < min_s || max_s - min_s < (u64)FLOW_RUN_SPAN_NS) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	if (s_max_d - s_min_d > (s_min_d >> 1)) {
		t->run_known = 0;
		__sync_fetch_and_add(&m_ewma_freeze, 1ULL);
		return;
	}
	t->run_known = 1;
	__sync_fetch_and_add(&m_ewma_sat, 1ULL);
}

static __noinline void flow_run_prune(struct flow_task_ctx *t, u64 now)
{
	u64 win;
	int i;

	if (!t || !now)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);

		if (s && s > now)
			return;
	}
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);
		u64 d = READ_ONCE(t->run_dur[i]);

		if (!s || !d)
			continue;
		if (now - s > win) {
			t->run_dur[i] = 0;
			t->run_stamp[i] = 0;
			t->run_pruned++;
		}
	}
	flow_run_recalc(t);
}

static __noinline void flow_run_close(struct flow_task_ctx *t, u64 now)
{
	u64 tot;
	u64 win;
	u32 head;
	u32 idx;
	u32 prev_idx;
	u64 prev_d;
	u64 prev_s;
	int i;

	if (!t || !now)
		return;
	tot = READ_ONCE(t->run_total);
	if (!tot)
		return;
	win = (u64)FLOW_RUN_WIN_NS;
	if (tot > win)
		tot = win;
	for (i = 0; i < 8; i++) {
		u64 s = READ_ONCE(t->run_stamp[i]);

		if (s && s > now)
			return;
	}
	head = READ_ONCE(t->run_head);
	idx = head & 7U;
	prev_idx = (head - 1U) & 7U;
	prev_d = READ_ONCE(t->run_dur[prev_idx]);
	prev_s = READ_ONCE(t->run_stamp[prev_idx]);

	if (prev_s && now > prev_s &&
	    (now - prev_s) <= (u64)FLOW_CADENCE_MAX_NS &&
	    tot <= ((u64)FLOW_SLICE_MIN_NS * 2ULL))
		__sync_fetch_and_or(&t->flags, (u32)FLOW_FLAG_INTERACTIVE);
	else if (tot >= (u64)FLOW_SLICE_MAX_NS)
		__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_INTERACTIVE);

	t->run_dur[idx] = flow_ewma_next(prev_d, tot);
	t->run_stamp[idx] = now;
	t->run_head = head + 1U;
	t->run_total = 0;
	flow_run_recalc(t);
}

#endif
