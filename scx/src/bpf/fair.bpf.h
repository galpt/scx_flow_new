// SPDX-License-Identifier: GPL-2.0
/*
 * Scoring for the flow scheduler.
 *
 * Log scale keeps multi millisecond frame tasks near short wakeups.
 * Avg folds samples with one eighth gain. Freq folds rate samples
 * the same way. Lat scores wake rate plus wait rate plus runtime
 * with sync plus irq plus pinned lifts. Greedy scales cost from one
 * to two for tasks past the mean service. Due time lands ahead of
 * the clock inside a small window for urgent tasks. Slice tracks a
 * ten millisecond target with boost for long frame runs when the
 * host is not loaded. All math stays integer only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_FAIR_BPF_H
#define __FLOW_FAIR_BPF_H

#include "intf.h"
#include "maps.bpf.h"

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

static __always_inline u32 flow_task_weight(const struct task_struct *p,
					    struct flow_task_ctx *t)
{
	u32 w = flow_eff_w(flow_nice_weight(p), flow_share_live(p));

	(void)t;
	if (!p)
		return w;
	if (p->flags & (PF_KTHREAD | PF_WQ_WORKER | PF_IO_WORKER)) {
		w += (w >> 1);
		if (w > (u32)FLOW_CGROUP_WEIGHT_MAX)
			w = (u32)FLOW_CGROUP_WEIGHT_MAX;
	}
	return w;
}

/* Floor binary log. Zero maps to zero with no branch on high bits. */
static __always_inline u32 flow_log2_u64(u64 v)
{
	u32 r = 0;

	if (v >= (1ULL << 32)) {
		v >>= 32;
		r += 32;
	}
	if (v >= (1ULL << 16)) {
		v >>= 16;
		r += 16;
	}
	if (v >= (1ULL << 8)) {
		v >>= 8;
		r += 8;
	}
	if (v >= (1ULL << 4)) {
		v >>= 4;
		r += 4;
	}
	if (v >= (1ULL << 2)) {
		v >>= 2;
		r += 2;
	}
	if (v >= (1ULL << 1))
		r += 1;
	return r;
}

/* Fold with one eighth gain. First sample seeds. Zero sample keeps. */
static __always_inline u64 flow_calc_avg(u64 old, u64 now)
{
	if (!now)
		return old;
	if (!old)
		return now;
	return old - (old >> 3) + (now >> 3);
}

/* Fold a rate sample. Interval zero keeps the old rate. */
static __always_inline u64 flow_calc_avg_freq(u64 old_freq, u64 interval_ns)
{
	u64 inst;

	if (!interval_ns)
		return old_freq;
	inst = 1000000000ULL / interval_ns;
	if (!old_freq)
		return inst;
	return old_freq - (old_freq >> 3) + (inst >> 3);
}

/* Urgency score from wake plus wait rates plus runtime. Log scale
 * keeps frame tasks near short helpers. Sync plus irq plus pinned
 * lifts mark direct wake chains and bound drivers. Floor at one. */
static __always_inline u32 flow_calc_lat_cri(struct task_struct *p,
					      struct flow_task_ctx *t)
{
	u64 wait_f;
	u64 wake_f;
	u64 avg;
	u32 w;
	u64 comm;
	u64 rt;
	u32 a;
	u32 b;
	u32 s;

	if (!t)
		return 1U;
	wait_f = READ_ONCE(t->wait_freq);
	wake_f = READ_ONCE(t->wake_freq);
	avg = READ_ONCE(t->avg_runtime_ns);
	w = flow_task_weight(p, t);
	comm = (wait_f + 1ULL) * (wake_f + 1ULL);
	if (comm < wait_f + 1ULL)
		comm = ~0ULL;
	if (comm > (1ULL << 32))
		comm = (1ULL << 32);
	rt = ((avg >> 10) + 1ULL) * (u64)w;
	if (rt < ((avg >> 10) + 1ULL))
		rt = ~0ULL;
	if (rt > (1ULL << 32))
		rt = (1ULL << 32);
	a = flow_log2_u64(comm);
	b = flow_log2_u64(rt);
	s = a + b;
	if (s > 64U)
		s = 64U;
	s = s * s;
	if (!s)
		s = 1U;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_IS_SYNC_WAKEUP)
		s += 2U;
	if (READ_ONCE(t->flags) & (u32)(FLOW_FLAG_WOKEN_BY_HARDIRQ | FLOW_FLAG_WOKEN_BY_SOFTIRQ))
		s += 2U;
	if (READ_ONCE(t->pinned_cpu) >= 0)
		s += 1U;
	if (s > 8192U)
		s = 8192U;
	return s;
}

/* Cost scale from system lag. At or below the mean costs one. Past
 * the mean scales toward two at the lag cap. Range is 1024 to 2048. */
static __always_inline u64 flow_calc_greedy_penalty(struct task_struct *p,
						    struct flow_task_ctx *t)
{
	u64 avg;
	u64 svc;
	u64 over;
	u64 cap;

	(void)p;
	if (!t)
		return 1024ULL;
	avg = READ_ONCE(sys_stat.avg_svc_time_iwgt);
	svc = READ_ONCE(t->svc_time_iwgt);
	if (svc <= avg)
		return 1024ULL;
	over = svc - avg;
	cap = (u64)FLOW_TASK_LAG_MAX * 100ULL / (u64)FLOW_CGROUP_WEIGHT_DFLT;
	if (!cap)
		cap = 1ULL;
	if (over >= cap)
		return 2048ULL;
	return 1024ULL + (over * 1024ULL) / cap;
}

/* Due time for queue order. Anchor sits behind the clock by a small
 * window scaled by load. Cost is bounded runtime times greedy over
 * score. Urgent tasks land inside the window and run at once. */
static __always_inline u64 flow_calc_when_to_run(struct task_struct *p,
						 struct flow_task_ctx *t)
{
	u64 clc;
	u64 queued;
	u64 win;
	u64 acc;
	u64 adj;
	u64 pen;
	u32 lc;
	u64 step;

	if (!t)
		return READ_ONCE(sys_stat.cur_logical_clk);
	clc = READ_ONCE(sys_stat.cur_logical_clk);
	queued = READ_ONCE(sys_stat.nr_queued);
	win = (u64)FLOW_DL_COMPETE_WINDOW;
	if (queued > 1ULL) {
		u64 ncpu = scx_bpf_nr_cpu_ids();

		if (!ncpu)
			ncpu = 1ULL;
		if (queued > ncpu)
			win = win * ncpu / queued;
	}
	acc = READ_ONCE(t->acc_runtime_ns);
	if (acc > (u64)FLOW_SLICE_MAX_NS)
		acc = (u64)FLOW_SLICE_MAX_NS;
	adj = (u64)FLOW_SLICE_MAX_NS + acc;
	pen = flow_calc_greedy_penalty(p, t);
	lc = flow_calc_lat_cri(p, t);
	if (!lc)
		lc = 1U;
	step = (adj * pen) / ((u64)lc * 1024ULL);
	if (clc > win)
		return clc - win + step;
	return step;
}

/* Base slice from a ten millisecond window over online CPUs. Boost
 * covers one full frame run when the host is not loaded. Bounds are
 * five hundred microseconds to five milliseconds, boost to twenty. */
static __always_inline u64 flow_calc_slice(struct flow_task_ctx *t,
					    struct flow_running_state *rs)
{
	u64 ncpu;
	u64 queued;
	u64 base;
	u64 avg;

	ncpu = scx_bpf_nr_cpu_ids();
	if (!ncpu)
		ncpu = 1ULL;
	queued = READ_ONCE(sys_stat.nr_queued);
	if (!queued)
		queued = 1ULL;
	base = (u64)FLOW_TARGETED_LATENCY_NS * ncpu / queued;
	if (base < (u64)FLOW_SLICE_MIN_NS)
		base = (u64)FLOW_SLICE_MIN_NS;
	if (base > (u64)FLOW_SLICE_MAX_NS)
		base = (u64)FLOW_SLICE_MAX_NS;
	if (!t)
		return base;
	avg = READ_ONCE(t->avg_runtime_ns);
	if (avg >= READ_ONCE(sys_stat.slice_ns) && queued <= ncpu) {
		u64 pinned = 0;

		if (rs)
			pinned = READ_ONCE(rs->nr_pinned);
		if (!pinned) {
			u64 boost = avg + (u64)FLOW_SLICE_MIN_NS;

			if (boost < (u64)FLOW_SLICE_MIN_NS)
				boost = (u64)FLOW_SLICE_MIN_NS;
			if (boost > (u64)FLOW_SLICE_BOOST_MAX)
				boost = (u64)FLOW_SLICE_BOOST_MAX;
			return boost;
		}
	}
	return base;
}

#endif
