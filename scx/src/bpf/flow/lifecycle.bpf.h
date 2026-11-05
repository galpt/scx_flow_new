// SPDX-License-Identifier: GPL-2.0
/*
 * Flow task lifecycle plus init with cgroup shares.
 *
 * Moved from main with additive weight hooks only. Single ownership
 * through the queued flag is unchanged. Freq hint is neutral for
 * placement. Hotplug needs restart, same risk as the pinned path.
 * Unknown weights read as default with prior behavior. Blocked tail
 * counts stops that leave the task still runnable on the cached LLC
 * with no fresh lookup and no vtime penalty, so blocking never shifts
 * the deadline. Runnable covers preemptions plus slice expiry plus
 * migrations, any stop where the task waits elsewhere. An invalid
 * cached LLC falls back to zero with no loss. Enqueue time ages waits
 * with no vtime shift and a zero clock clears to unknown. Streak counts
 * full burns capped at twice the pop retry bound with clean decay and
 * ends in a preempt when the bound is reached. Stop records a yield bit
 * into the three bit task history with fresh zero neutral as a hog.
 * Running seeds the latency flag from the history with pinned always
 * zero and counts an age rescue when an old wait steps the hold down.
 * Freq hist keeps the last four
 * raw samples for sizing with no reader in BPF. Mask change on a queued
 * task keeps the queue with no rewrite and wakes the owner through the
 * pinned fast path for pinned waits else the constrained path with the
 * boosted key for latency tasks.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_LIFECYCLE_BPF_H
#define __FLOW_LIFECYCLE_BPF_H

#include "../intf.h"
#include "maps.bpf.h"
#include "stats.bpf.h"
#include "guards.bpf.h"
#include "vtime.bpf.h"
#include "cgroup.bpf.h"
#include "freq.bpf.h"
#include "preempt.bpf.h"

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u64 want = 0;
	s32 cpu;
	u32 llc;
	TOUCH_ARENA();
	n = scx_bpf_nr_cpu_ids();
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	flow_nr_cpus = n;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u32 key;
		struct flow_cpu_ctx *cc;
		u32 id;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		key = (u32)cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			continue;
		id = READ_ONCE(cc->llc_id);
		if (!flow_llc_ok(id))
			continue;
		if ((u64)id + 1 > want)
			want = (u64)id + 1;
	}
	if (want == 0)
		want = 1;
	if (want > (u64)FLOW_MAX_LLCS) {
		scx_bpf_error("LLC count over bound");
		return -E2BIG;
	}
	flow_nr_llcs = want;
	if (n + want + 1 > 4096ULL) {
		scx_bpf_error("queue count over bound");
		return -E2BIG;
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u64 dsq;
		s32 ret;
		if ((u64)llc >= want)
			break;
		dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq)) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(dsq, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	{
		s32 ret = scx_bpf_create_dsq((u64)FLOW_FALLBACK_DSQ, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("fallback dsq create failed");
			return ret;
		}
	}
	if (want <= 1)
		return 0;
	/* Size the static area before the first pair queue use. */
	/* The pair queue draws from this area so it must be ready first. */
	/* Eight pages hold 32KiB. One pair with cap n times 4 needs the */
	/* queue header plus two heaps plus cap times 16 bytes of entries. */
	/* A 16 CPU host needs about one KiB per pair and fits with margin. */
	/* Overflow takes a fresh block and leaves old pages mapped, so an */
	/* oversize host still fails closed with no reuse. Single LLC above */
	/* uses only DSQs and creates no pair, so skipping init there is by */
	/* design. Enqueue and dispatch guard every pair use on more than one */
	/* LLC, so a future static user must move this init above that return. */
	{
		int ret = scx_static_init(8);
		if (ret) {
			scx_bpf_error("static init failed");
			return ret;
		}
	}
	bpf_for(llc, 0, FLOW_MAX_LLCS) {
		u32 node = 0;
		u32 cnt;
		u64 strand;
		u64 idx;
		u64 cap;
		bool first = false;
		u32 c;
		u64 got = (u64)-1;
		if ((u64)llc >= want)
			break;
		first = false;
		bpf_for(c, 0, FLOW_MAX_CPUS) {
			struct flow_cpu_ctx *cc;
			u32 key = c;
			if ((u64)c >= n)
				break;
			cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
			if (!cc)
				continue;
			if (READ_ONCE(cc->llc_id) == llc) {
				node = READ_ONCE(cc->node_id);
				first = true;
				break;
			}
		}
		if (!first)
			node = 0;
		if (!flow_node_ok(node)) {
			scx_bpf_error("node over bound");
			return -EINVAL;
		}
		cnt = flow_node_count[node];
		strand = (u64)(cnt % 2);
		if (strand == (u64)SCX_DHQ_STRAND_A) {
			idx = flow_pair_count;
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			cap = n * 4;
			if (cap < 8)
				cap = 8;
			got = scx_dhq_create_balanced(false, cap,
						      SCX_DHQ_MODE_PRIORITY,
						      (u64)FLOW_DHQ_MAX_IMBALANCE);
			if (!got) {
				scx_bpf_error("pair create failed");
				return -ENOMEM;
			}
			flow_pair_dhqs[idx] = (scx_dhq_t *)got;
			if (idx < (u64)FLOW_MAX_PAIRS)
				flow_pair_cap[(u32)idx] = cap;
			flow_pair_count += 1;
			flow_node_last_pair[node] = idx;
		} else {
			idx = flow_node_last_pair[node];
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			if (!flow_pair_dhqs[idx]) {
				scx_bpf_error("pair null for strand B");
				return -EINVAL;
			}
		}
		flow_llc_pair[llc] = idx;
		flow_llc_strand[llc] = strand;
		flow_node_count[node] = cnt + 1;
		if (idx < (u64)FLOW_MAX_PAIRS)
			flow_pair_node[(u32)idx] = node;
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *t;
	s64 v;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	v = (s64)p->scx.dsq_vtime;
	t->vtime = v;
	t->deadline = flow_vtime_add_slice(v);
	t->slice_rem = (u64)FLOW_SLICE_NS;
	t->gen = 0;
	t->strand = (u32)FLOW_STRAND_A;
	t->llc_id = 0;
	t->flags = 0;
	t->hist3 = 0;
	t->pad[0] = 0;
	t->pad[1] = 0;
	t->pad[2] = 0;
	t->enq_ns = 0;
	/* History starts empty. Zero reads as a hog, so a new task proves */
	/* latency with early yields first. Cgroup tail stays. Init plus */
	/* move seed it, zero init reads as default, and membership never */
	/* changes on enable. Enqueue time starts empty with no wait. */
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_cpu_ctx *cc;
	u32 llc = 0;
	u32 strand = (u32)FLOW_STRAND_A;
	u32 key;
	struct flow_running_state *rs;
	u64 sl;
	u64 ng;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	key = cpu;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (cc) {
		u32 tmp = READ_ONCE(cc->llc_id);
		if (flow_llc_ok(tmp))
			llc = tmp;
		if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
			u64 idx = flow_llc_pair[llc];
			if (idx < (u64)FLOW_MAX_PAIRS && flow_pair_dhqs[(u32)idx]) {
				u32 s = (u32)flow_llc_strand[llc];
				if (s == (u32)FLOW_STRAND_A || s == (u32)FLOW_STRAND_B)
					strand = s;
			}
		}
	} else {
		if (flow_llc_ok(t->llc_id))
			llc = t->llc_id;
		if (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B)
			strand = t->strand;
	}
	sl = p->scx.slice;
	/* Clamp holds the extended award bound at three quanta with no */
	/* drop to one, so an awarded slice keeps its length here while a */
	/* bad read still falls back to one. Stopping plus tick share the */
	/* same three quantum clamp. */
	if (!sl)
		sl = (u64)FLOW_SLICE_NS;
	else if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	rs = &flow_running_state[cpu];
	ng = rs->gen + 1;
	if (ng == 0)
		ng = 1;
	rs->vtime = t->vtime;
	rs->deadline = t->deadline;
	rs->slice_rem = sl;
	rs->llc_id = llc;
	rs->strand = strand;
	rs->gen = ng;
	/* Streak switch. A pinned start clears the hold since the wait */
	/* reached the CPU. A start with an old enqueue ages out one step */
	/* so a single good wait steps the hold down with no new knob. A */
	/* recent requeue keeps the hold so consecutive full burns still */
	/* reach the bound. A legacy tall hold clamps to twice the pop */
	/* retry bound with no new knob so a prior count never sticks past */
	/* the storm window. Clean stops decay elsewhere, so this path only */
	/* ages old waits. The latency flag follows the history with pinned */
	/* always zero so the kick can boost both sides with no extra */
	/* lookup. An old wait that steps the hold down counts an age */
	/* rescue on the running LLC. Reserved stays zero past the flag. */
	if (flow_is_pinned(p)) {
		rs->hog_streak = 0;
		rs->lat = 0;
	} else {
		u32 cap = (u32)FLOW_POP_RETRY_MAX * 2U;
		u64 enq = READ_ONCE(t->enq_ns);
		u64 now = bpf_ktime_get_ns();
		rs->lat = flow_hist_is_lat(t->hist3) ? 1 : 0;
		if (rs->hog_streak > cap)
			rs->hog_streak = cap;
		if (enq && now > enq) {
			u64 age = now - enq;
			if (age > (u64)FLOW_SLICE_NS * 4ULL) {
				if (rs->hog_streak > 0) {
					rs->hog_streak -= 1;
					flow_stat_inc(llc, 23);
				}
			}
		}
	}
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	t->strand = strand;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
	/* Act at start. Send the smoothed hint for this one CPU only. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	flow_freq_apply(task_cpu);
}

void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_task_ctx *t;
	struct flow_running_state *rs;
	u64 sl;
	bool voluntary;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	/* Single snapshot for the stop. True when the task reads not */
	/* runnable with remain above zero at this stop else false. One */
	/* read serves the score path below with no second read for the */
	/* same stop. Pinned plus exiting bypass score effects below. */
	voluntary = !runnable && sl > 0;
	t->slice_rem = sl;
	/* Yield record. A stop with remain yields early and records one, */
	/* a full burn records zero, so two of three ones later read as */
	/* latency while fresh zero stays a hog. Placement plus vtime plus */
	/* slice handling stay unchanged. */
	t->hist3 = flow_hist_push(t->hist3, sl == 0 ? 0 : 1);
	rs = &flow_running_state[cpu];
	rs->slice_rem = sl;
	/* Streak step on the stop edge only, one add per run epoch. No */
	/* remain means the full award burnt, so step the hold by the */
	/* award q capped at twice the pop retry bound with no new knob */
	/* and no wrap. A clean stop steps the hold down one so */
	/* consecutive full burns still reach the bound but a clean run */
	/* never sticks past the storm window. The tick keeps remain only */
	/* with no step so one burn never counts twice. Placement plus */
	/* vtime plus slice handling stay unchanged. */
	if (sl == 0) {
		u32 s = rs->hog_streak;
		u32 cap = (u32)FLOW_POP_RETRY_MAX * 2U;
		u64 step = 1;

		if (t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
			step = (u64)t->pad[0];
		if (s < cap) {
			u64 next = (u64)s + step;

			if (next > (u64)cap)
				next = (u64)cap;
			rs->hog_streak = (u32)next;
		}
	} else {
		if (rs->hog_streak > 0)
			rs->hog_streak -= 1;
	}
	/* Blocked count. A stop that leaves the task still runnable waits */
	/* elsewhere, which covers preemptions plus slice expiry plus */
	/* migrations, so count it on the cached LLC with no fresh lookup */
	/* and no vtime penalty. The cached LLC was seeded from the CPU */
	/* view at running time, invalid falls back to zero with no loss. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	if (runnable) {
		u32 bllc = READ_ONCE(t->llc_id);

		if (!flow_llc_ok(bllc))
			bllc = 0;
		flow_stat_inc(bllc, 16);
	}
	/* Sense load at stop. Burnt nanos over wall feed the smoothed level. */
	/* Placement plus vtime plus slice handling stay unchanged. */
	if ((u64)FLOW_SLICE_NS >= sl)
		flow_freq_sample(cpu, (u64)FLOW_SLICE_NS - sl);
	else
		flow_freq_sample(cpu, 0);
	/* Extra score with hysteresis and bypass. Pinned plus exiting keep */
	/* prior behavior and never take a score from this path. Voluntary */
	/* feeds zero with no growth step on that stop. Empty wait feeds */
	/* zero with no age credit. Full burn with raw top takes growth, */
	/* all else takes decay. Both use integer floor with wide cap four */
	/* hundred and blend three old plus one new over four for a window */
	/* about four and time about three and a half. Counts stay separate */
	/* with no new bound beyond the streak cap. CPU only with no cross */
	/* average. Fresh reads zero with q one until the first count, */
	/* amended from the prior middle default since no burn has been */
	/* seen yet. Growth needs a full awarded burn with raw top against */
	/* the q scaled denom, so a partial burn still takes decay with no */
	/* new knob: only a full extended burn earns growth. Award length */
	/* comes from the task pad in one through three else one, with */
	/* voluntary plus empty wait keeping precedence through decay. */
	/* Latency history feeds the queue key offset only and never feeds */
	/* the score here, so a latency task still needs a full burn for */
	/* growth with no inversion. Merged means the raw burn hint shares */
	/* the same blend with no second path, not a history feed. */
	{
		bool is_pinned = flow_is_pinned(p);
		bool is_exiting = (p->flags & PF_EXITING) != 0;
		struct flow_extra_state *es;
		u64 old;
		u64 now_s;
		u64 enq;
		u64 q_src = 1;
		if (!is_pinned && !is_exiting) {
			es = &flow_extra_state[cpu];
			/* Award length source. The task pad carries the last */
			/* award q in one through three else one, so the burn */
			/* below accounts against the slice just run. */
			if (t->pad[0] >= 1 && t->pad[0] <= (u8)FLOW_MAX_QUANTA)
				q_src = (u64)t->pad[0];
			if (es->n_growth == 0 && es->n_decay == 0) {
				old = 0;
			} else {
				old = es->score;
				if (old > (u64)FLOW_SCORE_HMAX)
					old = (u64)FLOW_SCORE_HMAX;
			}
			enq = READ_ONCE(t->enq_ns);
			if (voluntary) {
				now_s = flow_score_decay(old);
				if (es->n_decay < 0xffffffffffffffffULL)
					es->n_decay += 1;
			} else if (!enq) {
				now_s = flow_score_decay(old);
				if (es->n_decay < 0xffffffffffffffffULL)
					es->n_decay += 1;
			} else {
				u64 used;
				u64 raw;
				u64 denom = q_src * (u64)FLOW_SLICE_NS;
				/* Denom scales with the award. The q bound keeps */
				/* the product small, the guard below saturates on */
				/* overflow with no wrap. A remain past the award */
				/* keeps used zero with no underflow. */
				if (denom / (u64)FLOW_SLICE_NS != q_src)
					denom = (u64)0xffffffffffffffffULL;
				if (denom >= sl)
					used = denom - sl;
				else
					used = 0;
				/* Raw burn steps wire the raw max lock with no */
				/* knob: zero through four with only the top */
				/* step at full taking growth. Used stays at or */
				/* below denom at or below three slices so used */
				/* times four stays near twelve million with no */
				/* overflow and no wrap. */
				raw = 0;
				if (denom)
					raw = used * (u64)FLOW_SCORE_RAW_MAX / denom;
				if (raw > (u64)FLOW_SCORE_RAW_MAX)
					raw = (u64)FLOW_SCORE_RAW_MAX;
				if (raw == (u64)FLOW_SCORE_RAW_MAX) {
					now_s = flow_score_growth(old);
					if (es->n_growth < 0xffffffffffffffffULL)
						es->n_growth += 1;
				} else {
					now_s = flow_score_decay(old);
					if (es->n_decay < 0xffffffffffffffffULL)
						es->n_decay += 1;
				}
			}
			if (now_s > (u64)FLOW_SCORE_HMAX)
				now_s = (u64)FLOW_SCORE_HMAX;
			es->score = now_s;
		}
	}
}

void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	struct flow_running_state *rs;
	u64 sl;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		return;
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		return;
	sl = p->scx.slice;
	if (sl > (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA)
		sl = (u64)FLOW_SLICE_NS * (u64)FLOW_MAX_QUANTA;
	rs->slice_rem = sl;
	/* Tick keeps remain with no streak step. The stop edge above owns */
	/* the one add per run epoch, so a burn that ticks at zero remain */
	/* then stops never counts twice. A mid slice tick with remain */
	/* keeps the hold since only a clean stop decays. Placement plus */
	/* slice handling stay unchanged with no freq move. */
}

void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t;
	(void)deq_flags;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	__sync_fetch_and_and(&t->flags, (u32)~(u32)FLOW_FLAG_QUEUED);
}

/* No SMT probe runs. Each CPU stands single and a missing sibling */
/* fails closed with no move. Select stays through the shared picker. */
/* The hint plus the pick stay inside the task mask plus the live range */
/* with no off mask result. A stale hint falls back to the first allowed */
/* live CPU before the shared pick, and a stale pick falls back the same */
/* way after. The cached first target serves both fallbacks with one walk. */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	s32 eff_prev;
	s32 picked;
	s32 first;

	if (!p || !p->cpus_ptr)
		return prev_cpu;
	first = flow_first_allowed(p);
	eff_prev = prev_cpu;
	if (eff_prev < 0 || !flow_cpu_live((u32)eff_prev) || !flow_cpu_allowed(eff_prev, p)) {
		if (first >= 0)
			eff_prev = first;
		else
			return prev_cpu;
	}
	picked = scx_bpf_select_cpu_dfl(p, eff_prev, wake_flags, &idle);
	if (picked < 0 || !flow_cpu_live((u32)picked) || !flow_cpu_allowed(picked, p)) {
		if (first >= 0)
			return first;
		return eff_prev;
	}
	return picked;
}

/* Reclamp the cached queue affinity on mask change. Preserves virtual */
/* time plus deadline plus generation plus queued state with no fresh */
/* assign. Exiting tasks keep the minimal slice. A queued task keeps the */
/* charged affinity with no rewrite so later accounting stays on the */
/* enqueue LLC, and the new owner takes a pinned fast path wake for */
/* pinned waits else a constrained wake with an orphan count only on a */
/* live allowed kick and no move. The enqueue plus dispatch repair stays */
/* as fallback when the hook never fires. */
void BPF_STRUCT_OPS(flow_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct flow_task_ctx *t;
	s32 tgt;
	u32 cpu;
	struct flow_cpu_ctx *cc;
	u32 llc;

	(void)cpumask;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	if (READ_ONCE(t->flags) & (u32)FLOW_FLAG_QUEUED) {
		s32 owner = flow_first_allowed(p);
		u32 qllc = READ_ONCE(t->llc_id);
		s64 hv;
		bool pinned = flow_is_pinned(p);
		int olat = 0;

		if (!flow_llc_ok(qllc))
			qllc = 0;
		hv = READ_ONCE(t->vtime);
		/* Latency wakes compare on the boosted key on both sides, */
		/* so shift the raw stored time here while the kick boosts */
		/* the running side from its flag. Pinned keeps the raw key */
		/* with the fast path. The stored time stays raw with no */
		/* accumulation. One pinned test serves the key plus the */
		/* kick below with no second walk. A preempt won by a */
		/* latency task counts the latency preempt tail on the */
		/* queued LLC with the class already in hand. */
		if (!pinned)
			olat = flow_hist_is_lat(READ_ONCE(t->hist3)) ? 1 : 0;
		if (olat)
			hv = flow_vtime_boost(hv, 1);
		/* Queued keep. No LLC rewrite so accounting stays on the */
		/* enqueue LLC. Pinned uses the fast path that preempts past */
		/* the tail with no gap check since the wait cannot run */
		/* elsewhere, shared uses the constrained gap test. Orphan */
		/* counts only when a live allowed owner takes a kick so a */
		/* skip never inflates the orphan count. A race that loses */
		/* the owner between the check and the kick stays a stats */
		/* glitch with no move no loss. */
		if (owner < 0 || !flow_cpu_allowed(owner, p) ||
		    !flow_cpu_live((u32)owner)) {
			flow_kick_constrained(owner, hv, p, qllc);
			return;
		}
		if (pinned)
			flow_kick_pinned(owner, hv, p, qllc);
		else if (flow_kick_constrained(owner, hv, p, qllc) && olat)
			flow_stat_inc(qllc, 22);
		flow_stat_inc(qllc, 18);
		return;
	}
	if (p->flags & PF_EXITING)
		t->slice_rem = (u64)FLOW_EXIT_SLICE_NS;
	tgt = flow_first_allowed(p);
	if (tgt < 0)
		return;
	if (!flow_cpu_live((u32)tgt))
		return;
	cpu = (u32)tgt;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &cpu);
	if (!cc)
		return;
	llc = READ_ONCE(cc->llc_id);
	if (!flow_llc_ok(llc))
		return;
	t->llc_id = llc;
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS && flow_pair_dhqs[(u32)idx]) {
			u32 s = (u32)flow_llc_strand[llc];
			if (s == (u32)FLOW_STRAND_A || s == (u32)FLOW_STRAND_B)
				t->strand = s;
		}
	}
}

/* Seed one cgroup weight from the init args. Fires for every cgroup */
/* including root at load. Every path returns zero so a bad arg plus */
/* a missing id plus a full map never aborts cgroup creation or load. */
/* A miss reads as default with prior behavior. Map holds 4096 entries */
/* with no eviction, so a full map also reads as default. Seeding order */
/* with init_task is documented at init_task, and the live enqueue */
/* lookup heals a reversed start with no sticky default. */
s32 BPF_STRUCT_OPS(flow_cgroup_init, struct cgroup *cgrp,
		   struct scx_cgroup_init_args *args)
{
	u64 cgid;
	u64 w;
	if (!cgrp || !args)
		return 0;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return 0;
	w = (u64)flow_cgroup_clamp(args->weight);
	(void)bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
	return 0;
}

/* Drop the weight entry so a reused id never reads stale shares. */
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	u64 cgid;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	bpf_map_delete_elem(&cgrp_weight_stor, &cgid);
}

/* Track cpu.weight changes. Update creates, so a weight set before */
/* init still lands. Clamp keeps the knob in range. */
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	u64 cgid;
	u64 w;
	if (!cgrp)
		return;
	cgid = flow_cgroup_cgid(cgrp);
	if (!cgid)
		return;
	w = (u64)flow_cgroup_clamp(weight);
	bpf_map_update_elem(&cgrp_weight_stor, &cgid, &w, BPF_ANY);
}

/* Cache the destination weight on the moving task. Null dest keeps */
/* defaults with no move. Storage is created on miss so a task without */
/* context still caches the move, which stays sleepable safe. Enqueue */
/* reads the live map by id, so the cache is a hint only. */
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct flow_task_ctx *t;
	u64 cgid;
	(void)from;
	if (!p)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	if (!to) {
		t->cgrp_id = 0;
		t->cg_weight = (u32)FLOW_CGROUP_WEIGHT_DFLT;
		return;
	}
	cgid = flow_cgroup_cgid(to);
	t->cgrp_id = cgid;
	t->cg_weight = flow_cgroup_lookup(cgid);
}

/* Seed the task weight cache at task init. Args carry the birth */
/* cgroup the same way as flash/forge. Null cgroup keeps defaults. */
/* Cgroup init runs for every cgroup including root at load, but order */
/* against init_task before 6.12 is unverified. A task born before its */
/* cgroup weight lands reads default, and the live enqueue lookup heals */
/* on next enqueue with no sticky default. Needs 6.12 plus for the */
/* cgroup hooks, checked by the installer. Enqueue never reads this */
/* cache alone, so set_weight needs no move. */
s32 BPF_STRUCT_OPS(flow_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;
	u64 cgid = 0;
	if (!p)
		return 0;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return -ENOMEM;
	if (args && args->cgroup)
		cgid = flow_cgroup_cgid(args->cgroup);
	t->cgrp_id = cgid;
	t->cg_weight = flow_cgroup_lookup(cgid);
	return 0;
}

/* Lifecycle hotplug needs restart with tables seeded once, */
/* reinstall needs restart with no live transition, creation never aborts */
/* on shares. Docs only, no logic change. */

#endif
