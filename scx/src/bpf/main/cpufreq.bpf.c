// SPDX-License-Identifier: GPL-2.0
/*
 * Cache domain frequency hints for the core.
 *
 * One slot per cache domain tracks running tasks plus the applied
 * level plus the last transition time. Wakeups show up through the
 * pid view with no scan, and the timer applies at most one domain
 * transition per tick past the minimum gap, so bursts coalesce and
 * both edges carry hysteresis. Boost pins full performance while a
 * domain runs anything, rest releases the pin when a domain idles
 * past the gap. All sets run in the timer with no request lock
 * held, so any CPU in the domain stays legal. Levels never follow
 * single tasks, only domain transitions cross to the hardware.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Slot for one domain id with tag plus one encoding. */
/* Zero tag means empty, so domain zero never reads empty. */
static struct flow_llc_perf *flow_llc_slot(u32 llc)
{
	u32 key;
	if ((u64)llc >= (u64)FLOW_LLC_MAX)
		return NULL;
	key = llc;
	return bpf_map_lookup_elem(&llc_stor, &key);
}
/* Note one running task in its domain with tag claim. */
/* A tag mismatch clears the slot first, so a reused slot never */
/* mixes two domains. Runs outside the tree lock with atomics only. */
static __always_inline void flow_llc_note_run(u32 llc)
{
	struct flow_llc_perf *slot = flow_llc_slot(llc);
	u32 tag = llc + 1;
	if (!slot)
		return;
	if (READ_ONCE(slot->tag) != tag) {
		WRITE_ONCE(slot->tag, tag);
		WRITE_ONCE(slot->busy, 0);
		WRITE_ONCE(slot->boosted, 0);
		WRITE_ONCE(slot->last, 0);
	}
	__sync_fetch_and_add(&slot->busy, 1);
}
/* Withdraw one running task from its domain with floor at zero. */
/* A lost race clamps at zero instead of wrapping, so the idle edge */
/* still fires with no stall. Runs outside the tree lock. */
static __always_inline void flow_llc_note_stop(u32 llc)
{
	struct flow_llc_perf *slot = flow_llc_slot(llc);
	u32 tag = llc + 1;
	u32 cur;
	u32 old;
	int i;
	if (!slot)
		return;
	if (READ_ONCE(slot->tag) != tag)
		return;
	bpf_for(i, 0, 4) {
		cur = READ_ONCE(slot->busy);
		if (cur == 0)
			break;
		old = __sync_val_compare_and_swap(&slot->busy,
		    cur, cur - 1);
		if (old == cur)
			break;
	}
}
/* Apply one level to every live CPU in one domain. */
/* Counts one set per CPU applied, so the wire tracks coalesced */
/* transitions with no per task detail. Runs in the timer only. */
static __noinline void flow_llc_apply(u32 llc, u32 level)
{
	u64 n = nr_cpu_ids;
	u32 cpu;
	if (n == 0 || n > (u64)FLOW_MAX_CPUS)
		return;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_topo *tp;
		if ((u64)cpu >= n)
			break;
		tp = flow_topo(cpu);
		if (!tp)
			continue;
		if (tp->llc != llc)
			continue;
		if (!flow_cpu_live(cpu))
			continue;
		scx_bpf_cpuperf_set((s32)cpu, level);
		__sync_fetch_and_add(&flow_stats.cpuperf_sets, 1);
	}
}
/* Tick one domain transition with gap plus hysteresis. */
/* Boosts a busy domain past the gap, rests an idle domain past */
/* the gap, and applies at most one domain per tick, so the first */
/* needy domain wins with the rest waiting one tick. A full slot */
/* scan bounds the pass with no per task work. Runs in the timer */
/* only with no request lock held. */
static __noinline void flow_cpufreq_tick(u64 now)
{
	u64 gap = (u64)FLOW_CPUFREQ_MIN_NS;
	u32 key;
	bool done = false;
	bpf_for(key, 0, FLOW_LLC_MAX) {
		struct flow_llc_perf *slot;
		u32 tag;
		u32 busy;
		u32 boosted;
		u64 last;
		if (done)
			break;
		slot = bpf_map_lookup_elem(&llc_stor, &key);
		if (!slot)
			continue;
		tag = READ_ONCE(slot->tag);
		if (tag == 0)
			continue;
		busy = READ_ONCE(slot->busy);
		boosted = READ_ONCE(slot->boosted);
		last = READ_ONCE(slot->last);
		if (busy != 0 && boosted == 0) {
			if (now < last)
				continue;
			if (now - last < gap)
				continue;
			flow_llc_apply(tag - 1, (u32)SCX_CPUPERF_ONE);
			WRITE_ONCE(slot->boosted, 1);
			WRITE_ONCE(slot->last, now);
			done = true;
		} else if (busy == 0 && boosted != 0) {
			if (now < last)
				continue;
			if (now - last < gap)
				continue;
			flow_llc_apply(tag - 1, 0);
			WRITE_ONCE(slot->boosted, 0);
			WRITE_ONCE(slot->last, now);
			done = true;
		}
	}
}
