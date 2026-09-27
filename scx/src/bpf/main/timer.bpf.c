// SPDX-License-Identifier: GPL-2.0
/*
 * Charge and timer helpers for the core.
 *
 * Holds the leftover charge plus the hint refill plus the single
 * kicking timer with hint scan and refill gate. Each helper stays
 * noinline with scalar inputs and no duplicate walk, so the verifier
 * stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Charge one leftover run segment at most once with no scaling. */
/* Stopping owns the normal charge and clears the run start. */
/* Disable and exit funnel here only for a running task that */
/* stopping never saw. The start claims with a compare and swap, so */
/* stopping versus disable or exit charges once. The owner check runs */
/* before the claim, and a failed claim means stopping won, so this */
/* pass drops with no double charge and no stolen segment. */
/* The hierarchy lookup carries a reference with a paired release, */
/* and a null lookup skips the pool charge with no trap. */
/* Outlined to keep disable and exit small. */
static __noinline void flow_charge_leftover(s32 cpu,
	struct task_struct *p, struct flow_task_ctx *tctx, u32 pid)
{
	u64 start;
	u64 now;
	u64 delta;
	u64 got;
	struct cgroup *cgrp;
	if (!tctx)
		return;
	if (pid == 0)
		return;
	start = READ_ONCE(tctx->run_at);
	if (start == 0)
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* A stopped task holds zero with no charge left. */
	/* Only the owning CPU charges, so a migrated stop stays once. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 cur;
		if (!st)
			return;
		cur = READ_ONCE(st->running_pid);
		if (cur != pid)
			return;
	}
	now = flow_now();
	if (flow_time_before(now, start))
		return;
	delta = now - start;
	got = __sync_val_compare_and_swap(&tctx->run_at,
	    start, 0);
	if (got != start)
		return;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_on_cpu_dec();
	cgrp = flow_task_cgrp(p);
	if (cgrp) {
		flow_bw_consume(cgrp, delta);
		flow_cgrp_put(cgrp);
	}
}
/* Refill one hint slot with cap and leaf flag handling. */
/* Each slot holds 8 ancestor ids with the leaf first. Every listed */
/* pool refills alone with cap, and the leaf flag clears only when */
/* the whole chain holds pool, so a drained parent keeps the park */
/* with no bypass. Stale or reused ids refill harmlessly with no */
/* cleanup. Returns 1 when refill added pool else 0. Outlined to */
/* keep the timer callback small. */
static __noinline u32 flow_refill_hint_slot(u32 hkey,
	u64 now)
{
	struct flow_park_chain *chain;
	struct flow_cgrp_ctx *leaf = NULL;
	bool drained = false;
	bool added = false;
	u32 j;
	chain = bpf_map_lookup_elem(&park_hint, &hkey);
	if (!chain)
		return 0;
	bpf_for(j, 0, FLOW_CGRP_DEPTH_MAX) {
		struct flow_cgrp_ctx *e;
		u64 hid;
		u64 before;
		u64 after;
		if ((u64)j >= 8ULL)
			break;
		hid = chain->ids[j];
		if (!hid)
			continue;
		e = flow_cgrp(hid);
		if (!e)
			continue;
		if (j == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    READ_ONCE(e->quota_us)))
			continue;
		before = flow_load_pool(e);
		flow_bw_refill(e, now);
		after = flow_load_pool(e);
		if (after > before)
			added = true;
		if (after == 0)
			drained = true;
	}
	if (leaf && !drained)
		flow_flag_clear(leaf);
	return added ? 1 : 0;
}
/* Single kicking timer for throttled parks with hint refill scan. */
/* Scans from a rotated live start instead of a fixed id, so an offlined */
/* boot CPU never parks the kick and passes spread with no hotspot. */
/* The start rotates by the kick count, so consecutive ticks visit */
/* different CPUs first. When a park waits, the timer refills one */
/* chunk of 8 hint slots per tick rotating over the 64 ring, so time */
/* based refill unparks tasks with no new enqueue and the scan stays */
/* bounded. Hints record drained ids at park time with a wrapping */
/* counter, and stale or reused ids refill harmlessly with cap and no */
/* cleanup. Active groups past the ring still refill on the enqueue */
/* path. The kick is refill gated: it fires only when refill added */
/* pool or no limit remains, so idle ticks and still throttled ticks */
/* stay quiet with no storm. A cleared limited count still kicks once, */
/* so parks from a removed limit drain soon. When still throttled with */
/* no refill yet, pending re-arms for the next tick with no stall. The */
/* kick targets the first live CPU with mask wins on drain, so a parked */
/* mask mismatch stays best effort with no task scan here. The dispatch */
/* recheck uses loads only with no walk refill, and the 10ms tick always */
/* covers the 1ms floor, so a gated kick finds fresh pools. Pending uses */
/* an atomic exchange to match the enqueue store with no torn flag. */
/* The live scan stays bound at 8: the rotated start is always live, so */
/* the first peer hits with no 1024 sweep. */
static int flow_bw_timer_cb(void *map, int *key,
	struct bpf_timer *timer)
{
	u32 found = 0xffffffffU;
	u64 was;
	u64 kicks;
	u64 n;
	u32 start = 0;
	u32 off;
	u64 now;
	bool refilled = false;
	u32 i;
	u32 hint_start = 0;
	(void)map;
	(void)key;
	if (!flow_load_pending())
		goto arm;
	was = __sync_lock_test_and_set(&flow_bw_pending, 0);
	if (!was)
		goto arm;
	/* Refill one chunk of 8 hint slots rotating over the 64 ring. */
	/* Each slot holds 8 ancestor ids with the leaf first. The chunk */
	/* start steps by 8 per 10ms tick, so the full ring covers in 8 */
	/* ticks with a bounded scan. */
	now = flow_now();
	hint_start = (u32)(((now / (u64)FLOW_BW_TIMER_NS) % 8ULL) * 8ULL);
	bpf_for(i, 0, 8) {
		u32 hkey = (hint_start + i) % (u32)FLOW_PARK_HINT_NR;
		if (flow_refill_hint_slot(hkey, now))
			refilled = true;
	}
	/* Refill gated kick only with retry when still throttled. */
	if (!refilled && flow_load_limited()) {
		__sync_lock_test_and_set(&flow_bw_pending, 1);
		goto arm;
	}
	n = nr_cpu_ids;
	if (n == 0 || n > (u64)FLOW_MAX_CPUS)
		goto arm;
	kicks = READ_ONCE(flow_stats.kicks);
	start = (u32)(kicks % n);
	bpf_for(off, 0, FLOW_STEAL_BOUND) {
		u32 peer;
		if ((u64)off >= n)
			break;
		peer = (start + off) % (u32)n;
		if (flow_cpu_live(peer)) {
			found = peer;
			break;
		}
	}
	if (found != 0xffffffffU) {
		scx_bpf_kick_cpu((s32)found, SCX_KICK_IDLE);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	}
arm:
	bpf_timer_start(timer, (u64)FLOW_BW_TIMER_NS, 0);
	return 0;
}
