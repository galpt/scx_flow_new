// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * Maps hold task deadlines, CPU pid plus cursor rows, the
 * topology view, and the hierarchy share plus pool rows. Init
 * creates one deadline queue per CPU plus one overflow tail, and
 * it fails loudly when an id reaches the local range. Ops split
 * across select_cpu, enqueue, dispatch, lifecycle, and hierarchy
 * files. Hotplug needs a restart, and the watchdog stays at
 * 30 seconds.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Per task deadline for the life of the task. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
/* Per CPU pid with steal cursor. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
/* Per CPU topology view with sibling plus domain. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_topo);
} topo_stor SEC(".maps");
/* Per hierarchy share plus pool by id with miss default. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_CGRP_MAX);
	__type(key, u64);
	__type(value, struct flow_cgrp_ctx);
} cgrp_stor SEC(".maps");
/* Single kicking timer for throttled work with lazy refill. */
struct flow_bw_timer {
	struct bpf_timer timer;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct flow_bw_timer);
} bw_timer SEC(".maps");
/* Ring of lately parked chains for the timer refill scan. */
/* Each slot holds 8 ancestor ids with the leaf first and zero pad. */
/* Parks record the walked chain with a wrapping counter, and the */
/* timer refills each listed pool with cap. Stale or reused ids refill */
/* harmlessly, so no cleanup runs. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_PARK_HINT_NR);
	__type(key, u32);
	__type(value, struct flow_park_chain);
} park_hint SEC(".maps");
volatile u64 nr_cpu_ids;
volatile struct flow_sched_stats flow_stats;
volatile u64 flow_cgrp_gen = 1;
volatile u64 flow_bw_limited = 0;
volatile u64 flow_bw_pending = 0;
/* Wrapping counter for the parked hint ring. */
volatile u64 flow_hint_idx = 0;
/* Monotonic clock in nanos for deadlines and starvation. */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}
/* Task state without create for fast read paths. */
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}
/* Task state with create for enqueue and enable paths. */
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
/* CPU state or null when the id is past the bound. */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}
/* Topology view or null when the id is past the bound. */
static struct flow_topo *flow_topo(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&topo_stor, &key);
}
/* Hierarchy entry or null on miss with default share. */
static struct flow_cgrp_ctx *flow_cgrp(u64 cgid)
{
	return bpf_map_lookup_elem(&cgrp_stor, &cgid);
}
/* Acquired hierarchy of one task with paired release. */
/* Uses the scheduler view with a reference, so the caller releases */
/* with release when non null. A null return means the root with */
/* miss defaults and no hierarchy use. */
static __always_inline struct cgroup *flow_task_cgrp(
	struct task_struct *p)
{
	return scx_bpf_task_cgroup(p);
}
/* Release one acquired hierarchy with null tolerance. */
/* A null pointer needs no release, so miss paths stay cheap. */
static __always_inline void flow_cgrp_put(
	struct cgroup *cgrp)
{
	if (cgrp)
		bpf_cgroup_release(cgrp);
}
/* Atomic load of the hierarchy generation to match the bumps. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_gen(void)
{
	return __sync_fetch_and_add(&flow_cgrp_gen, 0);
}
/* Atomic load of the limited count to match the fixups. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_limited(void)
{
	return __sync_fetch_and_add(&flow_bw_limited, 0);
}
/* Atomic load of the pending flag to match the enqueue store. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_pending(void)
{
	return __sync_fetch_and_add(&flow_bw_pending, 0);
}
/* Record one parked chain of 8 ancestor ids with the leaf first. */
/* Uses a wrapping counter with one map update, so concurrent parks */
/* never tear and an overwrite only drops an older chain with the */
/* enqueue refill covering active groups. Outlined to keep the */
/* throttle and timer paths small. */
static __noinline void flow_hint_chain(u64 ids[8])
{
	u64 idx;
	u32 key;
	struct flow_park_chain chain;
	int i;
	bpf_for(i, 0, 8) {
		if ((u64)i >= (u64)FLOW_CGRP_DEPTH_MAX)
			break;
		chain.ids[i] = ids[i];
	}
	idx = __sync_fetch_and_add(&flow_hint_idx, 1);
	key = (u32)(idx % (u64)FLOW_PARK_HINT_NR);
	bpf_map_update_elem(&park_hint, &key, &chain, BPF_ANY);
}
/* Atomic load of one hierarchy flags to match the flag stores. */
/* Pairs with the set and clear stores with no torn read. */
static __always_inline u32 flow_load_flags(
	struct flow_cgrp_ctx *e)
{
	return __sync_fetch_and_add(&e->flags, 0);
}
/* Set the throttle bit on one hierarchy entry with one try. */
/* Uses one compare and swap, so concurrent sets never tear. A lost */
/* try leaves the bit to the winner with no stall. */
static __always_inline void flow_flag_set(
	struct flow_cgrp_ctx *e)
{
	u32 cur = flow_load_flags(e);
	u32 want;
	if (cur & (u32)FLOW_CGRP_THROTTLED)
		return;
	want = cur | (u32)FLOW_CGRP_THROTTLED;
	__sync_val_compare_and_swap(&e->flags, cur, want);
}
/* Clear the throttle bit on one hierarchy entry with one try. */
/* Uses one compare and swap, so concurrent clears never tear. */
static __always_inline void flow_flag_clear(
	struct flow_cgrp_ctx *e)
{
	u32 cur = flow_load_flags(e);
	u32 want;
	if (!(cur & (u32)FLOW_CGRP_THROTTLED))
		return;
	want = cur & ~(u32)FLOW_CGRP_THROTTLED;
	__sync_val_compare_and_swap(&e->flags, cur, want);
}
/* Id of one hierarchy with root at one on missing. */
/* Runs on an acquired or ops trusted pointer with a held view, */
/* so the node read stays valid. A missing pointer means the root, */
/* so the id stays one. */
static __always_inline u64 flow_cgrp_id(
	struct cgroup *cgrp)
{
	struct kernfs_node *kn;
	u64 id;
	if (!cgrp)
		return 1;
	kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return 1;
	id = BPF_CORE_READ(kn, id);
	if (!id)
		return 1;
	return id;
}
/* Level of one hierarchy with root at zero on missing. */
/* Runs on an acquired or ops trusted pointer with a held view. */
/* The level never changes after creation, so the read stays valid. */
static __always_inline int flow_cgrp_level(
	struct cgroup *cgrp)
{
	if (!cgrp)
		return 0;
	return BPF_CORE_READ(cgrp, level);
}
/* Ancestor at one level with a reference and paired release. */
/* Uses the tryget lookup, so the caller releases when non null. */
/* A bad level fails closed to null with no trap. */
static __always_inline struct cgroup *flow_cgrp_ancestor(
	struct cgroup *cgrp, int level)
{
	if (!cgrp)
		return NULL;
	return bpf_cgroup_ancestor(cgrp, level);
}
/* Hierarchy share over depth 8 with miss default 100. */
/* Compounds each ancestor weight by base 100, so a light */
/* parent lowers the share. Misses use base with no trap. */
/* Depth 8 covers the nearest 8 levels from the leaf, so a deeper */
/* tree truncates the far root levels with the leaf order kept. */
/* Each ancestor carries a reference with a paired release. */
/* Outlined to keep enqueue small. */
static __noinline u32 flow_hier_weight(
	struct cgroup *cgrp)
{
	u64 hier = (u64)FLOW_CGRP_WEIGHT_DFL;
	int level;
	int i;
	if (!cgrp)
		return (u32)FLOW_CGRP_WEIGHT_DFL;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
		u32 w;
		int lvl;
		if (i > level)
			break;
		lvl = level - i;
		if (lvl < 0)
			break;
		anc = flow_cgrp_ancestor(cgrp, lvl);
		if (!anc)
			continue;
		id = flow_cgrp_id(anc);
		flow_cgrp_put(anc);
		if (!id)
			continue;
		e = flow_cgrp(id);
		if (!e)
			w = (u32)FLOW_CGRP_WEIGHT_DFL;
		else
			w = flow_weight_clamp(
			    __sync_fetch_and_add(&e->weight,
			    0));
		hier = hier * (u64)w / (u64)FLOW_WEIGHT_BASE;
		if (hier > (u64)FLOW_WEIGHT_MAX)
			hier = (u64)FLOW_WEIGHT_MAX;
		if (hier < (u64)FLOW_WEIGHT_MIN)
			hier = (u64)FLOW_WEIGHT_MIN;
		if (i == 0 && lvl == 0)
			break;
	}
	return (u32)hier;
}
/* Atomic load of one pool rest to match the compare and swap stores. */
/* Pairs with the refill and consume loops with no torn read. */
static __always_inline u64 flow_load_pool(
	struct flow_cgrp_ctx *e)
{
	return __sync_fetch_and_add(&e->pool_ns, 0);
}
/* Atomic load of one refill stamp to match the compare and swap stores. */
/* Pairs with the refill claim with no torn read. */
static __always_inline u64 flow_load_updated(
	struct flow_cgrp_ctx *e)
{
	return __sync_fetch_and_add(&e->updated_at, 0);
}
/* Lazy refill of one pool with burst cap and floor use. */
/* Unlimited pools stay zero with no time use. Elapsed time */
/* refills by quota over period with saturating math, capped at */
/* quota plus burst. Huge inputs clamp instead of wrapping, so the */
/* pool never collapses to a small cap. The stamp advances only when */
/* the refill adds, so tiny elapsed keeps its fraction for the next */
/* pass. The stamp claims with a compare and swap, so concurrent */
/* refills add once. The pool adds with one compare and swap try, so */
/* concurrent refills never tear. A lost try drops the add with the */
/* stamp advanced, so the next elapsed refills with no stall. */
static __noinline void flow_bw_refill(
	struct flow_cgrp_ctx *e, u64 now)
{
	u64 updated;
	u64 elapsed;
	u64 prod;
	u64 add;
	u64 max;
	u64 old;
	u64 cur;
	u64 sum;
	u64 want;
	if (!e)
		return;
	if (flow_bw_unlimited(
	    __sync_fetch_and_add(&e->quota_us, 0)))
		return;
	updated = flow_load_updated(e);
	if (flow_time_before(now, updated))
		return;
	elapsed = now - updated;
	if (!elapsed)
		return;
	if (!__sync_fetch_and_add(&e->period_us, 0))
		return;
	if (elapsed > 4294967295ULL ||
	    __sync_fetch_and_add(&e->quota_us, 0) > 4294967295ULL)
		prod = (u64)~0ULL;
	else
		prod = elapsed *
		    __sync_fetch_and_add(&e->quota_us, 0);
	add = prod / __sync_fetch_and_add(&e->period_us, 0);
	if (!add)
		return;
	old = __sync_val_compare_and_swap(&e->updated_at,
	    updated, now);
	if (old != updated)
		return;
	max = flow_bw_max_ns(
	    __sync_fetch_and_add(&e->quota_us, 0),
	    __sync_fetch_and_add(&e->burst_us, 0));
	if (!max)
		return;
	cur = flow_load_pool(e);
	if (cur >= max)
		return;
	sum = cur + add;
	if (sum < cur)
		sum = (u64)~0ULL;
	want = sum;
	if (want > max)
		want = max;
	__sync_val_compare_and_swap(&e->pool_ns, cur, want);
}
/* True when one hierarchy is throttled with lazy refill. */
/* Walks the nearest 8 ancestors with refill, and the tightest pool */
/* binds, so any drained pool parks the task. Unlimited walks */
/* pass at once with no pool use. A null hierarchy passes at once. */
/* Pool reads use atomic loads to match the refill stores. The walked */
/* chain records to the hint ring on park with the leaf first, and */
/* the leaf flag sets on park else clears on pass, so the dispatch */
/* check stays a single lookup with no walk. */
/* Each ancestor carries a reference with a paired release. */
static __noinline bool flow_bw_throttled(
	struct cgroup *cgrp, u64 now)
{
	int level;
	int i;
	u64 chain[8] = {};
	struct flow_cgrp_ctx *leaf = NULL;
	if (!cgrp)
		return false;
	if (!flow_load_limited())
		return false;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
		int lvl;
		if (i > level)
			break;
		lvl = level - i;
		if (lvl < 0)
			break;
		anc = flow_cgrp_ancestor(cgrp, lvl);
		if (!anc)
			continue;
		id = flow_cgrp_id(anc);
		flow_cgrp_put(anc);
		if (!id)
			continue;
		chain[i] = id;
		e = flow_cgrp(id);
		if (!e)
			continue;
		if (i == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    __sync_fetch_and_add(&e->quota_us, 0)))
			continue;
		flow_bw_refill(e, now);
		if (flow_load_pool(e) == 0) {
			if (leaf)
				flow_flag_set(leaf);
			flow_hint_chain(chain);
			return true;
		}
		if (i == 0 && lvl == 0)
			break;
	}
	if (leaf)
		flow_flag_clear(leaf);
	return false;
}
/* Limited pools drain saturating to zero with no wrap, and */
/* unlimited pools pass with no charge. Pool updates use one compare */
/* and swap try, so concurrent charges never tear. A lost try drops */
/* the charge with the next charge covering, so no stall. When any */
/* ancestor sits drained, the leaf flag sets, so the dispatch check */
/* holds later parks with no walk. A null hierarchy passes. */
/* Each ancestor carries a reference with a paired release. */
static __noinline void flow_bw_consume(
	struct cgroup *cgrp, u64 delta)
{
	int level;
	int i;
	struct flow_cgrp_ctx *leaf = NULL;
	bool drained = false;
	if (!cgrp)
		return;
	if (!delta)
		return;
	if (!flow_load_limited())
		return;
	level = flow_cgrp_level(cgrp);
	bpf_for(i, 0, FLOW_CGRP_DEPTH_MAX) {
		struct cgroup *anc;
		u64 id;
		struct flow_cgrp_ctx *e;
		int lvl;
		u64 cur;
		u64 want;
		if (i > level)
			break;
		lvl = level - i;
		if (lvl < 0)
			break;
		anc = flow_cgrp_ancestor(cgrp, lvl);
		if (!anc)
			continue;
		id = flow_cgrp_id(anc);
		flow_cgrp_put(anc);
		if (!id)
			continue;
		e = flow_cgrp(id);
		if (!e)
			continue;
		if (i == 0)
			leaf = e;
		if (flow_bw_unlimited(
		    __sync_fetch_and_add(&e->quota_us, 0)))
			continue;
		cur = flow_load_pool(e);
		if (cur == 0) {
			drained = true;
			if (i == 0 && lvl == 0)
				break;
			continue;
		}
		if (cur > delta)
			want = cur - delta;
		else
			want = 0;
		__sync_val_compare_and_swap(&e->pool_ns, cur,
		    want);
		if (want == 0)
			drained = true;
		if (i == 0 && lvl == 0)
			break;
	}
	if (drained && leaf)
		flow_flag_set(leaf);
}
/* True when the id is a live CPU below nr and the bound. */
/* Live means below the nr snapshot at init with no kernel online read. */
/* Hotplug needs a restart with fail closed to overflow. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
/* True when the CPU is live and inside the task mask. */
/* Live is the init snapshot with no hotplug read, so an offlined CPU */
/* past init still reads live here and needs a restart to drain. */
/* Unknown CPUs fail closed to overflow with mask wins on drain. */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* Drop the on CPU gauge by one with no wrap and no clear. */
/* Retries the compare and swap so concurrent stops pair, and a lost */
/* race leaves the gauge to the winner with no silent zero. */
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 4) {
		u64 cur = flow_stats.on_cpu;
		u64 nxt;
		u64 old;
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
	}
}
/* Clear the running pid with a compare and swap loop. */
/* Retries the swap so a concurrent run pairs, and a lost race keeps */
/* the winner with no torn zero. Release carries no pid, so the loop */
/* claims whatever owner it finds. The segment still ends through */
/* stopping or disable with no charge here. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	s32 i;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	bpf_for(i, 0, 4) {
		u32 cur = __sync_fetch_and_add(
		    &st->running_pid, 0);
		u32 old;
		if (cur == 0)
			break;
		old = __sync_val_compare_and_swap(
		    &st->running_pid, cur, 0);
		if (old == cur)
			break;
	}
}
/* Clear the running pid only when the pid owns it. */
/* Uses one compare and swap, so a stale exit never clears a new */
/* owner after a switch. A zero pid never owns, so it passes. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (pid == 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	__sync_val_compare_and_swap(&st->running_pid, pid, 0);
}
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
	start = __sync_fetch_and_add(&tctx->run_at, 0);
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
		cur = __sync_fetch_and_add(&st->running_pid, 0);
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
		    __sync_fetch_and_add(&e->quota_us, 0)))
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
	kicks = __sync_fetch_and_add(&flow_stats.kicks, 0);
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
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"
#include "cgroup.bpf.c"
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	u64 n;
	s32 cpu;
	u32 tkey = 0;
	struct flow_bw_timer *tm;
	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		struct flow_cpu_state *st;
		struct flow_topo *tp;
		u32 key;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (st) {
			st->running_pid = 0;
			st->cursor = (u32)cpu;
		}
		tp = bpf_map_lookup_elem(&topo_stor, &key);
		if (tp) {
			tp->smt_sib = 0xffffffffU;
			tp->llc = 0;
		}
	}
	/* One deadline queue per CPU plus one overflow tail. */
	/* Deadline holds 0x6800 plus id and overflow holds 0x7000. */
	/* Count holds one per CPU plus one with one bounded pass at init. */
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		u64 vtime;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		vtime = flow_vtime_dsq((u32)cpu);
		if (vtime >= (u64)SCX_DSQ_LOCAL_ON) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(vtime, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
	}
	if (flow_overflow_dsq() >= (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(flow_overflow_dsq(), -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	/* Single timer wakes throttled parks with no pool scan. */
	tm = bpf_map_lookup_elem(&bw_timer, &tkey);
	if (!tm) {
		scx_bpf_error("timer lookup failed");
		return -EINVAL;
	}
	bpf_timer_init(&tm->timer, &bw_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(&tm->timer, flow_bw_timer_cb);
	ret = bpf_timer_start(&tm->timer, (u64)FLOW_BW_TIMER_NS, 0);
	if (ret < 0) {
		scx_bpf_error("timer start failed");
		return ret;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .enable			= (void *)flow_enable,
	       .disable			= (void *)flow_disable,
	       .exit_task		= (void *)flow_exit_task,
	       .cpu_release		= (void *)flow_cpu_release,
	       .cgroup_init		= (void *)flow_cgroup_init,
	       .cgroup_exit		= (void *)flow_cgroup_exit,
	       .cgroup_prep_move	= (void *)flow_cgroup_prep_move,
	       .cgroup_move		= (void *)flow_cgroup_move,
	       .cgroup_cancel_move	= (void *)flow_cgroup_cancel_move,
	       .cgroup_set_weight	= (void *)flow_cgroup_set_weight,
	       .cgroup_set_bandwidth	= (void *)flow_cgroup_set_bandwidth,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
