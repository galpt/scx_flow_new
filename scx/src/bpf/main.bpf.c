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
volatile u64 nr_cpu_ids;
volatile struct flow_sched_stats flow_stats;
volatile u64 flow_cgrp_gen = 1;
volatile u64 flow_bw_limited = 0;
volatile u64 flow_bw_pending = 0;
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
static __always_inline u32 flow_hier_weight(
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
			w = flow_weight_clamp(e->weight);
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
/* Lazy refill of one pool with burst cap and floor use. */
/* Unlimited pools stay zero with no time use. Elapsed time */
/* refills by quota over period with saturating math, capped at */
/* quota plus burst. Huge inputs clamp instead of wrapping, so the */
/* pool never collapses to a small cap. The stamp advances only when */
/* the refill adds, so tiny elapsed keeps its fraction for the next */
/* pass. */
static __always_inline void flow_bw_refill(
	struct flow_cgrp_ctx *e, u64 now)
{
	u64 elapsed;
	u64 prod;
	u64 add;
	u64 max;
	u64 sum;
	if (!e)
		return;
	if (flow_bw_unlimited(e->quota_us))
		return;
	if (flow_time_before(now, e->updated_at))
		return;
	elapsed = now - e->updated_at;
	if (!elapsed)
		return;
	if (!e->period_us)
		return;
	if (elapsed > 4294967295ULL || e->quota_us > 4294967295ULL)
		prod = (u64)~0ULL;
	else
		prod = elapsed * e->quota_us;
	add = prod / e->period_us;
	if (!add)
		return;
	e->updated_at = now;
	max = flow_bw_max_ns(e->quota_us, e->burst_us);
	if (!max)
		return;
	if (e->pool_ns >= max)
		return;
	sum = e->pool_ns + add;
	if (sum < e->pool_ns)
		sum = (u64)~0ULL;
	e->pool_ns = sum;
	if (e->pool_ns > max)
		e->pool_ns = max;
}
/* True when one hierarchy is throttled with lazy refill. */
/* Walks the nearest 8 ancestors with refill, and the tightest pool */
/* binds, so any drained pool parks the task. Unlimited walks */
/* pass at once with no pool use. A null hierarchy passes at once. */
/* Each ancestor carries a reference with a paired release. */
static __always_inline bool flow_bw_throttled(
	struct cgroup *cgrp, u64 now)
{
	int level;
	int i;
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
		e = flow_cgrp(id);
		if (!e)
			continue;
		if (flow_bw_unlimited(e->quota_us))
			continue;
		flow_bw_refill(e, now);
		if (e->pool_ns == 0)
			return true;
		if (i == 0 && lvl == 0)
			break;
	}
	return false;
}
/* Charge one runtime delta to the nearest 8 ancestors with floor. */
/* Limited pools drain saturating to zero with no wrap, and */
/* unlimited pools pass with no charge. A null hierarchy passes. */
/* Each ancestor carries a reference with a paired release. */
static __always_inline void flow_bw_consume(
	struct cgroup *cgrp, u64 delta)
{
	int level;
	int i;
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
		if (flow_bw_unlimited(e->quota_us))
			continue;
		if (e->pool_ns > delta)
			e->pool_ns -= delta;
		else
			e->pool_ns = 0;
		if (i == 0 && lvl == 0)
			break;
	}
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
/* Clear the running pid with no other state change. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_pid = 0;
}
/* Clear the running pid only when the pid owns it. */
/* A stale exit never clears a new owner after a switch. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	if (st->running_pid != pid)
		return;
	st->running_pid = 0;
}
/* Charge one leftover run segment at most once with no scaling. */
/* Stopping owns the normal charge and clears the run start. */
/* Disable and exit funnel here only for a running task that */
/* stopping never saw. The count flag pairs with stopping through */
/* the run start, so a release never double charges. */
/* The hierarchy lookup carries a reference with a paired release, */
/* and a null lookup skips the pool charge with no trap. */
static __always_inline void flow_charge_leftover(s32 cpu,
	struct task_struct *p, struct flow_task_ctx *tctx, u32 pid)
{
	u64 start;
	u64 now;
	u64 delta;
	struct cgroup *cgrp;
	if (!tctx)
		return;
	start = tctx->run_at;
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
		if (!st || st->running_pid != pid)
			return;
	}
	now = flow_now();
	if (flow_time_before(now, start))
		return;
	delta = now - start;
	tctx->run_at = 0;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_on_cpu_dec();
	cgrp = flow_task_cgrp(p);
	if (cgrp) {
		flow_bw_consume(cgrp, delta);
		flow_cgrp_put(cgrp);
	}
}
/* Single kicking timer for throttled parks with lazy refill. */
/* Scans for the first live CPU instead of a fixed id, so an offlined */
/* boot CPU never parks the kick. Kicks only when a park waits, so */
/* idle ticks stay quiet with no storm. A cleared limited count still */
/* kicks once, so parks from a removed limit drain soon. */
/* Refill stays lazy on the enqueue path with no pool scan here, and */
/* the 10ms tick always covers the 1ms floor, so a kick finds refill. */
static int flow_bw_timer_cb(void *map, int *key,
	struct bpf_timer *timer)
{
	u32 cpu;
	u32 found = 0xffffffffU;
	u64 was;
	(void)map;
	(void)key;
	if (!flow_load_pending())
		goto arm;
	was = __sync_lock_test_and_set(&flow_bw_pending, 0);
	if (!was)
		goto arm;
	bpf_for(cpu, 0, FLOW_MAX_CPUS) {
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if (flow_cpu_live(cpu)) {
			found = cpu;
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
