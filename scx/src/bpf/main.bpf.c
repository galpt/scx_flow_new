// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * One entry file with ordered includes and an owned pair queue.
 * Tasks enter the pair queue by vtime, else fall back to the LLC DSQ.
 * Dispatch drains pair, then LLC, then fallback. Single LLC bypasses
 * pairing and uses the LLC DSQ directly. Stats are per LLC.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/minheap.h>
#include <lib/sdt_alloc.h>
#include <lib/spinlock.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/*
 * Owned pair queue section. Two strands share one lock.
 * Names use flow_dhq and flow_strand with no outside text kept.
 */
struct flow_dhq {
	scx_minheap_t *strand_a;
	scx_minheap_t *strand_b;
	arena_spinlock_t lock;
	u64 capacity;
	u64 size_a;
	u64 size_b;
	u64 max_imbalance;
};
typedef struct flow_dhq __arena flow_dhq_t;
__weak u64 flow_dhq_create(u64 capacity, u64 max_imbalance)
{
	flow_dhq_t *dhq;
	u64 half;
	dhq = scx_static_alloc(sizeof(*dhq), 1);
	if (!dhq)
		return (u64)NULL;
	half = capacity / 2;
	dhq->strand_a = scx_minheap_alloc(half);
	if (!dhq->strand_a)
		return (u64)NULL;
	dhq->strand_b = scx_minheap_alloc(half);
	if (!dhq->strand_b)
		return (u64)NULL;
	dhq->capacity = capacity;
	dhq->max_imbalance = max_imbalance;
	return (u64)dhq;
}
static inline int flow_dhq_insert_inner(flow_dhq_t *dhq, u64 elem, u64 strand, u64 key)
{
	scx_minheap_t *heap;
	u64 mine;
	u64 other;
	int ret;
	if (!dhq)
		return -EINVAL;
	heap = (strand == (u64)FLOW_STRAND_A) ? dhq->strand_a : dhq->strand_b;
	if (!heap)
		return -EINVAL;
	scx_spin_lock(&dhq->lock);
	if (dhq->size_a + dhq->size_b >= dhq->capacity) {
		ret = -ENOSPC;
		goto out;
	}
	if (dhq->max_imbalance > 0) {
		if (strand == (u64)FLOW_STRAND_A) {
			mine = dhq->size_a;
			other = dhq->size_b;
		} else {
			mine = dhq->size_b;
			other = dhq->size_a;
		}
		if (mine >= other + dhq->max_imbalance) {
			ret = -EAGAIN;
			goto out;
		}
	}
	ret = scx_minheap_insert(heap, elem, key);
	if (ret)
		goto out;
	if (strand == (u64)FLOW_STRAND_A)
		dhq->size_a += 1;
	else
		dhq->size_b += 1;
	scx_spin_unlock(&dhq->lock);
	return 0;
out:
	scx_spin_unlock(&dhq->lock);
	return ret;
}
__hidden __noinline int flow_strand_insert_vtime(flow_dhq_t *dhq, u64 elem, u64 vtime, u64 strand)
{
	if (!dhq)
		return -EINVAL;
	if (strand != (u64)FLOW_STRAND_A && strand != (u64)FLOW_STRAND_B)
		return -EINVAL;
	return flow_dhq_insert_inner(dhq, elem, strand, vtime);
}
static inline u64 flow_dhq_pop_strand_locked(flow_dhq_t *dhq, u64 strand)
{
	scx_minheap_t *heap;
	struct scx_minheap_elem helem;
	int ret;
	heap = (strand == (u64)FLOW_STRAND_A) ? dhq->strand_a : dhq->strand_b;
	if (!heap)
		return (u64)NULL;
	if ((strand == (u64)FLOW_STRAND_A && dhq->size_a == 0) ||
	    (strand == (u64)FLOW_STRAND_B && dhq->size_b == 0))
		return (u64)NULL;
	ret = scx_minheap_pop(heap, &helem);
	if (ret)
		return (u64)NULL;
	if (strand == (u64)FLOW_STRAND_A)
		dhq->size_a -= 1;
	else
		dhq->size_b -= 1;
	return helem.elem;
}
__hidden __noinline u64 flow_dhq_pop(flow_dhq_t *dhq)
{
	u64 out = (u64)NULL;
	u64 wa;
	u64 wb;
	if (!dhq)
		return (u64)NULL;
	scx_spin_lock(&dhq->lock);
	if (dhq->size_a + dhq->size_b == 0)
		goto unlock;
	if (dhq->size_a > 0 && dhq->strand_a)
		wa = dhq->strand_a->helems[0].weight;
	else
		wa = (u64)-1;
	if (dhq->size_b > 0 && dhq->strand_b)
		wb = dhq->strand_b->helems[0].weight;
	else
		wb = (u64)-1;
	if (wa <= wb)
		out = flow_dhq_pop_strand_locked(dhq, (u64)FLOW_STRAND_A);
	else
		out = flow_dhq_pop_strand_locked(dhq, (u64)FLOW_STRAND_B);
	if (!out) {
		if (wa <= wb)
			out = flow_dhq_pop_strand_locked(dhq, (u64)FLOW_STRAND_B);
		else
			out = flow_dhq_pop_strand_locked(dhq, (u64)FLOW_STRAND_A);
	}
unlock:
	scx_spin_unlock(&dhq->lock);
	return out;
}
/* Maps plus pair tables. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_ctx);
} cpu_ctx_stor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_LLCS);
	__type(key, u32);
	__type(value, struct flow_llc_stats);
} llc_stats_stor SEC(".maps");
volatile u64 flow_nr_cpus;
volatile u64 flow_nr_llcs;
flow_dhq_t *flow_pair_dhqs[FLOW_MAX_PAIRS];
u64 flow_llc_pair[FLOW_MAX_LLCS];
u64 flow_llc_strand[FLOW_MAX_LLCS];
u32 flow_node_count[FLOW_MAX_NODES];
u64 flow_node_last_pair[FLOW_MAX_NODES];
u32 flow_pair_count;
static __always_inline struct flow_llc_stats *flow_stats_for(u32 llc)
{
	return bpf_map_lookup_elem(&llc_stats_stor, &llc);
}
static __always_inline void flow_stat_add(u32 llc, u64 off, s64 delta)
{
	struct flow_llc_stats *st = flow_stats_for(llc);
	u64 *cell;
	if (!st)
		return;
	if (off == 0)
		cell = &st->queued;
	else if (off == 1)
		cell = &st->dispatched;
	else if (off == 2)
		cell = &st->fallback;
	else
		cell = &st->steal;
	if (delta >= 0)
		__sync_fetch_and_add(cell, (u64)delta);
	else
		__sync_fetch_and_sub(cell, (u64)(-(delta)));
}
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	u64 n;
	u64 want = 0;
	s32 cpu;
	u32 llc;
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
		if (strand == (u64)FLOW_STRAND_A) {
			idx = flow_pair_count;
			if (idx >= (u64)FLOW_MAX_PAIRS) {
				scx_bpf_error("pair over bound");
				return -EINVAL;
			}
			cap = n * 4;
			if (cap < 8)
				cap = 8;
			got = flow_dhq_create(cap,
					      (u64)FLOW_DHQ_MAX_IMBALANCE);
			if (!got) {
				scx_bpf_error("pair create failed");
				return -ENOMEM;
			}
			flow_pair_dhqs[idx] = (flow_dhq_t *)got;
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
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return;
	t->vtime = p->scx.dsq_vtime;
	t->strand = (u32)FLOW_STRAND_A;
	t->llc_id = 0;
	t->flags = 0;
	t->pad = 0;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	u32 llc = 0;
	u32 strand = (u32)FLOW_STRAND_A;
	u64 vtime = p->scx.dsq_vtime;
	struct flow_task_ctx *t;
	flow_dhq_t *dhq = NULL;
	int ret;
	(void)enq_flags;
	if (task_cpu < 0)
		task_cpu = bpf_get_smp_processor_id();
	cpu = (u32)task_cpu;
	if (flow_cpu_ok(cpu)) {
		struct flow_cpu_ctx *cc;
		u32 key = cpu;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (cc && flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
	}
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (t) {
		t->vtime = vtime;
		t->llc_id = llc;
	}
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)FLOW_STRAND_A &&
			    strand != (u32)FLOW_STRAND_B)
				strand = (u32)FLOW_STRAND_A;
			if (t)
				t->strand = strand;
		}
	}
	if (dhq) {
		ret = flow_strand_insert_vtime(dhq, (u64)p->pid, vtime,
					       (u64)strand);
		if (ret == 0) {
			flow_stat_add(llc, 0, 1);
			scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
			return;
		}
		flow_stat_add(llc, 2, 1);
	}
	{
		u64 dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, vtime, 0);
		flow_stat_add(llc, 0, 1);
	}
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 strand = (u32)FLOW_STRAND_A;
	u64 dsq;
	flow_dhq_t *dhq = NULL;
	(void)prev;
	if (cpu < 0)
		return;
	c = (u32)cpu;
	if (!flow_cpu_ok(c))
		return;
	{
		u32 key = c;
		struct flow_cpu_ctx *cc;
		cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
		if (!cc)
			return;
		if (!flow_llc_ok(READ_ONCE(cc->llc_id)))
			return;
		llc = READ_ONCE(cc->llc_id);
	}
	dsq = flow_llc_dsq(llc);
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[idx];
			strand = (u32)flow_llc_strand[llc];
		}
	}
	if (dhq) {
		u64 pid = flow_dhq_pop(dhq);
		if (pid) {
			struct task_struct *p;
			p = bpf_task_from_pid((s32)pid);
			if (!p) {
				flow_stat_add(llc, 2, 1);
				flow_stat_add(llc, 0, -1);
				goto try_llc;
			}
			{
				struct flow_task_ctx *t;
				u32 tst = strand;
				t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
				if (t)
					tst = t->strand;
				scx_bpf_dsq_insert_vtime(p, dsq,
							 (u64)FLOW_SLICE_NS,
							 p->scx.dsq_vtime, 0);
				bpf_task_release(p);
				flow_stat_add(llc, 0, -1);
				if (scx_bpf_dsq_move_to_local(dsq, 0)) {
					flow_stat_add(llc, 1, 1);
					if (tst != strand)
						flow_stat_add(llc, 3, 1);
					return;
				}
				flow_stat_add(llc, 0, 1);
			}
		}
	}
try_llc:
	if (scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_add(llc, 1, 1);
		flow_stat_add(llc, 0, -1);
		return;
	}
	if (scx_bpf_dsq_move_to_local((u64)FLOW_FALLBACK_DSQ, 0)) {
		flow_stat_add(llc, 1, 1);
		flow_stat_add(llc, 0, -1);
		return;
	}
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dispatch		= (void *)flow_dispatch,
	       .enable			= (void *)flow_enable,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
