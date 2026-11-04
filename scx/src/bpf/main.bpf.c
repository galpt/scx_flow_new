// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * One entry file with ordered includes and an upstream pair queue.
 * Tasks enter the pair queue by vtime, else fall back to the LLC DSQ.
 * Dispatch drains pair, then LLC, then fallback. Single LLC bypasses
 * pairing and uses the LLC DSQ directly. Stats are per LLC.
 * A running snapshot carries vtime plus deadline plus slice for
 * threshold preempt. Victim state is carried on requeue. Stealing
 * walks own pair, same node pairs, remote pairs, LLC queues.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/dhq.h>
#include <lib/minheap.h>
#include <lib/sdt_alloc.h>
#include <lib/spinlock.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
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
scx_dhq_t *flow_pair_dhqs[FLOW_MAX_PAIRS];
u64 flow_llc_pair[FLOW_MAX_LLCS];
u64 flow_llc_strand[FLOW_MAX_LLCS];
u32 flow_node_count[FLOW_MAX_NODES];
u64 flow_node_last_pair[FLOW_MAX_NODES];
u32 flow_pair_count;
/* Per CPU running snapshot. Zero init means empty. */
struct flow_running_state flow_running_state[FLOW_MAX_CPUS];
/* Per pair last vtime for monotonic unique assign. Zero init. */
s64 flow_dhq_seq[FLOW_MAX_PAIRS];
/* Node per pair plus node per LLC for hierarchy walk. Zero init. */
u32 flow_pair_node[FLOW_MAX_PAIRS];
u32 flow_llc_node[FLOW_MAX_LLCS];
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
		if (llc < (u32)FLOW_MAX_LLCS)
			flow_llc_node[llc] = node;
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
	t->deadline = v + (s64)FLOW_SLICE_NS;
	t->slice_rem = (u64)FLOW_SLICE_NS;
	t->gen = 0;
	t->seq = (u64)v;
	t->strand = (u32)FLOW_STRAND_A;
	t->llc_id = 0;
	t->flags = 0;
	t->pad = 0;
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
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!t)
		return;
	key = cpu;
	cc = bpf_map_lookup_elem(&cpu_ctx_stor, &key);
	if (cc) {
		if (flow_llc_ok(READ_ONCE(cc->llc_id)))
			llc = READ_ONCE(cc->llc_id);
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
	if (!sl || sl > (u64)FLOW_SLICE_NS)
		sl = (u64)FLOW_SLICE_NS;
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
	t->gen = ng;
	t->slice_rem = sl;
	t->llc_id = llc;
	t->strand = strand;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool idle = false;
	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);
}
static __always_inline void flow_kick_for_enq(s32 task_cpu, u32 llc, s64 use_v,
					      s64 use_d)
{
	u32 cpu;
	struct flow_running_state *rs;
	s64 dv;
	s64 dd;
	if (task_cpu < 0)
		return;
	cpu = (u32)task_cpu;
	if (!flow_cpu_ok(cpu))
		goto idle;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		goto idle;
	rs = &flow_running_state[cpu];
	if (rs->gen == 0)
		goto idle;
	if (rs->slice_rem <= (u64)FLOW_PREEMPT_TAIL)
		goto idle;
	dv = rs->vtime - use_v;
	dd = rs->deadline - use_d;
	if (dv >= (s64)FLOW_PREEMPT_THRESH || dd >= (s64)FLOW_PREEMPT_THRESH) {
		scx_bpf_kick_cpu(task_cpu, SCX_KICK_PREEMPT);
		flow_stat_add(llc, 3, 1);
		return;
	}
idle:
	scx_bpf_kick_cpu(task_cpu, SCX_KICK_IDLE);
}
void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 task_cpu = scx_bpf_task_cpu(p);
	u32 cpu;
	u32 llc = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	s64 kv;
	s64 use_v;
	s64 use_d;
	u64 use_sl;
	u32 use_strand;
	u32 use_llc;
	int carry = 0;
	u32 pair_u = 0;
	int have_pair = 0;
	struct flow_task_ctx *t;
	scx_dhq_t *dhq = NULL;
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
	kv = (s64)p->scx.dsq_vtime;
	use_v = kv;
	use_d = kv + (s64)FLOW_SLICE_NS;
	use_sl = (u64)FLOW_SLICE_NS;
	use_strand = strand;
	use_llc = llc;
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			if (strand != (u32)SCX_DHQ_STRAND_A &&
			    strand != (u32)SCX_DHQ_STRAND_B)
				strand = (u32)SCX_DHQ_STRAND_A;
			use_strand = strand;
			pair_u = (u32)idx;
			have_pair = 1;
		}
	}
	t = bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (t) {
		if (t->gen != 0 && t->slice_rem != 0 &&
		    (t->strand == (u32)FLOW_STRAND_A || t->strand == (u32)FLOW_STRAND_B) &&
		    flow_llc_ok(t->llc_id) &&
		    t->deadline == t->vtime + (s64)FLOW_SLICE_NS) {
			if (flow_cpu_ok(cpu) && cpu < (u32)FLOW_MAX_CPUS) {
				struct flow_running_state *rs = &flow_running_state[cpu];
				if (rs->gen != 0 && rs->gen == t->gen &&
				    flow_llc_ok(rs->llc_id) &&
				    (rs->strand == (u32)FLOW_STRAND_A ||
				     rs->strand == (u32)FLOW_STRAND_B)) {
					carry = 1;
					use_v = t->vtime;
					use_d = t->deadline;
					use_sl = t->slice_rem;
					use_strand = t->strand;
					use_llc = t->llc_id;
				}
			}
		}
		if (!carry) {
			if (dhq && have_pair && pair_u < (u32)FLOW_MAX_PAIRS) {
				s64 last = flow_dhq_seq[pair_u];
				s64 fresh;
				if ((s64)(kv - last) > 0)
					fresh = kv;
				else
					fresh = last + 1;
				flow_dhq_seq[pair_u] = fresh;
				use_v = fresh;
				use_d = fresh + (s64)FLOW_SLICE_NS;
				use_sl = (u64)FLOW_SLICE_NS;
				use_strand = strand;
				use_llc = llc;
				t->seq = (u64)fresh;
			} else {
				use_v = kv;
				use_d = kv + (s64)FLOW_SLICE_NS;
				use_sl = (u64)FLOW_SLICE_NS;
				use_strand = strand;
				use_llc = llc;
				t->seq = (u64)kv;
			}
			t->vtime = use_v;
			t->deadline = use_d;
			t->slice_rem = use_sl;
			t->strand = use_strand;
			t->llc_id = use_llc;
			t->gen = 0;
		}
	}
	if (dhq) {
		ret = scx_dhq_insert_vtime(dhq, (u64)p->pid, (u64)use_v,
					   (u64)use_strand);
		if (ret == 0) {
			flow_stat_add(llc, 0, 1);
			flow_kick_for_enq(task_cpu, llc, use_v, use_d);
			return;
		}
		flow_stat_add(llc, 2, 1);
	}
	{
		u64 dsq = flow_llc_dsq(llc);
		if (!flow_dsq_ok(dsq))
			dsq = (u64)FLOW_FALLBACK_DSQ;
		scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, (u64)use_v, 0);
		flow_stat_add(llc, 0, 1);
		flow_kick_for_enq(task_cpu, llc, use_v, use_d);
	}
}
/*
 * Pop one entry from a pair queue into the local LLC queue.
 * Peek is a hint only, pop is truth. Null task is stale.
 * Returns 1 when a task reached the local queue.
 */
static __always_inline int flow_pop_to_local(scx_dhq_t *dhq, u32 llc, u32 strand,
					     int always_steal)
{
	u64 pid;
	struct task_struct *p;
	struct flow_task_ctx *t;
	u32 tst;
	u64 ins_vtime;
	u64 dsq;
	if (!dhq)
		return 0;
	if (!flow_llc_ok(llc))
		return 0;
	if (scx_dhq_nr_queued(dhq) == 0)
		return 0;
	if (!scx_dhq_peek(dhq))
		return 0;
	pid = scx_dhq_pop(dhq);
	if (!pid)
		return 0;
	p = bpf_task_from_pid((s32)pid);
	if (!p) {
		flow_stat_add(llc, 2, 1);
		flow_stat_add(llc, 0, -1);
		return 0;
	}
	tst = strand;
	ins_vtime = (u64)p->scx.dsq_vtime;
	t = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (t) {
		tst = t->strand;
		if (t->deadline == t->vtime + (s64)FLOW_SLICE_NS && t->slice_rem != 0)
			ins_vtime = (u64)t->vtime;
	}
	dsq = flow_llc_dsq(llc);
	scx_bpf_dsq_insert_vtime(p, dsq, (u64)FLOW_SLICE_NS, ins_vtime, 0);
	bpf_task_release(p);
	flow_stat_add(llc, 0, -1);
	if (scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_add(llc, 1, 1);
		if (always_steal || tst != strand)
			flow_stat_add(llc, 3, 1);
		return 1;
	}
	flow_stat_add(llc, 0, 1);
	return 0;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 c;
	u32 llc = 0;
	u32 node = 0;
	u32 strand = (u32)SCX_DHQ_STRAND_A;
	u64 dsq;
	u64 own_idx = (u64)-1;
	scx_dhq_t *dhq = NULL;
	u32 pi;
	u32 li;
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
		node = READ_ONCE(cc->node_id);
		if (!flow_node_ok(node))
			node = 0;
	}
	dsq = flow_llc_dsq(llc);
	if (flow_nr_llcs > 1 && flow_llc_ok(llc)) {
		u64 idx = flow_llc_pair[llc];
		if (idx < (u64)FLOW_MAX_PAIRS) {
			dhq = flow_pair_dhqs[(u32)idx];
			strand = (u32)flow_llc_strand[llc];
			own_idx = idx;
		}
	}
	if (dhq) {
		if (flow_pop_to_local(dhq, llc, strand, 0))
			return;
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] != node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			if (flow_pop_to_local(cand, llc, strand, 1))
				return;
		}
		bpf_for(pi, 0, FLOW_MAX_PAIRS) {
			u64 idx = (u64)pi;
			scx_dhq_t *cand;
			if (idx == own_idx)
				continue;
			if (pi >= flow_pair_count)
				break;
			if (idx >= (u64)FLOW_MAX_PAIRS)
				continue;
			if (flow_pair_node[pi] == node)
				continue;
			cand = flow_pair_dhqs[pi];
			if (!cand)
				continue;
			if (flow_pop_to_local(cand, llc, strand, 1))
				return;
		}
	}
	if (scx_bpf_dsq_move_to_local(dsq, 0)) {
		flow_stat_add(llc, 1, 1);
		flow_stat_add(llc, 0, -1);
		return;
	}
	bpf_for(li, 0, FLOW_MAX_LLCS) {
		u64 odsq;
		if (li == llc)
			continue;
		if ((u64)li >= flow_nr_llcs)
			break;
		if (!flow_llc_ok(li))
			continue;
		odsq = flow_llc_dsq(li);
		if (!flow_dsq_ok(odsq))
			continue;
		if (scx_bpf_dsq_move_to_local(odsq, 0)) {
			flow_stat_add(llc, 1, 1);
			flow_stat_add(llc, 0, -1);
			flow_stat_add(llc, 3, 1);
			return;
		}
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
	       .running			= (void *)flow_running,
	       .enable			= (void *)flow_enable,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
