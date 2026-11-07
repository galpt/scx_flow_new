// SPDX-License-Identifier: GPL-2.0
/*
 * Wait history for the flow scheduler.
 *
 * Buckets split queue waits by length with slice fractions and
 * multiples through chained compares with no loop. Records add
 * one to the per CPU cell for the kind and bucket with bounds
 * checks and no loop. Store keeps a provisional kind from the
 * queue choice with pinned tasks keeping the pinned kind.
 * Finalize keeps the full path kind and stamps the enqueue time
 * with the full clock with zero stored as one so known and
 * unknown stay distinct. Observe counts the enqueue to dispatch
 * wait on the moving CPU and the enqueue to run wait on the
 * running CPU from the same stamp with the full delta with zero
 * staying skipped. Tables are written once so late CPUs need a
 * restart to see the wait table.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_LAT_BPF_H
#define __FLOW_LAT_BPF_H
#include "intf.h"
#include "maps.bpf.h"
static __always_inline u32 flow_lat_bucket(u64 delta)
{
	if (delta < (u64)FLOW_SLICE_MIN_NS / 4ULL)
		return 0;
	if (delta < (u64)FLOW_SLICE_MIN_NS / 2ULL)
		return 1;
	if (delta < (u64)FLOW_SLICE_MIN_NS)
		return 2;
	if (delta < (u64)FLOW_SLICE_MIN_NS * 2ULL)
		return 3;
	if (delta < (u64)FLOW_SLICE_MIN_NS * 3ULL)
		return 4;
	if (delta < (u64)FLOW_SLICE_MIN_NS * 10ULL)
		return 5;
	if (delta < (u64)FLOW_SLICE_MIN_NS * 30ULL)
		return 6;
	return 7;
}
static __always_inline void flow_lat_record(u32 cpu, u32 kind, u32 bucket, u32 is_run)
{
	struct flow_lat_hist *hist;
	u64 half;
	u64 step;
	u64 idx;
	if (!flow_cpu_ok(cpu))
		return;
	if (kind >= (u32)FLOW_LAT_KINDS)
		return;
	if (bucket >= (u32)FLOW_LAT_BUCKETS)
		return;
	if (is_run > 1)
		return;
	hist = bpf_map_lookup_elem(&lat_hist, &cpu);
	if (!hist)
		return;
	/* Build the index in two adds so each bound stays checked. */
	__asm__ volatile("" : "+r"(kind), "+r"(bucket), "+r"(is_run));
	step = (u64)kind * (u64)FLOW_LAT_BUCKETS + (u64)bucket;
	if (step >= (u64)FLOW_LAT_KINDS * (u64)FLOW_LAT_BUCKETS)
		return;
	half = (u64)is_run * (u64)FLOW_LAT_KINDS * (u64)FLOW_LAT_BUCKETS;
	__asm__ volatile("" : "+r"(step), "+r"(half));
	idx = half + step;
	if (idx >= (u64)FLOW_HIST_LEN)
		return;
	__asm__ volatile("" : "+r"(idx));
	__sync_fetch_and_add(&hist->cells[idx], 1ULL);
}
static __always_inline void flow_lat_store(task_ctx *t, u32 prio, int pinned)
{
	if (!t)
		return;
	if (pinned) {
		t->lat_kind = (u32)FLOW_LAT_PINNED;
		return;
	}
	if (prio < (u32)FLOW_LAT_KINDS)
		t->lat_kind = prio;
	else
		t->lat_kind = (u32)FLOW_LAT_UNKNOWN;
}
static __always_inline void flow_lat_finalize(task_ctx *t, u32 kind, u64 now)
{
	if (!t)
		return;
	if (kind >= (u32)FLOW_LAT_KINDS)
		kind = (u32)FLOW_LAT_UNKNOWN;
	t->lat_kind = kind;
	t->enq_ns = now ? now : 1;
}
static __always_inline void flow_lat_observe(u32 cpu, task_ctx *t, u64 now, u32 is_run)
{
	u64 stamp;
	u64 delta;
	u32 kind;
	u32 bucket;
	if (!t)
		return;
	if (!now)
		return;
	stamp = READ_ONCE(t->enq_ns);
	if (!stamp)
		return;
	if (now <= stamp) {
		delta = 0;
	} else {
		delta = now - stamp;
	}
	kind = READ_ONCE(t->lat_kind);
	if (kind >= (u32)FLOW_LAT_KINDS)
		return;
	bucket = flow_lat_bucket(delta);
	flow_lat_record(cpu, kind, bucket, is_run);
}
#endif
