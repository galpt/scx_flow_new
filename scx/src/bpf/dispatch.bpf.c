// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves every parked task in global deadline order up to sixteen per
 * pass with no sequence gate and no CPU gate. Each move picks the
 * least key then deadline then owned then pid among entries the
 * dispatch CPU may run, so admits sort before top key rejects while
 * rejects still drain ordered last. The head keeps smallest pid best
 * effort while the full scan orders owned then pid. Affinity plus
 * liveness gate every move through the same mask as the fallback path
 * with live proven once at entry, so the target class never widens.
 * Ordered checks run first so every parked task stays preferred, while
 * the fallback drain moves solely the remainder when the tree reads
 * empty plus corrupt plus persistent stale up to the batch bound. Deep
 * backlog still drains sixteen ordered per pass with the earliest
 * moves kept in order. One head read plus task state picks the least
 * with fallback to the tail scan, so hits skip the walk while only the
 * picked pid takes a reference.
 * Drops run at teardown, so the hot path keeps no deletes and the
 * core drops shares through stopping plus disable plus exit. Empty
 * queue leaves at once with no scan so idle stays cheap. Stall drains
 * solely through the same empty plus corrupt plus stale fallback with
 * mask checks and no order gate so runnable tasks never stall on live
 * work. Fail open stays as the empty plus corrupt plus stale canary
 * since task state plus tree land synchronously and solely genuine
 * misses reach it. Over moves count progress with ordered moves
 * counting vEB hits plus fallback moves counting FIFO parks so every
 * dispatched task lands in one bucket. Level follows after ordered
 * moves plus fallback with the same CPU only and no call on steady
 * through one exit, so idle cannot be skipped.
 *
 * The pass splits across dispatch/probes, failopen, drain, ordered,
 * head, perf files with one RCU section per scan. Ordered plus drain
 * plus pick plus consume plus head stay noinline with scalar inputs
 * and bounded loops, so the verifier stays small with no unrolled
 * caller tree, while the single task moves plus the fallback account
 * stay inline so the deepest path keeps its call frames small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/perf.bpf.c"
#include "dispatch/probes.bpf.c"
#include "dispatch/failopen.bpf.c"
#include "dispatch/drain.bpf.c"
#include "dispatch/ordered.bpf.c"
/* Single fallback account with over plus park in one place. */
/* Keeps the three drain sites paired, so every extra move lands in */
/* both buckets with no missed count. */
static __always_inline void flow_fifo_account(u32 extra)
{
	if (!extra)
		return;
	__sync_fetch_and_add(&flow_stats.over_moves,
	    (u64)extra);
	__sync_fetch_and_add(&flow_stats.fifo_parks,
	    (u64)extra);
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	u32 extra = 0;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		goto out;
	if (veb_min() == (u32)FLOW_VEB_EMPTY) {
		extra = veb_fail_open_drain(cpu,
		    (u32)FLOW_DISPATCH_MAX_BATCH);
		flow_fifo_account(extra);
		/* Single exit covers the level, so idle cannot be skipped. */
		goto out;
	}
	moved = flow_ordered_fill(cpu);
	if (moved) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
		__sync_fetch_and_add(&flow_stats.veb_hits,
		    (u64)moved);
		if (moved < (u32)FLOW_DISPATCH_MAX_BATCH &&
		    scx_bpf_dsq_nr_queued(flow_overflow_dsq()) != 0) {
			u32 left = (u32)FLOW_DISPATCH_MAX_BATCH - moved;
			extra = veb_fail_open_drain(cpu, left);
			flow_fifo_account(extra);
		}
		/* Single exit covers the level, so idle cannot be skipped. */
		goto out;
	}
	extra = veb_fail_open_drain(cpu,
	    (u32)FLOW_DISPATCH_MAX_BATCH);
	flow_fifo_account(extra);
out:
	/* Level follows after ordered moves plus fail open */
	/* with the same CPU only through one exit. */
	flow_perf_update(cpu);
}
