// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves admitted tasks in global deadline order up to sixteen per pass
 * with no sequence gate and no CPU gate. Each move picks the least key
 * then deadline then owned then pid among entries the dispatch CPU may
 * run. Affinity plus liveness gate
 * every move through the same entry check as the FIFO path, so the
 * target class never widens. Ordered checks run first so admitted
 * tasks stay preferred, while the FIFO drain moves the remainder in
 * queue order up to the batch bound. Past one hundred twenty eight
 * queued ordered stops after four moves with FIFO covering the
 * remainder to sixteen, so a deep tail never burns sixteen double
 * scans in one pass. Task state gates admission with no extra index
 * lookup, so only the picked pid takes a reference.
 * Drops run at teardown, so the hot path keeps no deletes and the
 * core drops shares through stopping plus disable plus exit. Empty
 * queue leaves at once with no scan so idle stays cheap. Stall drains
 * up to sixteen FIFO tasks with liveness plus affinity checks and no
 * order gate so runnable tasks never stall on live work. Fail open
 * stays rare in normal load since rows land synchronously and solely
 * genuine affinity misses reach it. Over moves count progress with
 * ordered moves counting vEB hits plus fail open moves counting FIFO
 * parks so every dispatched task lands in one bucket. Level follows
 * after ordered moves plus fail open with the same CPU only and no
 * call on steady through one exit, so idle cannot be skipped.
 *
 * The pass splits across dispatch/probes, failopen, drain, perf files
 * with one RCU section per helper. Each helper stays noinline with
 * scalar inputs and bounded loops, so the verifier stays small,
 * except the single move plus the batch drain wrapper which stay
 * inline so the deepest dispatch path keeps its call frames small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/perf.bpf.c"
#include "dispatch/probes.bpf.c"
#include "dispatch/failopen.bpf.c"
#include "dispatch/drain.bpf.c"
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	u32 extra = 0;
	int i;
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
		if (extra) {
			__sync_fetch_and_add(&flow_stats.over_moves,
			    (u64)extra);
			__sync_fetch_and_add(&flow_stats.fifo_parks,
			    (u64)extra);
		}
		/* Single exit covers the level, so idle cannot be skipped. */
		goto out;
	}
	bpf_for(i, 0, FLOW_DISPATCH_MAX_BATCH) {
		u64 qlen;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		qlen = scx_bpf_dsq_nr_queued(flow_overflow_dsq());
		if (qlen == 0)
			break;
		/* Past deep backlog ordered stops after four moves with */
		/* FIFO covering the remainder below, so one pass never */
		/* burns sixteen double scans on a deep tail while still */
		/* draining sixteen with ordered first. */
		if ((u64)moved >= (u64)FLOW_DISPATCH_FLOOD_PROBES &&
		    qlen > (u64)FLOW_DISPATCH_FLOOD_QUEUED)
			break;
		/* A recheck miss ends ordered and falls to FIFO below, */
		/* so one stale pick never burns extra scans. */
		if (!veb_consume_best(cpu))
			break;
		moved++;
	}
	if (moved) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
		__sync_fetch_and_add(&flow_stats.veb_hits,
		    (u64)moved);
		if (moved < (u32)FLOW_DISPATCH_MAX_BATCH &&
		    scx_bpf_dsq_nr_queued(flow_overflow_dsq()) != 0) {
			u32 left = (u32)FLOW_DISPATCH_MAX_BATCH - moved;
			extra = veb_fail_open_drain(cpu, left);
			if (extra) {
				__sync_fetch_and_add(&flow_stats.over_moves,
				    (u64)extra);
				__sync_fetch_and_add(&flow_stats.fifo_parks,
				    (u64)extra);
			}
		}
		/* Single exit covers the level, so idle cannot be skipped. */
		goto out;
	}
	extra = veb_fail_open_drain(cpu,
	    (u32)FLOW_DISPATCH_MAX_BATCH);
	if (extra) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)extra);
		__sync_fetch_and_add(&flow_stats.fifo_parks,
		    (u64)extra);
	}
out:
	/* Level follows after ordered moves plus fail open */
	/* with the same CPU only through one exit. */
	flow_perf_update(cpu);
}
