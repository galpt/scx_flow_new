// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves admitted tasks in tree order up to sixteen per pass
 * with best effort under flood. Ordered checks run first so
 * admitted tasks stay preferred, while the FIFO drain may
 * move admitted tasks out of order under flood.
 * The pass starts from the least key and follows successors with
 * at most twenty key probes so one pass never scans the tail more
 * than twenty times. Twenty covers sixteen moves plus four skip
 * slack so full batches never starve on sparse keys. Under flood
 * with more than one hundred twenty eight queued the pass stops
 * ordered probes after four checks past moves while moving work
 * keeps probing, so productive batches never truncate on the
 * attempt count. A deep backlog never burns twenty full tail scans
 * with zero moves. A drained tail exits
 * the pass at once so empty probes never run. Empty keys skip through
 * counts with no tail scan and drained keys advance at once so
 * fruitless rescans never run. Each key scans the overflow tail and
 * moves the first admitted task with sequence, liveness, affinity
 * checks. Duplicates leave in park order within one key. Per CPU
 * mismatch, missing order, stale sequence skip with no tree drop and
 * the core drops shares through stopping plus disable plus exit. Only
 * the moved pid drops its key when the stored key still matches.
 * Empty queue leaves at once with no scan so idle stays cheap. Empty
 * tree or stall drains up to sixteen FIFO tasks with liveness plus
 * affinity checks plus keyed drop and no order or sequence gate so
 * runnable tasks never stall on live work. Under flood most parks
 * hold no key since per CPU rows saturate, so this FIFO drain carries
 * rejects in queue order up to the batch bound and one stalled pass
 * still makes batch progress. Fail open stays rare in normal load
 * since rows land synchronously and solely genuine affinity misses
 * reach it. Over moves count progress with ordered moves counting vEB
 * hits plus fail open moves counting FIFO parks so every dispatched
 * task lands in one bucket. Level follows after ordered moves plus
 * fail open with the same CPU only and no call on steady through one
 * exit, so idle cannot be skipped.
 *
 * The pass splits across dispatch/probes, failopen, drain, perf files
 * with one RCU section per helper. Each helper stays noinline with
 * scalar inputs and bounded loops, so the verifier stays small,
 * except the bit scans plus the batch drain wrapper which stay
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
	u32 cur;
	u32 extra = 0;
	u64 qlen = 0;
	int attempt;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		goto out;
	cur = veb_min();
	if (cur == (u32)FLOW_VEB_EMPTY) {
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
	bpf_for(attempt, 0, FLOW_DISPATCH_MAX_PROBES) {
		u32 *cntp;
		bool got;
		u32 *after;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		if (cur == (u32)FLOW_VEB_EMPTY)
			break;
		qlen = scx_bpf_dsq_nr_queued(flow_overflow_dsq());
		if (qlen == 0)
			break;
		if ((u64)attempt >= (u64)FLOW_DISPATCH_FLOOD_PROBES +
		    (u64)moved &&
		    qlen > (u64)FLOW_DISPATCH_FLOOD_QUEUED)
			break;
		cntp = veb_cnt_ptr(cur);
		if (!cntp || READ_ONCE(*cntp) == 0) {
			cur = veb_succ(cur);
			continue;
		}
		got = veb_try_move_one(cur, cpu);
		if (got) {
			moved++;
			after = veb_cnt_ptr(cur);
			if (!after || READ_ONCE(*after) == 0)
				cur = veb_succ(cur);
			continue;
		}
		cur = veb_succ(cur);
	}
	if (moved) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
		__sync_fetch_and_add(&flow_stats.veb_hits,
		    (u64)moved);
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
