// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves admitted tasks in tree order up to sixteen per pass.
 * The pass starts from the least key and follows successors with
 * at most twenty key probes so one pass never scans the tail more
 * than twenty times. Twenty covers sixteen moves plus four skip
 * slack so full batches never starve on sparse keys. Under flood
 * with more than one hundred twenty eight queued the pass stops
 * ordered probes after four and drains FIFO, so a deep backlog never
 * burns twenty full tail scans with zero moves. A drained tail exits
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
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "dispatch/perf.bpf.c"
static __noinline bool veb_try_move_one(u32 key, s32 cpu)
{
	bool moved = false;
	struct task_struct *p;
	if (key >= (u32)FLOW_VEB_U)
		return false;
	if (cpu < 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		u32 pid = 0;
		u32 k2 = 0;
		if (moved)
			break;
		if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p, key,
		    &pid, &k2)) {
			moved = true;
			veb_remove_if_key(pid, k2);
			break;
		}
	}
	bpf_rcu_read_unlock();
	return moved;
}
/* Fail open with liveness plus affinity solely and no order gate. */
/* Moves the first live affinity match at the overflow head so one */
/* runnable task always lands on the dispatch CPU even when a stale */
/* entry holds no order row. Skips drop no tree state with no park */
/* count so transient misses stay quiet. Moves count one FIFO park */
/* at the decision point. The moved pid drops its key solely when */
/* the stored key still matches. Stays rare since admits write rows */
/* synchronously and solely genuine affinity misses reach here. */
static __noinline bool veb_fail_open_one(s32 cpu)
{
	bool moved = false;
	u32 reap_pid = 0;
	u32 reap_key = (u32)FLOW_VEB_EMPTY;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return false;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		u32 pid;
		u32 *kp;
		if (moved)
			break;
		if (!flow_entry_ok(cpu, p, 0))
			continue;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		if (pid == 0) {
			bpf_task_release(t);
			continue;
		}
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			moved = true;
			reap_pid = pid;
			kp = bpf_map_lookup_elem(&veb_pid, &pid);
			if (kp && READ_ONCE(*kp) !=
			    (u32)FLOW_VEB_EMPTY &&
			    READ_ONCE(*kp) < (u32)FLOW_VEB_U)
				reap_key = READ_ONCE(*kp);
		}
		bpf_task_release(t);
		if (moved)
			break;
	}
	bpf_rcu_read_unlock();
	if (moved) {
		if (reap_pid != 0 && reap_key != (u32)FLOW_VEB_EMPTY)
			veb_remove_if_key(reap_pid, reap_key);
		return true;
	}
	return false;
}

/* Fail open drain with batch progress and FIFO order in one place. */
/* Calls the single head move up to the batch bound so a stalled pass */
/* still drains up to sixteen queue ordered tasks. Under flood rejects */
/* hold no key and ordered probes find nothing, so this loop carries */
/* the backlog instead of one per pass. Each move stays affinity gated */
/* with keyed drop, so order rows never leak and no dead task runs. */
static __noinline u32 veb_fail_open_drain(s32 cpu, u32 budget)
{
	u32 moved = 0;
	int i;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	if (budget > (u32)FLOW_DISPATCH_MAX_BATCH)
		budget = (u32)FLOW_DISPATCH_MAX_BATCH;
	bpf_for(i, 0, FLOW_DISPATCH_MAX_BATCH) {
		if ((u64)moved >= (u64)budget)
			break;
		if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
			break;
		if (!veb_fail_open_one(cpu))
			break;
		moved++;
	}
	return moved;
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	u32 cur;
	u32 extra = 0;
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
		if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
			break;
		if (attempt >= (int)FLOW_DISPATCH_FLOOD_PROBES &&
		    scx_bpf_dsq_nr_queued(flow_overflow_dsq()) >
		        (u64)FLOW_DISPATCH_FLOOD_QUEUED)
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
