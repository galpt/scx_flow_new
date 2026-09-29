// SPDX-License-Identifier: GPL-2.0
/*
 * Tier drains for the dispatch pass.
 *
 * Moves one queue to local with a shared gate plus mask plus stamp
 * checks. The gated trip serves local plus node plus machine plus
 * overflow with an optional backstop wait, and the homeless trip
 * serves global only with fail open moves. Overflow parks younger
 * than the backstop interval count one miss and keep order, so fresh
 * parks never jump the queue. Each visit pays one pid lookup plus one
 * state lookup, and a null, disallowed, unstamped, young, or failed
 * visit counts one miss with the miss cap at 3, so one bad head never
 * stalls the pass. Runs under the caller RCU read lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one queued task may move to the dispatching CPU. */
/* The live check repeats the dispatch check, so an offline CPU */
/* during the pass fails closed with no move. The mask wins next, */
/* then a zero stamp fails closed with one miss. Exiting tasks never */
/* reach here, they run at once on the enqueue path with no queue wait. */
static __noinline bool flow_gate_ok(s32 cpu,
	struct task_struct *p, struct flow_task_ctx *tctx)
{
	if (cpu < 0 || !tctx)
		return false;
	if (!p)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	if (!bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr))
		return false;
	if (tctx->wait_at == 0)
		return false;
	return true;
}
/* One gated trip over a queue to local with an optional backstop. */
/* Takes CPU plus queue plus limit plus base plus backstop scalars */
/* with no struct pass, so every tier verifies through this one loop. */
/* A set backstop holds parks younger than the interval with one miss. */
static __noinline u32 flow_drain_gated(s32 cpu,
	u64 dsq, u32 lim, u32 base, bool backstop)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;
	u64 now = 0;
	if (backstop)
		now = flow_now();
	bpf_for_each(scx_dsq, p, dsq, 0) {
		struct flow_task_ctx *tctx;
		struct task_struct *trusted;
		bool ok;
		if (moved + base >= lim)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		trusted = bpf_task_from_pid(p->pid);
		if (!trusted) {
			miss++;
			continue;
		}
		tctx = flow_lookup(trusted);
		if (!tctx) {
			bpf_task_release(trusted);
			miss++;
			continue;
		}
		ok = flow_gate_ok(cpu, trusted, tctx);
		if (ok && backstop && !flow_parked(tctx->wait_at,
		    now))
			ok = false;
		if (ok && scx_bpf_dsq_move(BPF_FOR_EACH_ITER,
		    trusted, (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(trusted);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(trusted);
			miss++;
		}
	}
	return moved;
}
/* One homeless trip over global to local with fail open moves. */
/* Tasks without state move with mask wins, so homeless work never */
/* stalls. All other visits count one miss with the same miss cap. */
static __noinline u32 flow_drain_global(s32 cpu,
	u32 lim, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;
	bpf_for_each(scx_dsq, p, SCX_DSQ_GLOBAL, 0) {
		struct task_struct *trusted;
		bool ok;
		if (moved + base >= lim)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		trusted = bpf_task_from_pid(p->pid);
		if (!trusted) {
			miss++;
			continue;
		}
		ok = bpf_cpumask_test_cpu((u32)cpu,
		    trusted->cpus_ptr);
		if (ok && scx_bpf_dsq_move(BPF_FOR_EACH_ITER,
		    trusted, (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(trusted);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(trusted);
			miss++;
		}
	}
	return moved;
}
