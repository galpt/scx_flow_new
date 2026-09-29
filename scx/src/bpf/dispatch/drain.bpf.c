// SPDX-License-Identifier: GPL-2.0
/*
 * Plain drain for the dispatch pass.
 *
 * Moves gated tasks to local with a miss cap at 4.
 * One bad head never blocks later work with no full scan.
 * Serves deadline, global, overflow, and steal trips. Every move
 * shares one gate helper with mask plus stamp plus generation
 * checks, and park moves add the throttle check. Admitted work
 * moves without a throttle recheck, since admission plus the gated
 * overflow pass already hold throttled parks with a timer wake.
 * Runs under the caller RCU read lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one overflow task is still throttled via its leaf flag. */
/* Takes cached plus id scalars with no struct pass, so the caller */
/* stays small and the check verifies once. A cold cache or a missing */
/* leaf moves fail open on purpose, so a move while parked costs one */
/* quantum at most. The moved task runs one slice, the stop path still */
/* charges the pools, and the next enqueue walks and parks with pending */
/* armed, so no pool bypass survives past one quantum. A flagged hit */
/* re-arms the timer flag for the next tick. */
static __noinline bool flow_over_throttled_scalar(bool cached,
	u64 cgid)
{
	struct flow_cgrp_ctx *e;

	if (!cached)
		return false;
	e = flow_cgrp(cgid);
	if (!e)
		return false;
	if (!(flow_load_flags(e) & (u32)FLOW_CGRP_THROTTLED))
		return false;
	__sync_lock_test_and_set(&flow_bw_pending, 1);
	return true;
}
/* True when one queued task may move to the dispatching CPU. */
/* Takes the task plus its state with no walk, so every drain */
/* verifies once. The live check repeats the dispatch check, so an */
/* offline during the pass fails closed with no move. The mask wins */
/* next, then a zero stamp fails closed, and a stale generation reads */
/* as cold with a fail open move for one quantum only. Park moves add */
/* the throttle check with the timer behind the wait, admitted moves */
/* skip it with admission plus overflow cover. Exiting tasks never */
/* reach here, they run at once on the enqueue path with no queue wait. */
static __noinline bool flow_gate_ok(s32 cpu,
	struct task_struct *p, struct flow_task_ctx *tctx, bool park)
{
	bool eff;
	if (cpu < 0 || !tctx)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	if (!bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr))
		return false;
	if (tctx->wait_at == 0)
		return false;
	eff = tctx->cached && tctx->generation == (u16)flow_load_gen();
	if (park && flow_over_throttled_scalar(eff, tctx->cgid))
		return false;
	return true;
}
/* One drain trip over a queue with a shared gate. */
/* Each visit pays one pid lookup plus one state lookup, and a null, */
/* disallowed, unstamped, failed, or throttled visit counts one miss */
/* with the miss cap at 4, so one bad head never stalls the pass. */
static __noinline u32 flow_drain_one(s32 cpu,
	u64 dsq, u32 budget, u32 base, bool open)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;

	bpf_for_each(scx_dsq, p, dsq, 0) {
		struct flow_task_ctx *tctx;
		bool ok;
		if (moved + base >= budget)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p) {
			miss++;
			continue;
		}
		/* Liveness holds through the trusted lookup above. */
		/* Missing state moves fail open on the homeless path */
		/* with mask wins, else fail closed with one miss. */
		/* The park check stays off here with no flag use, the */
		/* gated drain covers throttled parks with the timer. */
		tctx = flow_lookup(p);
		if (!tctx && !open) {
			bpf_task_release(p);
			miss++;
			continue;
		}
		if (tctx)
			ok = flow_gate_ok(cpu, p, tctx, false);
		else
			ok = bpf_cpumask_test_cpu((u32)cpu,
			    p->cpus_ptr);
		if (ok && scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	return moved;
}
