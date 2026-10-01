// SPDX-License-Identifier: GPL-2.0
/*
 * Fail open batch drain for the dispatch pass.
 *
 * Moves the first live affinity matches in queue order up to the
 * exact budget in one scan, so a stalled pass still drains queue
 * ordered tasks up to sixteen and a moving pass drains the remainder
 * after ordered work within sixteen. Ordered checks run first so
 * admitted tasks stay preferred, while this FIFO step moves the
 * remainder with best effort order there. Each move stays affinity
 * gated with drops at teardown, so no dead task runs. Callers pass
 * sixteen on stall plus the remainder on moving passes, so the
 * budget stays exact with no clamp. The queue handle stays hoisted
 * once at entry, so the scan pays no dsq lookup. Live stays proven
 * once at entry through the dispatch gate, so the scan pays one mask
 * test per entry with no live branch. Runs noinline with scalar CPU
 * plus budget and a bounded scan so the verifier stays small with no
 * unrolled caller tree and no rescan per move.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fail open drain with batch progress and FIFO order in one place. */
/* Moves up to the exact budget in queue order in one scan so a */
/* stalled pass still drains up to sixteen and a moving pass drains */
/* the remainder within sixteen. Ordered checks run first so admitted */
/* tasks stay preferred, while this FIFO step moves the remainder */
/* with best effort order. Noinline with scalar inputs so the single */
/* scan verifies once apart from the dispatch entry. */
static __noinline u32 veb_fail_open_drain(s32 cpu, u32 budget)
{
	u32 moved = 0;
	u64 ov;
	struct task_struct *p;
	if (cpu < 0)
		return 0;
	if (budget == 0)
		return 0;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return 0;
	}
	/* Queue handle stays hoisted, so the scan pays no dsq lookup. */
	ov = flow_overflow_dsq();
	if (scx_bpf_dsq_nr_queued(ov) == 0)
		return 0;
	/* Single scan moves up to budget in queue order with no rescan */
	/* per move, so a deep tail pays one scan for sixteen moves. */
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, ov, 0) {
		if ((u64)moved >= (u64)budget)
			break;
		if (flow_fail_open_move(BPF_FOR_EACH_ITER, cpu, p))
			moved++;
	}
	bpf_rcu_read_unlock();
	return moved;
}
