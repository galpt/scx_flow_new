// SPDX-License-Identifier: GPL-2.0
/*
 * Park plus admission for the enqueue path.
 *
 * Parks at the overflow tail with plain insert and counts one insert.
 * Admission allocates one sequence then stores it plus the deadline
 * plus key from the same period helpers, then admits under
 * the bound with tree plus row or parks as reject at the top key
 * with the far deadline then parks at the tail then notifies for
 * observability solely. Rejects stay ordered at the top key so
 * dispatch still picks them by key then deadline. Admitted parks
 * also store one head plus one placement view for later picks with
 * no extra counter, and rejects store the same views with the far
 * deadline keeping the head behind admits. Every park notifies best
 * effort with loss irrelevant.
 * Callers pass the chosen CPU with zero for unknown so fail closed
 * parks still notify with no bypass. Plain park stays inline so the
 * insert stays cheap. Admission stays noinline with scalar weight
 * plus CPU so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __always_inline void flow_park_plain(struct task_struct *p,
	u64 enq_flags)
{
	scx_bpf_dsq_insert(p, flow_overflow_dsq(),
	    (u64)FLOW_QUANTUM_NS, enq_flags);
	__sync_fetch_and_add(&flow_stats.inserts, 1);
}
/* Park plus notify with BPF owned admission in one place. */
/* Allocates one sequence then stores it then admits synchronously */
/* with tree plus row or parks as reject at the top key with the far */
/* deadline then parks at the tail then notifies for observability */
/* solely. Rejects stay ordered through task state plus tree with no */
/* row, so the ordered path still moves them. Every park notifies */
/* best effort with loss irrelevant. Callers pass the chosen CPU with */
/* zero for unknown so fail closed parks still notify with no bypass. */
static __noinline void flow_reject_top(u32 pid, u32 cpu,
	struct flow_task_ctx *tctx)
{
	u32 top;
	u64 far;
	/* Zero never keys the tree, so an early return stays safe with */
	/* the pid zero path clearing only above. */
	if (pid == 0)
		return;
	top = (u32)FLOW_VEB_U - 1;
	far = (u64)~0ULL;
	if (tctx) {
		WRITE_ONCE(tctx->admit_share, 0);
		if ((u64)cpu < (u64)FLOW_MAX_CPUS)
			WRITE_ONCE(tctx->admit_cpu, cpu);
		else
			WRITE_ONCE(tctx->admit_cpu, 0);
		WRITE_ONCE(tctx->deadline, far);
		WRITE_ONCE(tctx->key, top);
	}
	veb_insert(pid, far);
	flow_order_delete(pid);
	if ((u64)cpu < (u64)FLOW_MAX_CPUS) {
		flow_head_store(pid, top, far, cpu);
		flow_place_store(pid, cpu);
	}
}
static __noinline void flow_enqueue_admit(struct task_struct *p,
	u64 enq_flags, u32 weight, u32 cpu,
	struct flow_task_ctx *tctx)
{
	u64 now = flow_now();
	u64 period = flow_period_ns(weight);
	u64 deadline = flow_deadline_at(now, period);
	u64 share = flow_share_permille(period);
	u64 seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
	u32 pid = (u32)p->pid;
	u32 key = veb_quant(deadline);
	bool admitted = false;
	if (tctx) {
		WRITE_ONCE(tctx->seq, seq);
		WRITE_ONCE(tctx->deadline, deadline);
		WRITE_ONCE(tctx->key, key);
	}
	if (pid == 0) {
		flow_gate_reject();
		/* Zero never keys the tree plus head plus place, so clear */
		/* only with no insert stays safe and matches the helper */
		/* early return for zero. */
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, 0);
			WRITE_ONCE(tctx->deadline, 0);
			WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
		}
		flow_order_delete(pid);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS) {
		flow_gate_reject();
		flow_reject_top(pid, 0, tctx);
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		__sync_fetch_and_add(&flow_stats.parks, 1);
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	if (share == 0) {
		if (tctx) {
			WRITE_ONCE(tctx->admit_share, 0);
			WRITE_ONCE(tctx->admit_cpu, cpu);
			WRITE_ONCE(tctx->deadline, deadline);
			WRITE_ONCE(tctx->key, key);
		}
		veb_insert(pid, deadline);
		if (flow_order_write(pid, seq, deadline, cpu)) {
			__sync_fetch_and_add(&flow_stats.admits, 1);
			admitted = true;
			/* Zero share parks ordered as reject, so only the */
			/* placement view learns the CPU with no head. */
			flow_place_store(pid, cpu);
		} else {
			veb_remove(pid);
			if (tctx) {
				WRITE_ONCE(tctx->admit_share, 0);
				WRITE_ONCE(tctx->admit_cpu, 0);
				WRITE_ONCE(tctx->deadline, 0);
				WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
			}
		}
	} else {
		if (flow_admit_try_add(cpu, share)) {
			if (tctx) {
				WRITE_ONCE(tctx->admit_share, (u32)share);
				WRITE_ONCE(tctx->admit_cpu, cpu);
				WRITE_ONCE(tctx->deadline, deadline);
				WRITE_ONCE(tctx->key, key);
			}
			veb_insert(pid, deadline);
			if (flow_order_write(pid, seq, deadline, cpu)) {
				__sync_fetch_and_add(&flow_stats.admits, 1);
				admitted = true;
				/* Head keeps the earliest for the key with the */
				/* placement view learning the owner, so later */
				/* picks skip the tail walk and later parks */
				/* reuse warmth with mask still checked. */
				flow_head_store(pid, key, deadline, cpu);
				flow_place_store(pid, cpu);
			} else {
				veb_remove(pid);
				flow_admitted_sub(cpu, share);
				if (tctx) {
					WRITE_ONCE(tctx->admit_share, 0);
					WRITE_ONCE(tctx->admit_cpu, 0);
					WRITE_ONCE(tctx->deadline, 0);
					WRITE_ONCE(tctx->key, (u32)FLOW_VEB_EMPTY);
				}
			}
		}
	}
	if (admitted) {
		flow_park_plain(p, enq_flags);
		flow_notify_enqueue(pid, cpu, weight, seq);
		return;
	}
	flow_reject_top(pid, cpu, tctx);
	__sync_fetch_and_add(&flow_stats.rejects, 1);
	__sync_fetch_and_add(&flow_stats.parks, 1);
	flow_park_plain(p, enq_flags);
	flow_notify_enqueue(pid, cpu, weight, seq);
}
