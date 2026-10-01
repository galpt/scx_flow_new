// SPDX-License-Identifier: GPL-2.0
/*
 * Finish helper for task teardown.
 *
 * Holds the complete notify plus the paired teardown with single exit
 * through one return. Key remove, leftover charge, pid clear, gauge
 * drop, ledger drop, order delete, observability notify run in one
 * place so a missed cleanup cannot leak shares or linger keys.
 * Charged paths notify at once while idle paths notify solely when
 * queued so never queued tasks stay quiet. Drops run exactly once
 * through stored share clearing with order delete idempotent. Misses
 * count on blocking past deadline with parks folded in. Rings stay
 * best effort with loss irrelevant. Gives true when a segment charged
 * so stopping counts once with no double count. Disable plus exit
 * ignore the return with no extra work.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Complete notify with best effort and no counter on fault. */
/* Gives no state on reserve fault with loss irrelevant to decisions. */
static __noinline void flow_notify_complete(u32 pid,
	u32 cpu, u32 weight, u32 runnable)
{
	struct flow_event *ev;
	u64 seq;
	ev = bpf_ringbuf_reserve(&flow_cmp_rb, sizeof(*ev), 0);
	if (!ev)
		return;
	seq = __sync_fetch_and_add(&flow_seq, 1) + 1;
	ev->kind = (u64)FLOW_PROTO_COMPLETE;
	ev->seq = seq;
	ev->pid = pid;
	ev->cpu = cpu;
	ev->weight = weight;
	ev->pad = runnable;
	ev->at = flow_now();
	bpf_ringbuf_submit(ev, 0);
}
/* Paired teardown with key, charge, pid, gauge, ledger, notify. */
/* Drops the tree key then charges leftovers then clears the pid then */
/* drops the ledger with miss check then notifies for observability */
/* solely when queued or charged. Callers pass the task with weight */
/* plus runnable so every teardown covers all six with no split. */
static __noinline bool flow_finish_task(struct task_struct *p,
	s32 cpu, u32 weight, u32 runnable)
{
	u32 pid = (u32)p->pid;
	struct flow_task_ctx *tctx = flow_lookup(p);
	bool charged;
	u32 out_cpu = cpu >= 0 ? (u32)cpu : 0;
	u64 now = flow_now();
	veb_remove(pid);
	charged = flow_charge_leftover(p, tctx, cpu);
	flow_clear_running_if_owner(cpu, pid);
	flow_admit_drop(pid, tctx, runnable, now);
	if (charged) {
		flow_notify_complete(pid, out_cpu, weight, runnable);
		return true;
	}
	if (!tctx || READ_ONCE(tctx->seq) != 0)
		flow_notify_complete(pid, out_cpu, weight, runnable);
	return false;
}
