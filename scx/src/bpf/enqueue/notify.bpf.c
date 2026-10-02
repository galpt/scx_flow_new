// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue notify for the flow core.
 *
 * Reserves one ring slot and writes kind plus sequence plus pid plus
 * CPU plus weight with the enqueue kind so the daemon sees every park.
 * Gives no state on reserve fault with loss irrelevant to decisions.
 * Runs noinline with scalar pid plus CPU plus weight plus sequence
 * so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void flow_notify_enqueue(u32 pid,
	u32 cpu, u32 weight, u64 seq)
{
	struct flow_event *ev;
	ev = bpf_ringbuf_reserve(&flow_enq_rb, sizeof(*ev), 0);
	if (!ev)
		return;
	ev->kind = (u64)FLOW_PROTO_ENQUEUE;
	ev->seq = seq;
	ev->pid = pid;
	ev->cpu = cpu;
	ev->weight = weight;
	ev->pad = 0;
	ev->at = flow_now();
	bpf_ringbuf_submit(ev, 0);
}
