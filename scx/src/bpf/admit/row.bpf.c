// SPDX-License-Identifier: GPL-2.0
/*
 * Order row writes for the flow core.
 *
 * Holds the synchronous order row store plus delete used at park
 * time and at drop time. Admit writes one row with sequence,
 * deadline, CPU in one store so dispatch sees the same values as
 * task state with no roundtrip. Reject clears any stale row so no
 * empty row lingers. Drops delete idempotently so a second drop
 * stays quiet. Miss reads use the stored deadline before the delete
 * so blocking completions past deadline count once. All helpers stay
 * small so the verifier stays small. Rows live in the core with the
 * daemon as monitor solely.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool flow_order_write_one(u32 pid, u64 seq,
	u64 deadline, u32 cpu)
{
	struct flow_order_entry e;
	long ret;
	if (pid == 0)
		return false;
	if (seq == 0)
		return false;
	e.seq = seq;
	e.deadline = deadline;
	e.cpu = cpu;
	e.pad = 0;
	ret = bpf_map_update_elem(&order_stor, &pid, &e, BPF_ANY);
	return ret == 0;
}
static __noinline void flow_order_delete_one(u32 pid)
{
	if (pid == 0)
		return;
	bpf_map_delete_elem(&order_stor, &pid);
}
static __noinline u64 flow_order_deadline(u32 pid)
{
	struct flow_order_entry *ord;
	if (pid == 0)
		return 0;
	ord = bpf_map_lookup_elem(&order_stor, &pid);
	if (!ord)
		return 0;
	return READ_ONCE(ord->deadline);
}
static __always_inline bool flow_order_write(u32 pid, u64 seq,
	u64 deadline, u32 cpu)
{
	return flow_order_write_one(pid, seq, deadline, cpu);
}
static __always_inline void flow_order_delete(u32 pid)
{
	flow_order_delete_one(pid);
}
