// SPDX-License-Identifier: GPL-2.0
/*
 * Runtime floor helpers for the core.
 *
 * Holds the per CPU floor read plus the compare and swap max with
 * wrap safety. The floor tracks served runtime per CPU, and open
 * inserts key past it, so a long sleep never earns credit. Only
 * live inserts and pops touch the floor, parks and homeless work
 * never do. Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Floor of one CPU with zero on miss. */
/* A missing row reads zero, so fresh CPUs key past now. */
static __always_inline u64 flow_floor_read(u32 cpu)
{
	u32 key = cpu;
	u64 *v;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return 0;
	v = bpf_map_lookup_elem(&vruntime_floor, &key);
	if (!v)
		return 0;
	return READ_ONCE(*v);
}
/* Bump one floor to the later time with a plain compare. */
/* Saturated floors never wrap, so the plain order keeps the */
/* largest value with no signed diff use. The compare and swap */
/* loop keeps the largest value with no torn floor. Past bound or */
/* offline ids drop with no write. Outlined with scalar inputs, so */
/* the enqueue and stop paths verify once. */
static __noinline void flow_floor_max(u32 cpu, u64 val)
{
	u32 key = cpu;
	u64 *v;
	s32 i;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return;
	if (!flow_cpu_live(cpu))
		return;
	v = bpf_map_lookup_elem(&vruntime_floor, &key);
	if (!v)
		return;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*v);
		u64 old;
		if (cur >= val)
			break;
		old = __sync_val_compare_and_swap(v, cur, val);
		if (old == cur)
			break;
	}
}
