// SPDX-License-Identifier: GPL-2.0
/*
 * Task and map helpers for the core.
 *
 * Holds the clock plus task, CPU, topology, capacity, and
 * hint loads shared by every op. Runs inline with no walk, so the
 * verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Monotonic clock in nanos for deadlines plus fair times. */
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}
/* Task state without create for fast read paths. */
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}
/* Task state with create for enqueue and enable paths. */
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
/* CPU state or null when the id is past the bound. */
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}
/* Topology view or null when the id is past the bound. */
static struct flow_topo *flow_topo(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&topo_stor, &key);
}
/* Capacity units of one CPU with base on miss. */
/* A zero row means unknown, so the base applies. */
static __always_inline u32 flow_cpu_units(u32 cpu)
{
	u32 key = cpu;
	u32 *v;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return (u32)FLOW_CAP_BASE;
	v = bpf_map_lookup_elem(&cap_stor, &key);
	if (!v || *v == 0)
		return (u32)FLOW_CAP_BASE;
	return READ_ONCE(*v);
}
/* Node of one CPU with zero on miss. */
static __always_inline u32 flow_cpu_node(u32 cpu)
{
	struct flow_topo *tp = flow_topo(cpu);
	if (!tp)
		return 0;
	if (tp->node >= (u32)FLOW_MAX_NODES)
		return 0;
	return READ_ONCE(tp->node);
}
/* Flat period hint in micros for one id with zero for no hint. */
/* Id zero scopes to defaults with no row, so a missing hierarchy */
/* stays neutral with no stall. */
static __always_inline u32 flow_hint_us(u64 cgid)
{
	struct flow_hint *h;
	if (!cgid)
		return 0;
	h = bpf_map_lookup_elem(&hint_stor, &cgid);
	if (!h)
		return 0;
	return READ_ONCE(h->period_us);
}
/* Flat weight hint for one id with base on miss. */
/* Id zero scopes to the neutral share with no row, so a missing */
/* hierarchy stays neutral. A missing row means no hint, so the neutral */
/* share applies with no cgroup use. Values clamp once at write with */
/* single weighting, and reads clamp defensively with the same helper, */
/* so a stale row never escapes range. */
static __always_inline u32 flow_hint_weight(u64 cgid)
{
	struct flow_hint *h;
	if (!cgid)
		return (u32)FLOW_WEIGHT_BASE;
	h = bpf_map_lookup_elem(&hint_stor, &cgid);
	if (!h)
		return (u32)FLOW_WEIGHT_BASE;
	{
		u32 w = READ_ONCE(h->weight);
		if (w == 0)
			return (u32)FLOW_WEIGHT_BASE;
		return flow_weight_clamp(w);
	}
}
/* Acquired hierarchy of one task with paired release. */
/* Uses the scheduler view with a reference, so the caller releases */
/* with release when non null. A null return means the root with */
/* the default period and no hint use. */
static __always_inline struct cgroup *flow_task_cgrp(
	struct task_struct *p)
{
	return scx_bpf_task_cgroup(p);
}
/* Release one acquired hierarchy with null tolerance. */
/* A null pointer needs no release, so miss paths stay cheap. */
static __always_inline void flow_cgrp_put(
	struct cgroup *cgrp)
{
	if (cgrp)
		bpf_cgroup_release(cgrp);
}
