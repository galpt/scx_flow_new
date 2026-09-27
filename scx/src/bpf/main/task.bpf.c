// SPDX-License-Identifier: GPL-2.0
/*
 * Task and map helpers for the core.
 *
 * Holds the clock plus task, CPU, topology, hierarchy, and atomic
 * loads shared by every op. Runs inline with no walk, so the
 * verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Monotonic clock in nanos for deadlines and starvation. */
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
/* Hierarchy entry or null on miss with default share. */
static struct flow_cgrp_ctx *flow_cgrp(u64 cgid)
{
	return bpf_map_lookup_elem(&cgrp_stor, &cgid);
}
/* Acquired hierarchy of one task with paired release. */
/* Uses the scheduler view with a reference, so the caller releases */
/* with release when non null. A null return means the root with */
/* miss defaults and no hierarchy use. */
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
/* Relaxed load of the hierarchy generation to match the bumps. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_gen(void)
{
	return READ_ONCE(flow_cgrp_gen);
}
/* Relaxed load of the limited count to match the fixups. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_limited(void)
{
	return READ_ONCE(flow_bw_limited);
}
/* Relaxed load of the pending flag to match the enqueue store. */
/* Pairs with the fetch and add stores with no torn read. */
static __always_inline u64 flow_load_pending(void)
{
	return READ_ONCE(flow_bw_pending);
}
