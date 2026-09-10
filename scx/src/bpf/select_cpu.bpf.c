/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	s32 this_cpu;
	s32 picked;
	s32 first;
	u8 group;
	struct flow_task_ctx *tctx;
	this_cpu = (s32)bpf_get_smp_processor_id();
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		first = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, first))
			return first;
		return prev_cpu;
	}
	if (p->nr_cpus_allowed == 1) {
		s32 here = scx_bpf_task_cpu(p);
		s32 allow;
		if (flow_cpu_ok(p, here))
			return here;
		if (flow_cpu_ok(p, prev_cpu))
			return prev_cpu;
		allow = (s32)bpf_cpumask_first(p->cpus_ptr);
		if (flow_cpu_ok(p, allow))
			return allow;
		return prev_cpu;
	}
	tctx = bpf_task_storage_get(&task_ctx_stor,
	    p, 0, 0);
	if (tctx && tctx->group ==
	    (u8)FLOW_GROUP_HOG)
		group = (u8)FLOW_GROUP_HOG;
	else
		group = (u8)FLOW_GROUP_LIGHT;
	picked = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (picked >= 0 && flow_cpu_ok(p, picked)) {
		u8 g = flow_group_live((u32)picked,
		    nr_cpu_ids);
		if (g == group)
			return picked;
		__sync_fetch_and_add(
		    &flow_stats.group_steal_skipped, 1);
	}
	if (flow_cpu_ok(p, prev_cpu)) {
		u8 g = flow_group_live((u32)prev_cpu,
		    nr_cpu_ids);
		if (g == group)
			return prev_cpu;
	}
	if (flow_cpu_ok(p, this_cpu)) {
		u8 g = flow_group_live((u32)this_cpu,
		    nr_cpu_ids);
		if (g == group)
			return this_cpu;
	}
	first = flow_first_in_group(p, group);
	if (first >= 0)
		return first;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	return prev_cpu;
}
