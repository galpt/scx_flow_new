// SPDX-License-Identifier: GPL-2.0
/*
 * Hierarchy stubs for the thin core.
 *
 * Policy lives in the daemon. The core keeps paired stubs so cgroup
 * transitions stay balanced. Init plus move plus cancel pass. Exit
 * plus weight hold empty.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
	struct scx_cgroup_init_args *args)
{
	(void)cgrp;
	(void)args;
	return 0;
}
void BPF_STRUCT_OPS(flow_cgroup_exit, struct cgroup *cgrp)
{
	(void)cgrp;
}
s32 BPF_STRUCT_OPS(flow_cgroup_prep_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
	return 0;
}
void BPF_STRUCT_OPS(flow_cgroup_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
void BPF_STRUCT_OPS(flow_cgroup_cancel_move, struct task_struct *p,
	struct cgroup *from, struct cgroup *to)
{
	(void)p;
	(void)from;
	(void)to;
}
void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp,
	u32 weight)
{
	(void)cgrp;
	(void)weight;
}
