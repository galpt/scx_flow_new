// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op for the flow core.
 *
 * Proposes one CPU with deadline driven placement. The op derives one
 * deadline from weight derived period plus now then quantizes to one
 * key with the same quantize as the tree so placement shares the order
 * source with dispatch. The previous CPU wins when live plus allowed
 * with no drain check so warmth stays cheap. An idle CPU wins next
 * through the idle pick when live plus allowed so light work lands
 * with no scan. The first allowed live CPU wins last. Stale masks fail
 * closed with an error and one gate count so callers never run on a
 * stale CPU. The core owns admit with per CPU rows and the core
 * proposes solely through the selected CPU so rejects park with no run.
 * Dispatch order stays least plus successor with no change. The core
 * keeps mask wins and progress. One fallback helper pairs the previous,
 * idle, first checks with the gate count through one exit so a missed
 * gate cannot slip through.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fallback with previous, idle, first, gate in one place. */
/* Gives previous when allowed and live else idle when allowed */
/* and live else first when allowed and live else error with one */
/* gate count. Callers reach the gate solely here so every failure */
/* counts once with no missed reject. Placement shares the deadline */
/* source with the tree through the same quantize with no drain */
/* check so warmth stays cheap. */
static __always_inline s32 flow_fallback_cpu(
	const struct task_struct *p, s32 prev_cpu)
{
	s32 idle;
	s32 first;
	if (flow_cpu_ok(p, prev_cpu))
		return prev_cpu;
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (flow_cpu_ok(p, idle))
		return idle;
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (flow_cpu_ok(p, first))
		return first;
	flow_gate_reject();
	return -EINVAL;
}
s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p,
	s32 prev_cpu, u64 wake_flags)
{
	u64 period;
	u64 deadline;
	u32 key;
	s32 here;
	(void)wake_flags;
	period = flow_period_ns(p->scx.weight);
	deadline = flow_deadline_at(flow_now(), period);
	key = veb_quant(deadline);
	if (key >= (u32)FLOW_VEB_U) {
		flow_gate_reject();
		return -EINVAL;
	}
	if (is_migration_disabled(p) || p->nr_cpus_allowed == 1) {
		here = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, here))
			return here;
		return flow_fallback_cpu(p, prev_cpu);
	}
	return flow_fallback_cpu(p, prev_cpu);
}
