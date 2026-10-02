// SPDX-License-Identifier: GPL-2.0
/*
 * Select CPU op for the flow core.
 *
 * Proposes one CPU with deadline driven placement. The op derives one
 * deadline from weight derived period plus now then quantizes to one
 * key with the same quantize as the tree so placement shares the order
 * source with dispatch. Hot stays keep the last CPU first with
 * headroom so steady work stays, else idle spreads wakeups with no
 * scan, else warm stays keep the last CPU with headroom, else the
 * least loaded allowed CPU from a bounded scan with early exit on
 * idle, else the first allowed live CPU. Stale
 * masks fail closed with an error and one gate count so callers never
 * run on a stale CPU. The core owns admit with per CPU rows and the
 * core proposes solely through the selected CPU so rejects park with
 * no run. Dispatch order stays least key then deadline with no change.
 * The core keeps mask wins and progress. One fallback helper pairs
 * the hot, idle, warm, least, first checks with the gate count
 * through one exit so a missed gate cannot slip through.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Fallback with hot, idle, warm, least, first, gate in one place. */
/* Hot stays keep the last CPU first with headroom so steady work */
/* stays, else idle spreads wakeups with no scan, else warm stays */
/* keep the last CPU with headroom, else the least loaded allowed */
/* CPU from a bounded scan with early exit on idle else first when */
/* allowed and live else error with one gate count. Warmth needs */
/* headroom so a repeat never stacks onto an overloaded owner, and */
/* warm loses when an idle CPU exists since idle runs before warm. */
/* The scan folds idle so no repeat waits behind a busy owner when */
/* an idle CPU stays free. Callers reach the gate solely here so */
/* every failure counts once with no missed reject. Placement shares */
/* the deadline source with the tree through the same quantize with */
/* no drain check so stays stay cheap. Idle stays BPF only with no */
/* mirror, since the idle pick needs the live mask with no replay. */
static __always_inline s32 flow_fallback_cpu(
	const struct task_struct *p, s32 prev_cpu)
{
	s32 idle;
	s32 least;
	s32 first;
	struct flow_task_ctx *fctx;
	u32 packed = 0;
	u32 warmth = 0;
	s32 warm_cpu = -1;
	(void)prev_cpu;
	fctx = flow_lookup((struct task_struct *)p);
	if (fctx)
		packed = READ_ONCE(fctx->exhaust);
	warmth = flow_warmth_get(packed);
	warm_cpu = flow_warm_cpu_get(packed);
	/* Hot stays before idle so steady work keeps its CPU with */
	/* headroom and never stacks when busy. */
	if (warmth >= (u32)FLOW_HOT && warm_cpu >= 0 &&
	    flow_cpu_ok(p, warm_cpu) &&
	    flow_cpu_headroom(warm_cpu))
		return warm_cpu;
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (flow_cpu_ok(p, idle))
		return idle;
	/* Warm stays after idle so one cold wakeup still spreads while */
	/* a warm repeat keeps its CPU with headroom. */
	if (warmth >= (u32)FLOW_WARM && warmth < (u32)FLOW_HOT &&
	    warm_cpu >= 0 && flow_cpu_ok(p, warm_cpu) &&
	    flow_cpu_headroom(warm_cpu))
		return warm_cpu;
	least = flow_least_loaded(p);
	if (least >= 0 && flow_cpu_ok(p, least))
		return least;
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
