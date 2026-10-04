// SPDX-License-Identifier: GPL-2.0
/*
 * Preempt plus idle kick for the enqueue pass.
 *
 * Holds the strict one kick per wait rule with lead plus tail plus
 * eligibility. An eligible arrival leads the occupant by the margin
 * with more than the tail left on the owner, so near ties plus nearly
 * done owners never bounce while one kick per wait stays with no storm.
 * Every hold counts in preempt skipped with no missing fill. The four
 * kick points share this gate with no extra sender. Runs under the
 * caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when one arrival strictly preempts with margin plus tail. */
/* The arrival must lead the occupant strictly with the margin also */
/* strictly before, so near ties never bounce. The owner must have */
/* started with remaining slice strictly past the tail, so nearly done */
/* owners finish instead of taking a kick. */
static __always_inline bool flow_preempt_wants(u64 arrival,
	u64 occupant, u64 now, u64 occ_start)
{
	u64 margin;
	u64 occ_end;
	u64 tail;
	if (arrival == 0 || arrival == (u64)~0ULL)
		return false;
	if (occupant == 0)
		return false;
	if (!flow_time_before(arrival, occupant))
		return false;
	margin = flow_sat_add(arrival, (u64)FLOW_PREEMPT_MARGIN_NS);
	if (margin == (u64)~0ULL)
		return false;
	if (!flow_time_before(margin, occupant))
		return false;
	if (occ_start == 0)
		return false;
	occ_end = flow_sat_add(occ_start, (u64)FLOW_QUANTUM_NS);
	if (occ_end == (u64)~0ULL)
		return false;
	tail = flow_sat_add(now, (u64)FLOW_PREEMPT_TAIL_NS);
	if (tail == (u64)~0ULL)
		return false;
	if (!flow_time_before(tail, occ_end))
		return false;
	return true;
}
/* Kick one idle allowed CPU for tier waits with strict one kick at most. */
/* Tries the selected CPU first, then the kernel idle pick, then the */
/* first allowed live CPU. Kicks only when the target runs nothing, with */
/* the idle flag cleared first so the kick sticks. Never sends a preempt */
/* kick, so tier waits stay idle only. */
static __noinline void flow_kick_idle_allowed(
	const struct task_struct *p, s32 sel)
{
	s32 idle;
	s32 first;
	struct flow_cpu_state *st;
	struct flow_task_ctx *tctx;
	u64 vr = 0;
	s32 lag = 0;
	bool has_ctx = false;
	tctx = flow_lookup((struct task_struct *)p);
	if (tctx) {
		vr = READ_ONCE(tctx->vruntime);
		lag = READ_ONCE(tctx->vlag);
		has_ctx = true;
	}
	if (flow_cpu_ok(p, sel)) {
		st = flow_cpu((u32)sel);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			if (has_ctx &&
			    !flow_eligible(vr, READ_ONCE(st->min_vruntime),
			        lag)) {
				flow_count_preempt_skip();
				return;
			}
			scx_bpf_test_and_clear_cpu_idle(sel);
			scx_bpf_kick_cpu(sel, SCX_KICK_IDLE);
			flow_count_kick();
			return;
		}
	}
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0 && flow_cpu_ok(p, idle)) {
		st = flow_cpu((u32)idle);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			if (has_ctx &&
			    !flow_eligible(vr, READ_ONCE(st->min_vruntime),
			        lag)) {
				flow_count_preempt_skip();
				return;
			}
			scx_bpf_test_and_clear_cpu_idle(
			    (s32)idle);
			scx_bpf_kick_cpu((s32)idle,
			    SCX_KICK_IDLE);
			flow_count_kick();
			return;
		}
	}
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (first >= 0 && flow_cpu_ok(p, first)) {
		st = flow_cpu((u32)first);
		if (st &&
		    READ_ONCE(st->running_pid) == 0) {
			if (has_ctx &&
			    !flow_eligible(vr, READ_ONCE(st->min_vruntime),
			        lag)) {
				flow_count_preempt_skip();
				return;
			}
			scx_bpf_test_and_clear_cpu_idle(first);
			scx_bpf_kick_cpu(first, SCX_KICK_IDLE);
			flow_count_kick();
		}
	}
}
