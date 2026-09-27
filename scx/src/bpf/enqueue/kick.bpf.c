// SPDX-License-Identifier: GPL-2.0
/*
 * Idle kick for the enqueue pass.
 *
 * Holds the one idle allowed kick for overflow and global parks with
 * no preempt. Outlined to keep enqueue small with no duplicate walk.
 * Runs under the caller with no lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Kick one idle allowed CPU for overflow or global parks. */
/* Tries the kernel idle pick first, then the first allowed live CPU. */
/* Kicks only when the target runs nothing, with the idle flag cleared */
/* first so the kick sticks. Never sends a preempt kick, so pinned */
/* parks stay idle only. A kick miss stays fail closed with mask wins */
/* on drain and the timer or a later kicking enqueue wakes the park. */
static __noinline void flow_kick_idle_allowed(
	const struct task_struct *p)
{
	s32 idle;
	s32 first;
	struct flow_cpu_state *st;
	idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (idle >= 0 && flow_cpu_ok(p, idle)) {
		st = flow_cpu((u32)idle);
		if (st &&
		    __sync_fetch_and_add(&st->running_pid,
		    0) == 0) {
			scx_bpf_test_and_clear_cpu_idle(
			    (s32)idle);
			scx_bpf_kick_cpu((s32)idle,
			    SCX_KICK_IDLE);
			__sync_fetch_and_add(
			    &flow_stats.kicks, 1);
			return;
		}
	}
	first = (s32)bpf_cpumask_first(p->cpus_ptr);
	if (first >= 0 && flow_cpu_ok(p, first)) {
		st = flow_cpu((u32)first);
		if (st &&
		    __sync_fetch_and_add(&st->running_pid,
		    0) == 0) {
			scx_bpf_test_and_clear_cpu_idle(first);
			scx_bpf_kick_cpu(first, SCX_KICK_IDLE);
			__sync_fetch_and_add(
			    &flow_stats.kicks, 1);
		}
	}
}
