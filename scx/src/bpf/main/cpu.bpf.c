// SPDX-License-Identifier: GPL-2.0
/*
 * CPU view plus entry gate for the flow core.
 *
 * Holds the live, mask checks, running pid helpers,
 * the universal entry gate. The gate runs first in every op.
 * Bad CPUs plus bad tasks fail closed with one counter. Shared counters pair
 * volatile reads with atomic updates so observers see steady values.
 * Gauge compare and swap loops give up as benign with the next op
 * retrying the same value so counters stay best effort.
 * Runs inline for a small verifier footprint.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* CPU row with live plus lookup in one place. */
/* Gives zero on unknown CPUs so callers skip with no set. */
/* Keeps pid clear paths paired through one entry. */
static __always_inline struct flow_cpu_state *flow_cpu_state_for(
	s32 cpu)
{
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	return flow_cpu((u32)cpu);
}
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 16) {
		u64 cur = READ_ONCE(flow_stats.on_cpu);
		u64 nxt;
		u64 old;
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
	}
}
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st = flow_cpu_state_for(cpu);
	s32 i;
	if (!st)
		return;
	bpf_for(i, 0, 4) {
		u32 cur = READ_ONCE(st->running_pid);
		u32 old;
		if (cur == 0)
			break;
		old = __sync_val_compare_and_swap(
		    &st->running_pid, cur, 0);
		if (old == cur)
			break;
	}
}
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (pid == 0)
		return;
	st = flow_cpu_state_for(cpu);
	if (!st)
		return;
	__sync_val_compare_and_swap(&st->running_pid, pid, 0);
}
static __always_inline bool flow_entry_ok(s32 cpu,
	const struct task_struct *p, u64 dsq)
{
	if (!p)
		return false;
	if (cpu >= 0 && !flow_cpu_live((u32)cpu))
		return false;
	if (cpu >= 0 && !bpf_cpumask_test_cpu((u32)cpu,
	    p->cpus_ptr))
		return false;
	if (dsq && !flow_dsq_valid(dsq))
		return false;
	return true;
}
static __always_inline void flow_gate_reject(void)
{
	u64 cur = READ_ONCE(flow_stats.gate_rejects);
	if (cur == (u64)~0ULL)
		return;
	__sync_fetch_and_add(&flow_stats.gate_rejects, 1);
}
