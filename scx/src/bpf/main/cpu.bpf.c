// SPDX-License-Identifier: GPL-2.0
/*
 * CPU view helpers for the core.
 *
 * Holds the live plus mask checks plus the running pid and gauge
 * helpers with no charge. Runs inline with no walk, so the verifier
 * stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* True when the id is a live CPU below nr and the bound. */
/* Live means below the nr snapshot at init with no kernel online read. */
/* Hotplug needs a restart with fail closed to park. */
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
/* True when the CPU is live and inside the task mask. */
/* Live is the init snapshot with no hotplug read, so an offlined CPU */
/* past init still reads live here and needs a restart to drain. */
/* Unknown CPUs fail closed to park with mask wins on drain. */
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* Drop the on CPU gauge by one with no wrap and no clear. */
/* Retries the compare and swap to pair every counted start, and a lost */
/* race retries with no silent drop. The bound stays at 32 for the */
/* verifier, and the window is one swap, so 32 covers the worst burst */
/* with no growing leak past it. */
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 32) {
		u64 cur = flow_stats.on_cpu;
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
/* Clear the running pid with a compare and swap loop. */
/* Retries the swap so a concurrent run pairs, and a lost race keeps */
/* the winner with no torn zero. Release carries no pid, so the loop */
/* claims whatever owner it finds. The segment still ends through */
/* stopping or disable with no charge here. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	s32 i;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
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
/* Clear the running pid only when the pid owns it. */
/* Uses one compare and swap, so a stale exit never clears a new */
/* owner after a switch. A zero pid never owns, so it passes. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (pid == 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	__sync_val_compare_and_swap(&st->running_pid, pid, 0);
}
