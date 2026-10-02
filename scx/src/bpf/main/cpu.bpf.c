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
	/* Nr ids never exceeds the build bound with init failing over */
	/* bound, so the ids check alone implies the bound with no */
	/* extra branch while lookups keep their own bound for safety. */
	if ((u64)cpu >= nr_cpu_ids)
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
/* Mask check for dispatch inner scans with live proven outside. */
/* Holds the mask test solely with no live plus null plus cpu branch, */
/* so the per element cost stays one test after the pass proves live */
/* once at entry. Callers prove live plus non null iterator before the */
/* scan through the dispatch entry plus the iterator guarantee, so the */
/* test never sees a bad pointer or CPU here. */
static __always_inline bool flow_mask_ok(s32 cpu,
	const struct task_struct *p)
{
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
static __always_inline void flow_gate_reject(void)
{
	u64 cur = READ_ONCE(flow_stats.gate_rejects);
	if (cur == (u64)~0ULL)
		return;
	__sync_fetch_and_add(&flow_stats.gate_rejects, 1);
}
/* Backlog check with the shared tail depth in one place. */
/* Gives true when the tail holds work, so held parks plus steps stay */
/* base with hot stays still leading before idle while warm stays */
/* follow idle. Empty keeps grown slices with no extra threshold, so */
/* light load still spreads and grows slices. */
static __always_inline bool flow_saturated(void)
{
	return scx_bpf_dsq_nr_queued(flow_overflow_dsq()) != 0;
}
/* Headroom check with queued depth plus running in one place. */
/* Gives true solely when the CPU holds no queued task and no running */
/* task, so warmth never stacks onto an overloaded owner. Reuses the */
/* same depth plus running views as the level probe with no new map. */
/* A bad depth read fails closed with no headroom. */
static __always_inline bool flow_cpu_headroom(s32 cpu)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	if (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu) != 0)
		return false;
	st = flow_cpu_state_for(cpu);
	if (!st)
		return false;
	return READ_ONCE(st->running_pid) == 0;
}
/* Least loaded allowed CPU with a bounded scan in one place. */
/* Scans at most sixteen CPU ids with early exit on the first idle */
/* allowed CPU, so large machines never pay a full walk while small */
/* hosts still see every CPU. Load folds queued depth plus running */
/* plus the admitted sum with queued plus running weighed above the */
/* ledger, reusing the same views with no new map. Skips disallowed */
/* plus unreadable CPUs with no state. Gives the least loaded CPU or */
/* negative when none stays allowed. Noinline so both placement paths */
/* verify once apart from their callers. */
static __noinline s32 flow_least_loaded(const struct task_struct *p)
{
	s32 best = -1;
	u64 best_load = (u64)~0ULL;
	u64 lim;
	int i;
	if (!p)
		return -1;
	lim = nr_cpu_ids;
	if (lim > 16)
		lim = 16;
	if (lim == 0)
		return -1;
	bpf_for(i, 0, 16) {
		s32 cpu = (s32)i;
		s32 q;
		struct flow_cpu_state *st;
		u32 key;
		u64 *adm;
		u64 held = 0;
		u64 load;
		if ((u64)i >= lim)
			break;
		if (!bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr))
			continue;
		q = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
		    (u64)(u32)cpu);
		if (q < 0)
			continue;
		st = flow_cpu((u32)cpu);
		if (!st)
			continue;
		load = (u64)q;
		if (READ_ONCE(st->running_pid) != 0)
			load += 1;
		load *= 1024;
		key = (u32)cpu;
		adm = bpf_map_lookup_elem(&admitted_stor, &key);
		if (adm)
			held = READ_ONCE(*adm);
		if (held > 1024)
			held = 1024;
		load += held;
		if (load < best_load) {
			best_load = load;
			best = cpu;
		}
		if (load == 0)
			break;
	}
	return best;
}
