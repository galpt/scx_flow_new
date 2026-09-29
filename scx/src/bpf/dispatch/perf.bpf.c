// SPDX-License-Identifier: GPL-2.0
/*
 * Performance level helper for the dispatch pass.
 *
 * Holds the queue depth check plus the transition only set with
 * no knob and no extra walk. More than one runnable picks max
 * else half, and a steady level makes no call. Runs after the
 * caller lock with the dispatch CPU only and no remote use, so
 * the same CPU proof holds with no extra guard. Old kernels skip
 * with no call, and unknown CPUs skip with no call. Levels stay
 * in the allowlist with a cap clamp, so no trap fires.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Last level per CPU with no call on steady. */
/* Holds one level per CPU, so a repeat level skips the set. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_perf_last SEC(".maps");
/* Update one CPU level from queue depth with no call on steady. */
/* More than one runnable picks max else half with the running */
/* view plus own plus local plus global plus overflow. The kfunc */
/* check runs first, so old kernels skip with no call. The live */
/* check runs next, so unknown CPUs skip with no call. The */
/* allowlist holds plus the cap clamps, so no trap fires. The last */
/* level check holds, so a steady level makes no call. Runs after */
/* the caller lock with the dispatch CPU only and no remote use. */
static __noinline void flow_perf_update(s32 cpu)
{
	s32 own;
	s32 local;
	s32 global;
	s32 over;
	u64 depth = 0;
	u32 want;
	u32 cap;
	u32 key;
	u32 *last;
	struct flow_cpu_state *st;
	/* Old kernels hold no set, so skip with no call. */
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	/* Unknown CPUs hold no level, so skip with no call. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* Own plus local plus global plus overflow shape the depth. */
	/* A missing queue reads zero, so a bad read drops with no boost. */
	own = scx_bpf_dsq_nr_queued(flow_vtime_dsq((u32)cpu));
	if (own > 0)
		depth += (u64)own;
	local = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu);
	if (local > 0)
		depth += (u64)local;
	global = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_GLOBAL);
	if (global > 0)
		depth += (u64)global;
	over = scx_bpf_dsq_nr_queued(flow_overflow_dsq());
	if (over > 0)
		depth += (u64)over;
	/* The running view adds one, so a busy CPU counts its task. */
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		depth += 1;
	/* More than one runnable picks max else half with no knob. */
	if (depth > 1)
		want = (u32)FLOW_CPU_PERF_MAX;
	else
		want = (u32)FLOW_CPU_PERF_HALF;
	/* The allowlist holds half plus max with no other level. */
	if (want != (u32)FLOW_CPU_PERF_HALF &&
	    want != (u32)FLOW_CPU_PERF_MAX)
		return;
	/* The cap clamps the want, so a small CPU never overasks. */
	if (bpf_ksym_exists(scx_bpf_cpuperf_cap)) {
		cap = scx_bpf_cpuperf_cap(cpu);
		if (cap == 0)
			return;
		if (want > cap)
			want = cap;
	}
	/* Past bound CPUs hold no row, so skip with no call. */
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	key = (u32)cpu;
	last = bpf_map_lookup_elem(&cpu_perf_last, &key);
	if (!last)
		return;
	/* A steady level holds, so skip the set with no call. */
	if (READ_ONCE(*last) == want)
		return;
	__sync_lock_test_and_set(last, want);
	scx_bpf_cpuperf_set(cpu, want);
}
