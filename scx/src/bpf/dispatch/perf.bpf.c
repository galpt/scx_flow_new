// SPDX-License-Identifier: GPL-2.0
/*
 * Performance level helper for the dispatch pass.
 *
 * Holds the per CPU depth check plus the transition only set with
 * no knob and no extra walk. Any local plus running picks max else
 * half, and a steady level makes no call. Boost and idle stay paired
 * through one apply entry, so a busy CPU takes max and an idle CPU
 * returns to half with no forgotten deboost. Dispatch reaches the
 * helper through one exit label, so every pass covers the level with
 * no skipped tail. Runs after ordered moves plus fail open with the
 * dispatch CPU only and no remote use, so the same CPU proof holds
 * with no extra guard. Old kernels skip with no set, and unknown
 * CPUs skip with no set. The choice stays in the allowlist before
 * the cap, the cap may step outside it within range, so no trap
 * fires. Kicks pull backlog to idle CPUs, so only the dealing CPU
 * takes max.
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
/* Depth probe with local plus running and no shared use. */
/* Pure read with no set, so a bad read drops with no boost and a */
/* missing queue stays idle. Guards live in the set core, so the */
/* probe stays small with one duty. An invalid CPU reads bad ids */
/* that drop to idle, then the core skips with no set. */
static __noinline bool flow_perf_busy(s32 cpu)
{
	s32 local;
	u64 depth = 0;
	struct flow_cpu_state *st;
	/* Local shapes the depth with no shared use. */
	/* A bad read drops with no boost, so a missing queue stays idle. */
	local = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu);
	if (local > 0)
		depth += (u64)local;
	/* The running view adds one, so a busy CPU counts its task. */
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		depth += 1;
	return depth > 0;
}
/* Core set with every guard plus the transition only store. */
/* Holds the ksym plus live plus bound plus allowlist plus cap plus */
/* transition checks in one place, so callers cannot split them. */
/* Any local plus running picks max else half with no knob through */
/* through the paired entry, never a bare want. The kfunc check runs */
/* first, so old kernels skip with no set. The live check runs next, */
/* so unknown CPUs skip with no set. The allowlist guards the pre cap */
/* choice only, the cap may step outside it within range, so no trap */
/* fires. The last level check holds, so a steady level makes no set. */
/* Runs after ordered moves plus fail open with the dispatch CPU only */
/* and no remote use. */
static __noinline void flow_perf_set(s32 cpu, u32 want)
{
	u32 cap;
	u32 key;
	u32 *last;
	/* Old kernels hold no set, so skip with no call. */
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	/* Unknown CPUs hold no level, so skip with no call. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* The allowlist guards the pre cap choice with half plus max. */
	/* Dead by build here with no other level, kept fail closed. */
	if (want != (u32)FLOW_CPU_PERF_HALF &&
	    want != (u32)FLOW_CPU_PERF_MAX)
		return;
	/* The cap clamps the want within range, so want stays at or */
	/* below cap. A zero cap skips with no call as backstop only. */
	/* Past the clamp the want may sit outside the allowlist, still */
	/* in range, so the set stays safe. */
	if (bpf_ksym_exists(scx_bpf_cpuperf_cap)) {
		cap = scx_bpf_cpuperf_cap(cpu);
		if (cap == 0)
			return;
		if (want > cap)
			want = cap;
	}
	/* Past bound CPUs hold no row, so skip with no call. Live */
	/* already covers this bound, the check keeps the helper safe */
	/* apart with no caller trust. */
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	key = (u32)cpu;
	last = bpf_map_lookup_elem(&cpu_perf_last, &key);
	if (!last)
		return;
	/* A steady level holds, so skip the set with no call. The store */
	/* uses the atomic to match the pid plus cursor rows with no torn */
	/* write, the load pairs relaxed with no order need. */
	if (READ_ONCE(*last) == want)
		return;
	__sync_lock_test_and_set(last, want);
	scx_bpf_cpuperf_set(cpu, want);
}
/* Paired boost entry with max through the core. */
/* Never call alone from dispatch, always through the apply entry, */
/* so the idle mate cannot be forgotten. */
static __always_inline void flow_perf_boost(s32 cpu)
{
	flow_perf_set(cpu, (u32)FLOW_CPU_PERF_MAX);
}
/* Paired idle entry with half through the core. */
/* Never call alone from dispatch, always through the apply entry, */
/* so every boost path owns its deboost. */
static __always_inline void flow_perf_idle(s32 cpu)
{
	flow_perf_set(cpu, (u32)FLOW_CPU_PERF_HALF);
}
/* Single pairing point with busy picks boost else idle. */
/* Holds the branch once, so callers cannot boost without the idle */
/* mate and the math stays busy to max else half. */
static __always_inline void flow_perf_apply(s32 cpu, bool busy)
{
	if (busy)
		flow_perf_boost(cpu);
	else
		flow_perf_idle(cpu);
}
/* Update one CPU level from per CPU depth with no call on steady. */
/* Pairs the probe with the set through apply, so dispatch needs one */
/* exit call and deboost cannot be skipped. Same CPU only with no */
/* remote use and no tier prescan. */
static __always_inline void flow_perf_update(s32 cpu)
{
	flow_perf_apply(cpu, flow_perf_busy(cpu));
}
