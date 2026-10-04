// SPDX-License-Identifier: GPL-2.0
/*
 * Performance level helper for the dispatch pass.
 *
 * Holds the per CPU depth check plus the transition only set with no
 * knob and no extra walk. Any own plus local plus node plus running picks
 * max else half, and a steady level makes no call. Sparse nodes fold to
 * zero with no poll. Boost and idle stay
 * paired through one apply entry, so a busy CPU takes max and an idle
 * CPU returns to half with no forgotten deboost. Dispatch reaches the
 * helper through one exit label, so every pass covers the level with
 * no skipped tail. Runs after priority moves plus fail open with the
 * dispatch CPU only and no remote use, so the same CPU proof holds
 * with no extra guard. Old kernels skip with no set, and unknown CPUs
 * skip with no set. The choice stays in the allowlist before the cap,
 * the cap may step outside it within range, so no trap fires. Kicks
 * pull backlog to idle CPUs, so only the dealing CPU takes max.
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
/* Depth probe with own plus local plus node plus running. */
/* Pure read with no set, so a bad read drops with no boost and a */
/* missing queue stays idle. Sparse nodes read zero with no poll. Guards */
/* live here as well as in the set core, so a stale CPU reads idle even */
/* when called apart. An invalid CPU reads idle at once with no poll. */
static __noinline bool flow_perf_busy(s32 cpu)
{
	s32 own;
	s32 local;
	u64 depth = 0;
	struct flow_cpu_state *st;
	/* Unknown CPUs hold no depth, so skip with no poll. */
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	/* Own plus local plus node shape the depth with three polls only and */
	/* no tier prescan, so the pass pays no machine walk. A bad read drops */
	/* with no boost, so a missing queue stays idle. Sparse nodes fold to */
	/* zero with no poll. */
	own = scx_bpf_dsq_nr_queued(flow_local_dsq((u32)cpu));
	if (own > 0)
		depth += (u64)own;
	local = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu);
	if (local > 0)
		depth += (u64)local;
	/* The node queue adds shared work, so a node busy CPU holds max. */
	/* Sparse nodes read zero with no boost and no machine poll. */
	{
		u32 node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES &&
		    (u64)node < nr_node_ids) {
			s32 shared = scx_bpf_dsq_nr_queued(flow_node_dsq(node));
			if (shared > 0)
				depth += (u64)shared;
		}
	}
	/* The running view adds one, so a busy CPU counts its task. */
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		depth += 1;
	return depth > 0;
}
/* Core set with every guard plus the transition only store. */
/* Holds the ksym plus live plus bound plus allowlist plus cap plus */
/* transition checks in one place, so callers cannot split them. The */
/* kfunc check runs first, so old kernels skip with no set. The live */
/* plus bound checks run next with no cap cost, so unknown CPUs skip */
/* with no kfunc poll. The allowlist guards the pre cap choice only, */
/* the cap may step outside it within range, so no trap fires. The */
/* cached last level check holds after the cap, so a steady level makes */
/* no set with one cached compare. Runs after priority moves plus fail */
/* open with the dispatch CPU only and no remote use. */
static __noinline void flow_perf_set(s32 cpu, u32 want)
{
	u32 cap;
	u32 key;
	u32 *last;
	/* Old kernels hold no set, so skip with no call. */
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	/* Unknown CPUs hold no level, so skip with no call and no cap poll. */
	/* Live already covers the bound, the bound check keeps the helper */
	/* safe apart with no caller trust. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	/* The allowlist guards the pre cap choice with half plus max. */
	/* Dead enum by build here with no other level passed, kept fail */
	/* closed so a future caller still traps with no silent level. */
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
/* exit call and deboost cannot be skipped. The cached last level check */
/* in the set keeps steady passes cheap with no extra call. Same CPU */
/* only with no remote use and no tier prescan. */
static __always_inline void flow_perf_update(s32 cpu)
{
	flow_perf_apply(cpu, flow_perf_busy(cpu));
}
