// SPDX-License-Identifier: GPL-2.0
/*
 * Tail phases for the dispatch pass.
 *
 * The own queue moves first with the header cap, then the kernel
 * global plus the shared overflow tail move with a shared cap at
 * 4. Overflow drains here only when no hierarchy is limited, so a
 * throttled park never bypasses. Each phase takes scalars only
 * with no struct pass and verifies once. Runs under the caller
 * RCU read lock with a single outer section in dispatch.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Own phase with narrow inputs. Returns the own moves. */
/* Admitted work moves with the shared gate and no park check. */
static __noinline u32 flow_phase_own(s32 cpu, u64 own_dsq,
	u32 budget, u32 base)
{
	u32 lim;

	if (base >= budget)
		return 0;
	if (scx_bpf_dsq_nr_queued(own_dsq) == 0)
		return 0;
	lim = base + flow_own_cap(budget);
	if (lim > budget)
		lim = budget;
	if (base >= lim)
		return 0;
	return flow_drain_one(cpu, own_dsq, lim, base, false);
}

/* Global phase with narrow inputs. Returns the global moves. */
/* Homeless tasks without state move fail open with mask wins. */
static __noinline u32 flow_phase_global(s32 cpu, u32 lim,
	u32 base)
{
	if (base >= lim)
		return 0;
	if (scx_bpf_dsq_nr_queued((u64)SCX_DSQ_GLOBAL) == 0)
		return 0;
	return flow_drain_one(cpu, (u64)SCX_DSQ_GLOBAL, lim, base, true);
}

/* Overflow phase with narrow inputs. Takes the shared limit plus */
/* the cached limit flag, so the caller passes one load with no */
/* second walk. Admitted parks move with the shared gate and no */
/* park check, since no limit means no flag use. Returns the */
/* overflow moves. */
static __noinline u32 flow_phase_overflow(s32 cpu, u64 over,
	u32 lim, u32 base, u64 limited)
{
	if (base >= lim)
		return 0;
	if (limited)
		return 0;
	if (scx_bpf_dsq_nr_queued(over) == 0)
		return 0;
	return flow_drain_one(cpu, over, lim, base, false);
}
