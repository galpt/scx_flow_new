// SPDX-License-Identifier: GPL-2.0
/*
 * Gated drain for the dispatch pass.
 *
 * Throttled parks check the leaf flag with no walk and keep
 * order, so the soft park stays a hard gate. Unthrottled parks
 * move at once with no wait, so pinned work never stalls under
 * throttling. Null, disallowed, failed, unstamped, and throttled
 * visits count one miss each with the miss cap at 4, matching the
 * plain drain. Each visit pays one pid lookup plus one state lookup
 * through the shared gate. Serves overflow only under throttling.
 * Shares the move gate with the plain drain with the park check on.
 * Runs under the caller RCU read lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline u32 flow_drain_gated(s32 cpu,
	u64 dsq, u32 budget, u32 base)
{
	struct task_struct *p;
	u32 moved = 0;
	u32 miss = 0;

	bpf_for_each(scx_dsq, p, dsq, 0) {
		struct flow_task_ctx *tctx;

		if (moved + base >= budget)
			break;
		if (miss >= (u32)FLOW_MISS_CAP)
			break;
		p = bpf_task_from_pid(p->pid);
		if (!p) {
			miss++;
			continue;
		}
		tctx = flow_lookup(p);
		if (!tctx) {
			bpf_task_release(p);
			miss++;
			continue;
		}
		if (!flow_gate_ok(cpu, p, tctx, true)) {
			bpf_task_release(p);
			miss++;
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			bpf_task_release(p);
			moved++;
			miss = 0;
		} else {
			bpf_task_release(p);
			miss++;
		}
	}
	return moved;
}

/* Gated phase over overflow when throttling with narrow inputs. */
/* Takes the budget plus base plus cached limit flag, so the caller */
/* passes one load with no second walk. Returns the gated moves. */
static __noinline u32 flow_phase_gated(s32 cpu, u64 over,
	u32 budget, u32 base, u64 limited)
{
	u32 glim;
	u32 gcap;

	if (!limited)
		return 0;
	if (base >= budget)
		return 0;
	if (scx_bpf_dsq_nr_queued(over) == 0)
		return 0;
	gcap = flow_gated_cap(budget);
	glim = base + gcap;
	if (glim > budget)
		glim = budget;
	if (base >= glim)
		return 0;
	return flow_drain_gated(cpu, over, glim, base);
}
