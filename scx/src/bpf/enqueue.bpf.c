/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Routing and insert, included by main.bpf.c via
 * include.
 *
 * Fresh tasks join with the current mean. Known tasks
 * requeue with a clamped estimate. Tasks with no
 * target wait in the park queue. Inserts use ordered
 * time with the estimate as the key. Tiny bursts on
 * an idle and empty target run at once on the local
 * queue with a fast count. A slight overrun earns one
 * ordered head start with a linger count and no chain.
 * Kicks wake idle targets only.
 */

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 sel;
	s32 cpu = -1;
	bool cpu_valid = false;
	bool is_requeue = false;
	bool is_fresh = false;
	bool need_join = false;
	u64 est = 0;
	u64 tq = (u64)FLOW_TQ_SEED_NS;

	if (enq_flags & SCX_ENQ_REENQ)
		is_requeue = true;
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	if (!tctx) {
		tq = (u64)FLOW_TQ_SEED_NS;
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		/* Park holds the task for a later move. */
		scx_bpf_dsq_insert(p, (u64)FLOW_DSQ_PARK,
		    tq, 0);
		return;
	}
	if (tctx->est_ns == 0)
		is_fresh = true;
	if (tctx->grant_ns == (u64)-1)
		need_join = true;
	/* Tasks that cannot move stay on the current CPU. */
	if (is_migration_disabled(p)) {
		s32 here = scx_bpf_task_cpu(p);

		if (flow_cpu_ok(p, here)) {
			cpu = here;
			cpu_valid = true;
		}
	}
	if (!cpu_valid) {
		if (flow_cpu_ok(p, sel)) {
			cpu = sel;
			cpu_valid = true;
		} else {
			s32 first;

			first = (s32)bpf_cpumask_first(
			    p->cpus_ptr);
			if (flow_cpu_ok(p, first)) {
				cpu = first;
				cpu_valid = true;
			}
		}
	}
	if (!cpu_valid) {
		/* No target, park for a later move. */
		tq = (u64)FLOW_TQ_SEED_NS;
		if (is_fresh) {
			tctx->est_ns = tq;
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		} else if (is_requeue) {
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		} else if (need_join) {
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		}
		tctx->grant_ns = tq;
		tctx->owner = FLOW_OWNER_NONE;
		tctx->linger = 0;
		scx_bpf_dsq_insert(p, (u64)FLOW_DSQ_PARK,
		    tq, 0);
		return;
	}
	st = flow_cpu((u32)cpu);
	tq = st ? st->tq_ns : (u64)FLOW_TQ_SEED_NS;
	if (tq == 0)
		tq = (u64)FLOW_TQ_SEED_NS;
	if (is_fresh)
		est = tq;
	else
		est = flow_clamp_est(tctx->est_ns);
	tctx->est_ns = est;
	if (need_join) {
		flow_join_cpu((u32)cpu, est);
		tctx->owner = (u32)cpu;
		if (is_fresh)
			__sync_fetch_and_add(&flow_stats.inserts,
			    1);
		else
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
		st = flow_cpu((u32)cpu);
		tq = st ? st->tq_ns : tq;
		if (tq == 0)
			tq = (u64)FLOW_TQ_SEED_NS;
	} else {
		tctx->owner = (u32)cpu;
		if (is_requeue)
			__sync_fetch_and_add(&flow_stats.requeues,
			    1);
	}
	tctx->grant_ns = tq;
	/* Tiny bursts on an idle and empty target run local. */
	if ((u64)FLOW_GATE_FAST && flow_fast_ok(est, tq)) {
		u64 dsq = flow_dsq_for_cpu((u32)cpu);

		if (scx_bpf_dsq_nr_queued(dsq) == 0 &&
		    scx_bpf_dsq_nr_queued(
			(u64)SCX_DSQ_LOCAL_ON | (u64)cpu) == 0 &&
		    scx_bpf_test_and_clear_cpu_idle(cpu)) {
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu,
			    tq, 0);
			__sync_fetch_and_add(
			    &flow_stats.fast_hits, 1);
			if (flow_cpu_ok(p, cpu)) {
				scx_bpf_kick_cpu(cpu,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	/* A pending boost earns one ordered head start. */
	if ((u64)FLOW_GATE_LINGER && tctx->linger != 0) {
		u64 dsq = flow_dsq_for_cpu((u32)cpu);

		scx_bpf_dsq_insert_vtime(p, dsq, tq, 0, 0);
		__sync_fetch_and_add(&flow_stats.linger_boosts,
		    1);
		if ((u64)FLOW_GATE_CUTS) {
			if (scx_bpf_dsq_nr_queued(dsq) > 1)
				return;
		}
		if (flow_cpu_ok(p, cpu)) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks,
			    1);
		}
		return;
	}
	tctx->linger = 0;
	/* Ordered queue keeps short estimates first. */
	/* Kicks run only when the queue was empty. */
	{
		u64 dsq = flow_dsq_for_cpu((u32)cpu);

		scx_bpf_dsq_insert_vtime(p, dsq, tq, est, 0);
		if ((u64)FLOW_GATE_CUTS &&
		    scx_bpf_dsq_nr_queued(dsq) > 1)
			return;
		if (flow_cpu_ok(p, cpu)) {
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
		}
	}
}
