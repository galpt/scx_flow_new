// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Every release earns one absolute deadline from the burst predictor
 * else the hint period, and admission holds declared use under ninety
 * five percent before the task joins a queue. Admitted tasks join
 * direct when the target can drain before the deadline, else they join
 * the shared home, so no task waits for a busy CPU while shared room
 * stays open. Missed tasks park in overflow with a miss count and one
 * idle kick and no wait. Pinned tasks rest in overflow with wait set
 * and one idle kick. Exiting tasks run at once on the task CPU with
 * no queue wait and no gate. The gate runs first for all other
 * arrivals, so a stale CPU plus a moved task fails closed with one
 * counter. The predictor average plus deviation shape later deadlines
 * with shift updates from stopping, so short bursts earn tight
 * deadlines with no table walk. The admitted share pairs one add with
 * one drop through the stored value, so a hint change plus a move
 * never drifts the row. The exiting fast path plus one idle helper
 * plus one direct block form the three kick points, so every park
 * meets at most one kick with no storm. A direct preempt needs a margin lead with the owner slice
 * still long, so near ties plus nearly done owners never bounce.
 * Slice expiry paces the rest, so no slice write and no stamp run
 * here. See intf.h for the deadline helpers and dispatch.bpf.c for
 * the single scan.
 *
 * The op splits across enqueue/target, insert, and kick files with
 * the enqueue body here. Each helper stays inline except the kick,
 * which stays noinline with scalar input, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/target.bpf.c"
#include "enqueue/insert.bpf.c"
#include "enqueue/kick.bpf.c"

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	u64 now;
	u64 period;
	u64 deadline;
	u64 share;
	u32 hint;
	u64 avg = 0;
	u64 dev = 0;
	(void)enq_flags;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	/* The gate never runs here, so exiting work stays exempt. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			scx_bpf_dsq_insert(p,
			    (u64)SCX_DSQ_LOCAL_ON | (u64)tgt,
			    (u64)FLOW_QUANTUM_NS, enq_flags);
			tst = flow_cpu((u32)tgt);
			if (tst &&
			    READ_ONCE(tst->running_pid) == 0) {
				scx_bpf_kick_cpu(tgt,
				    SCX_KICK_IDLE);
				__sync_fetch_and_add(
				    &flow_stats.kicks, 1);
			}
			return;
		}
	}
	tctx = flow_get(p);
	sel = p->scx.selected_cpu;
	pinned = flow_task_pinned(p);
	now = flow_now();
	/* Tasks without state park in overflow with an idle kick. */
	/* The kick targets one idle allowed CPU with no preempt, so a */
	/* parked task wakes without a storm. */
	if (!tctx) {
		flow_gate_reject();
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	/* The gate runs before any queue join with fail closed. */
	/* A stale CPU plus a moved task counts one reject and parks in */
	/* overflow with one direct kick. A stale stored share drops */
	/* here too, so a double enqueue never holds two shares. */
	if (!flow_entry_ok(sel, p, 0) && !flow_entry_ok(
	    scx_bpf_task_cpu(p), p, 0)) {
		flow_gate_reject();
		flow_admit_drop_stored(tctx);
		tctx->wait_at = now;
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	/* Pinned tasks rest in overflow with wait set and one idle kick. */
	/* The share walk never runs here, so pinned parks stay cheap. */
	/* A stale stored share drops here too with no new share. */
	if (pinned) {
		flow_admit_drop_stored(tctx);
		tctx->wait_at = now;
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU parks homeless work in overflow with an idle kick. */
	/* A stale stored share drops here too with no new share. */
	if (!flow_cpu_ok(p, cpu)) {
		flow_gate_reject();
		flow_admit_drop_stored(tctx);
		tctx->wait_at = now;
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (tctx->deadline == 0 && tctx->wait_at == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	/* One release plus one predictor period plus one deadline. */
	/* A zero average means no history, so the hint period applies */
	/* with the default when the hint is zero. Later releases add */
	/* average plus deviation with saturation, so short bursts earn */
	/* tight deadlines with no table walk. The hint stores for the */
	/* admission share with no lag, while the predictor shapes only */
	/* the deadline once history exists. A miss on the last release */
	/* counts before the new release, so the miss count tracks wall */
	/* completion past release plus deadline. */
	hint = flow_task_hint(p);
	avg = READ_ONCE(tctx->avg_ns);
	dev = READ_ONCE(tctx->dev_ns);
	if (avg == 0)
		period = flow_task_period(tctx->hint_us ?
		    tctx->hint_us : hint);
	else
		period = flow_pred_period(avg, dev);
	tctx->hint_us = hint;
	/* A stale stored share drops before the miss check, so a double */
	/* enqueue without a stop never holds two shares. The normal pass */
	/* sees zero here with no extra debit. */
	flow_admit_drop_stored(tctx);
	if (tctx->release && tctx->deadline &&
	    flow_missed(tctx->release, tctx->deadline, now)) {
		flow_count_miss(tctx);
		tctx->wait_at = now;
		tctx->release = now;
		tctx->period = period;
		tctx->deadline = flow_pred_deadline(now, avg, dev, hint);
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	tctx->release = now;
	tctx->period = period;
	deadline = flow_pred_deadline(now, avg, dev, hint);
	tctx->deadline = deadline;
	tctx->wait_at = now;
	/* Admission holds declared use under the bound per CPU. */
	/* The share is one slice in the hint period always, so steady */
	/* work keeps a small share while the predictor shapes only the */
	/* deadline. A reject parks in overflow with one idle kick and no */
	/* wait. The added share stores on the task, so the stop drops the */
	/* stored value with no drift on hint change and no wrong CPU */
	/* debit on move. The stored share drops before the miss check */
	/* above, so a double enqueue without a stop never holds two */
	/* shares. */
	share = flow_admit_share(hint);
	if (share && !flow_admit_ok(flow_cpu_admitted((u32)cpu),
	    share)) {
		__sync_fetch_and_add(&flow_stats.rejects, 1);
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (share) {
		flow_admit_add((u32)cpu, share);
		__sync_lock_test_and_set(&tctx->admit_share, share);
		__sync_lock_test_and_set(&tctx->admit_cpu,
		    (u32)cpu);
	}
	__sync_fetch_and_add(&flow_stats.admits, 1);
	/* Direct join when the target drains before the deadline. */
	/* Else the shared home takes the task, node first then machine, */
	/* so no task waits for a busy CPU while shared room stays open. */
	if (flow_cpu_meets((u32)cpu, deadline, now)) {
		flow_local_insert(p, cpu, deadline);
	} else {
		u32 node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES &&
		    (u64)node < nr_node_ids)
			flow_node_insert(p, node, deadline);
		else
			flow_machine_insert(p, deadline);
	}
	/* Idle targets kick at once with no rate window. */
	/* The idle flag clears first so the kick sticks. The pid read */
	/* uses a relaxed load to match the running stores. The single */
	/* direct block holds both the idle plus the preempt kick, so no */
	/* fourth point beyond the three can storm. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 occ_pid;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		u64 occ_deadline;
		u64 margin;
		u64 occ_start;
		u64 occ_end;
		u64 tail;
		if (!st)
			return;
		if (READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* The running pid names the occupant with no curr read. */
		/* A trusted lookup carries the occupant deadline, and a */
		/* missing occupant fails closed with no kick and no count. */
		/* The occupant CPU validates before the compare, so a */
		/* migrated occupant never kicks the wrong CPU. A zero */
		/* occupant deadline means no order yet, so the arrival */
		/* paces with no kick. */
		occ_pid = READ_ONCE(st->running_pid);
		if (occ_pid == 0 || occ_pid == (u32)p->pid)
			return;
		bpf_rcu_read_lock();
		trusted = bpf_task_from_pid(occ_pid);
		if (!trusted) {
			bpf_rcu_read_unlock();
			return;
		}
		if (scx_bpf_task_cpu(trusted) != cpu) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		octx = flow_lookup(trusted);
		if (!octx) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		occ_deadline = READ_ONCE(octx->deadline);
		occ_start = READ_ONCE(octx->run_at);
		if (occ_deadline == 0) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		/* An urgent arrival leads by a margin with the owner slice */
		/* still long, so near ties plus nearly done owners never */
		/* bounce. The margin adds a quarter base slice to the */
		/* arrival with saturation, and the tail needs a quarter */
		/* slice left on the owner, so only a truly earlier arrival */
		/* with work left preempts at once. Equal or later arrivals */
		/* pace at slice expiry with no count. */
		if (!flow_time_before(deadline, occ_deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		margin = flow_sat_add(deadline,
		    (u64)FLOW_PREEMPT_MARGIN_NS);
		if (margin == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (!flow_time_before(margin, occ_deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (occ_start == 0) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		occ_end = flow_sat_add(occ_start,
		    (u64)FLOW_QUANTUM_NS);
		if (occ_end == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		tail = flow_sat_add(now,
		    (u64)FLOW_PREEMPT_TAIL_NS);
		if (tail == (u64)~0ULL) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		if (!flow_time_before(tail, occ_end)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		__sync_fetch_and_add(&flow_stats.kicks, 1);
	}
}
