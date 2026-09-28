// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Every arrival earns one key past the later of runtime, last
 * deadline, now, and the served floor, with a slack capped at
 * twice the quantum that shrinks as the effective weight grows. The effective weight folds the task weight with
 * the hierarchy share over depth 8, so a task under a light
 * parent waits longer. The hierarchy share caches by id with
 * generation validation, and a miss uses base share. Throttled
 * hierarchies park in overflow with no preempt kick and lazy refill, and
 * the single timer wakes parks soon. The task joins its target
 * deadline queue, so old kernels keep working. Pinned tasks and
 * foreign policies rest in overflow with wait set and one idle kick.
 * Overflow and global parks kick one idle allowed CPU only, so no
 * stall with no preempt storm. A busy target kicks only for
 * a strictly earlier deadline, and pinned arrivals never kick a
 * busy CPU. Slice expiry paces the rest, so no slice write and no
 * stamp run here. See intf.h for the key helpers and
 * dispatch.bpf.c for the matching drain order.
 *
 * The op splits across enqueue/target, insert, and kick files with
 * the enqueue body here. Each helper stays inline except the kick,
 * which stays noinline with scalar input and no duplicate walk, so
 * the verifier stays small.
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
	int policy;
	u32 hier;
	u32 eff;
	u64 now;
	u64 deadline;
	struct cgroup *cgrp = NULL;
	u64 cgid = 1;
	(void)enq_flags;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
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
	policy = p->policy;
	now = flow_now();
	/* Tasks without state keep the kernel global queue with an idle kick. */
	/* Homeless tasks without a route count here too, the name stays */
	/* for the wire with no split. The kick targets one idle allowed */
	/* CPU with no preempt, so a parked global wakes without a storm. */
	if (!tctx) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		flow_global_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	/* Pinned plus non normal, batch, idle tasks rest in overflow. */
	/* Only normal plus batch plus idle policies join the deadline */
	/* queues, and realtime stays ordered with no deadline use. */
	/* Overflow parks set wait for the gated backstop, then send one */
	/* idle kick with no preempt. The share walk populates the cache */
	/* with a throttle sync, so the gated flag check stays a single */
	/* lookup with no walk. Fail closed, the timer or a later */
	/* kicking enqueue wakes the rest with mask wins. Pinned never */
	/* kicks a busy CPU. */
	if (pinned || (policy != (int)FLOW_POL_NORMAL &&
	    policy != (int)FLOW_POL_BATCH &&
	    policy != (int)FLOW_POL_IDLE)) {
		u64 pcgid;
		u32 phier;
		struct cgroup *pcgrp;
		tctx->wait_at = now;
		pcgrp = flow_task_cgrp(p);
		pcgid = flow_cgrp_id(pcgrp);
		if (tctx->cached && tctx->cgid == pcgid &&
		    tctx->generation == (u16)flow_load_gen()) {
			phier = tctx->eweight;
		} else {
			phier = flow_hier_weight(pcgrp);
			tctx->cgid = pcgid;
			tctx->eweight = phier;
			tctx->generation = (u16)flow_load_gen();
			tctx->cached = true;
		}
		if (flow_load_limited() && flow_bw_throttled(pcgrp, now)) {
			/* A cold throttle parks with pending armed, so the */
			/* timer refills plus wakes with no stall. The read */
			/* runs before the write, so a set flag stays clean. */
			if (!flow_load_pending())
				__sync_lock_test_and_set(&flow_bw_pending,
				    1);
		}
		flow_cgrp_put(pcgrp);
		flow_over_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	cpu = flow_pick_target(p, sel);
	/* No live CPU keeps the kernel global queue with an idle kick. */
	/* Homeless tasks without a route count here too, the name stays */
	/* for the wire with no split. The kick targets one idle allowed */
	/* CPU with no preempt, so a parked global wakes without a storm. */
	if (!flow_cpu_ok(p, cpu)) {
		__sync_fetch_and_add(&flow_stats.enq_no_tctx, 1);
		tctx->wait_at = now;
		flow_global_insert(p);
		flow_kick_idle_allowed(p, sel);
		return;
	}
	if (tctx->deadline == 0 && tctx->wait_at == 0)
		__sync_fetch_and_add(&flow_stats.inserts, 1);
	/* Hierarchy share with cache and generation validation. */
	/* A cached id with current generation skips the depth walk. */
	/* A miss fuses share plus throttle in one depth-8 walk with */
	/* hint once, so the hot path pays one walk instead of two. */
	/* The task weight folds at use, so nice changes need no drop. */
	/* The generation compares only the low bits, so 64k bumps wrap. */
	/* Moves clear the cache and share changes bump the generation, */
	/* so a wrap needs 64k bumps with no move to falsely hit. */
	/* The hierarchy carries a reference with a paired release. */
	/* The cold pinned path above keeps two walks with no hot use. */
	cgrp = flow_task_cgrp(p);
	cgid = flow_cgrp_id(cgrp);
	{
		bool throttled = false;
		if (tctx->cached && tctx->cgid == cgid &&
		    tctx->generation == (u16)flow_load_gen()) {
			hier = tctx->eweight;
			if (flow_load_limited())
				throttled = flow_bw_throttled(cgrp, now);
		} else {
			throttled = flow_hier_checked(cgrp, now, &hier);
			tctx->cgid = cgid;
			tctx->eweight = hier;
			tctx->generation = (u16)flow_load_gen();
			tctx->cached = true;
		}
		/* Throttled hierarchies park in overflow with no kick. */
		/* Lazy refill runs on the walk, and the tightest pool binds. */
		/* Unlimited walks pass at once with no pool use. Fail closed, */
		/* the single timer wakes parks with mask wins on drain. */
		/* Throttled ns counts quanta at 1ms per hit with no wall use, */
		/* and nr throttled plus parked count the same hits. The names */
		/* stay for the wire with the quantum semantic documented. */
		if (throttled) {
			tctx->wait_at = now;
			flow_over_insert(p);
			__sync_fetch_and_add(&flow_stats.throttled_ns,
			    (u64)FLOW_QUANTUM_NS);
			__sync_fetch_and_add(&flow_stats.nr_throttled, 1);
			__sync_fetch_and_add(&flow_stats.parked, 1);
			if (!flow_load_pending())
				__sync_lock_test_and_set(&flow_bw_pending,
				    1);
			flow_cgrp_put(cgrp);
			return;
		}
	}
	flow_cgrp_put(cgrp);
	/* One key past the later of runtime, last deadline, now, and floor. */
	/* The effective weight folds task plus hierarchy through the */
	/* slack, so a long sleep earns no credit and a back to back */
	/* arrival queues behind its own last key. Moves carry the */
	/* deadline plus the runtime. Only the open path keys here, */
	/* parks keep no key use. */
	eff = flow_eff_weight(p->scx.weight, hier);
	{
		u64 base = flow_time_max(READ_ONCE(tctx->vruntime), now);
		u64 floor = flow_floor_read((u32)cpu);
		u64 slack = flow_deadline_slack(eff);
		base = flow_time_max(base, tctx->deadline);
		deadline = flow_deadline_key(base, floor, slack);
	}
	tctx->deadline = deadline;
	tctx->wait_at = now;
	flow_vtime_insert(p, cpu, deadline);
	/* Idle targets kick at once with no rate window. */
	/* The idle flag clears first so the kick sticks. The pid read */
	/* uses a relaxed load to match the running stores. */
	{
		struct flow_cpu_state *st = flow_cpu((u32)cpu);
		u32 occ_pid;
		struct task_struct *trusted;
		struct flow_task_ctx *octx;
		if (!st)
			return;
		if (READ_ONCE(st->running_pid) == 0) {
			scx_bpf_test_and_clear_cpu_idle(cpu);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			__sync_fetch_and_add(&flow_stats.kicks, 1);
			return;
		}
		/* Pinned rests in overflow above with no kick, so this busy */
		/* path sees open tasks only with no pinned check. */
		/* The running pid names the occupant with no curr read. */
		/* A trusted lookup carries the occupant deadline, and a */
		/* missing occupant fails closed with no kick and no count. */
		/* The occupant CPU validates before the compare, so a */
		/* migrated occupant never kicks the wrong CPU. A zero */
		/* occupant deadline means no order yet, so the arrival */
		/* paces with no kick. Fail closed exits pace with no */
		/* count, and only the decision exit counts one skip, so */
		/* the hot path pays one global store at most. */
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
		if (octx->deadline == 0) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			return;
		}
		/* A strictly earlier deadline kicks at once. */
		/* Equal or later deadlines pace at slice expiry with one */
		/* skip count at this decision exit only. */
		if (flow_time_before(deadline, octx->deadline)) {
			bpf_task_release(trusted);
			bpf_rcu_read_unlock();
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			__sync_fetch_and_add(
			    &flow_stats.preempt_kicks, 1);
			return;
		}
		bpf_task_release(trusted);
		bpf_rcu_read_unlock();
		__sync_fetch_and_add(&flow_stats.preempt_skipped, 1);
	}
}
