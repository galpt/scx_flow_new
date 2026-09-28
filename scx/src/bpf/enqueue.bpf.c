// SPDX-License-Identifier: GPL-2.0
/*
 * Enqueue op.
 *
 * Every arrival keys past the later of its virtual runtime and the
 * dispatch floor with one fresh sequence tick, so a long sleep
 * earns no credit and equal deadlines keep arrival order. The
 * effective weight folds the task weight with the hierarchy share
 * over depth 8, and runtime advances virtual time at stop, so
 * order carries weight with no fixed service step. The hierarchy
 * share caches by id with generation validation, and a miss uses
 * base share. Throttled hierarchies park in the ring with lazy
 * refill, and the single timer wakes parks soon. Pinned tasks and
 * foreign policies rest in the ring too with wait set and one idle
 * kick. The key forms before the tree lock with the node fetched
 * beside it, and a null fetch means on tree or in flight, so the
 * arrival refreshes its key fields and still kicks. Kicks run past
 * the unlock with idle first and a strictly earlier preempt on a
 * busy hint, and pinned arrivals never kick a busy CPU. See intf.h
 * for the key helpers and dispatch.bpf.c for the matching drain.
 *
 * The op splits across enqueue/target, insert, and kick files with
 * the enqueue body here. Each helper stays inline except the kick
 * plus the park, which stay noinline with scalar input and no
 * duplicate walk, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include "enqueue/target.bpf.c"
#include "enqueue/insert.bpf.c"
#include "enqueue/kick.bpf.c"

/* Park one arrival in the ring with wait set and one idle kick. */
/* Detaches first, so a re-parked queued task never duplicates */
/* between the tree and the ring. Marks parked membership, so a */
/* stale ring pid never double serves. Counts every ring arrival, */
/* counts the throttle hit when asked, arms the timer, and fails */
/* open to the global queue when the ring fills. Pinned arrivals */
/* skip the throttle count with the same rest. Runs with no lock */
/* held. */
static __noinline void flow_park_arrival(struct task_struct *p,
	struct flow_task_ctx *tctx, u64 now, s32 sel, bool count)
{
	tctx->wait_at = now;
	WRITE_ONCE(tctx->queued, (u8)2);
	__sync_fetch_and_add(&flow_stats.parked, 1);
	if (count) {
		__sync_fetch_and_add(&flow_stats.nr_throttled, 1);
		__sync_lock_test_and_set(&flow_bw_pending, 1);
	}
	if (!flow_park_push((u32)p->pid))
		flow_global_insert(p);
	flow_kick_idle_allowed(p, sel);
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p,
	u64 enq_flags)
{
	struct flow_task_ctx *tctx;
	s32 sel;
	s32 cpu = -1;
	bool pinned = false;
	int policy;
	u32 hier;
	u64 now;
	u64 deadline;
	u64 seq;
	struct flow_node *node;
	struct cgroup *cgrp = NULL;
	u64 cgid = 1;
	/* Exiting tasks run at once on the task CPU with no queue wait. */
	if (p->flags & PF_EXITING) {
		s32 tgt = scx_bpf_task_cpu(p);
		if (flow_cpu_ok(p, tgt)) {
			struct flow_cpu_state *tst;
			flow_local_insert(p, tgt, enq_flags);
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
	/* Pinned plus non normal, batch, idle tasks rest in the ring. */
	/* Only normal plus batch plus idle policies join the deadline */
	/* tree, and realtime stays parked with no key use. */
	/* Ring parks set wait for the backstop, then send one */
	/* idle kick with no preempt. The share walk populates the cache */
	/* with a throttle sync, so the park flag check stays a single */
	/* lookup with no walk. Fail closed, the timer or a later */
	/* kicking enqueue wakes the rest with mask wins. Pinned never */
	/* kicks a busy CPU. */
	if (pinned || (policy != (int)FLOW_POL_NORMAL &&
	    policy != (int)FLOW_POL_BATCH &&
	    policy != (int)FLOW_POL_IDLE)) {
		struct cgroup *pcgrp;
		u64 pcgid;
		u32 phier;
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
		if (flow_load_limited())
			flow_bw_throttled(pcgrp, now);
		flow_cgrp_put(pcgrp);
		flow_park_arrival(p, tctx, now, sel, false);
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
	if (tctx->vruntime == 0 && tctx->wait_at == 0)
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
		/* Throttled hierarchies park in the ring with idle kick. */
		/* Lazy refill runs on the walk, and the tightest pool binds. */
		/* Unlimited walks pass at once with no pool use. Fail closed, */
		/* the single timer wakes parks with mask wins on drain. */
		if (throttled) {
			flow_cgrp_put(cgrp);
			flow_park_arrival(p, tctx, now, sel, true);
			return;
		}
	}
	flow_cgrp_put(cgrp);
	/* Key past the later of runtime and floor with one fresh tick. */
	/* Order carries weight through the stop advance with no step */
	/* here. The floor clamp drops sleeper credit, and the sequence */
	/* keeps equal deadlines first in first out. Moves carry the */
	/* runtime. The share caches above for the stop advance, so the */
	/* hot insert needs no weight math. The key plus the node */
	/* fetch both run before the lock, so the locked section holds */
	/* add only. A null fetch with a live entry means on tree or in */
	/* flight, so the arrival refreshes its deadline and still kicks */
	/* with no insert and no stall. The sequence never refreshes */
	/* here, so a concurrent pop still matches with no live reap. */
	/* A null fetch with no entry means the alloc failed, so the */
	/* arrival fails open to the global queue with no loss. */
	(void)hier;
	deadline = flow_deadline_clamp(tctx->vruntime,
	    READ_ONCE(flow_floor));
	seq = flow_seq_next();
	tctx->deadline = deadline;
	tctx->wait_at = now;
	node = flow_tree_fetch((u32)p->pid);
	if (!node) {
		if (!flow_stash_lookup((u32)p->pid)) {
			flow_global_insert(p);
			flow_kick_idle_allowed(p, sel);
			return;
		}
		goto kick;
	}
	tctx->seq = seq;
	node->deadline = deadline;
	node->seq = seq;
	bpf_spin_lock(&edf_lock);
	bpf_rbtree_add(&edf_tree, &node->rb, flow_edf_less_cb);
	WRITE_ONCE(tctx->queued, (u8)1);
	bpf_spin_unlock(&edf_lock);
kick:
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
		/* Ring parks never preempt, so this busy path still */
		/* skips pinned arrivals that fell through to a key. */
		/* Pinned arrivals send idle kicks only with no compare. */
		if (pinned) {
			flow_kick_idle_allowed(p, sel);
			return;
		}
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
