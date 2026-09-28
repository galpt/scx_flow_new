// SPDX-License-Identifier: GPL-2.0
/*
 * Task lifecycle ops.
 *
 * Running claims the segment start from zero and counts the on CPU
 * gauge once per claim, and the claimed domain counts busy for the
 * frequency hint. Stopping claims the start once and charges the
 * raw segment to total runtime, advances virtual time by the cached
 * share, drains the hierarchy pools, withdraws the counted domain,
 * then counts one requeue per runnable stop else one completion.
 * Dequeue marks the tree node detached idempotently with the entry kept,
 * so a later enqueue reuses the node and the reap completes removal.
 * Enable clears the runtime plus the key plus the share cache, and drops
 * a husk entry with no node, so pid reuse never inherits a dead slot.
 * Disable marks detached plus charges a leftover segment at most once
 * when stopping never ran, and exit takes the node with exact token
 * pairing plus the same leftover charge. A null take marks for the
 * reap at the next pop with the entry kept. Release clears a stale
 * running view with no charge. See intf.h for the shared helpers and
 * enqueue.bpf.c for the key choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Domain of one CPU with unknown on miss. */
static __always_inline u32 flow_cpu_llc(s32 cpu)
{
	struct flow_topo *tp;
	if (cpu < 0)
		return 0;
	if (!flow_cpu_live((u32)cpu))
		return 0;
	tp = flow_topo((u32)cpu);
	if (!tp)
		return 0;
	return tp->llc;
}
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u64 now;
	u64 stamp;
	u64 prev;
	bool claimed = false;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (tctx) {
		/* Zero never marks a run, so a zero clock folds to one. */
		/* The claim swaps from zero only, so a second running */
		/* without a stop keeps the first start with no second */
		/* gauge count. The stopping and leftover claims pair */
		/* with no torn stamp. The counted domain stores beside */
		/* the start, so the stop withdraws exact after a move. */
		stamp = now ? now : 1;
		prev = __sync_val_compare_and_swap(&tctx->run_at,
		    0, stamp);
		claimed = prev == 0;
		if (claimed)
			tctx->run_llc = flow_cpu_llc(cpu);
	}
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st)
		__sync_lock_test_and_set(&st->running_pid,
		    (u32)p->pid);
inc:
	/* Count once per claimed start with no double count. */
	/* Tasks without state hold no claim, so they hold no count. */
	/* The domain count pairs with the claim, so every counted */
	/* start meets exactly one withdraw with no drift. */
	if (claimed) {
		__sync_fetch_and_add(&flow_stats.on_cpu, 1);
		if (tctx)
			flow_llc_note_run(tctx->run_llc);
	}
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	struct flow_task_ctx *tctx = flow_lookup(p);
	(void)deq_flags;
	/* Tree tasks never sit in a drain queue, so this fires for */
	/* local plus global removals with the flag already clear. */
	/* The detach stays idempotent with the entry kept for reuse. */
	flow_tree_detach(p, tctx);
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 start;
	u32 eff;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	/* Tasks without state hold no claim, so they hold no count. */
	/* The pid view still clears when owned. */
	if (!tctx) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	/* The start claims with an exchange, so stopping versus disable */
	/* or exit charges once. A zero claim means no counted start, */
	/* so this pass drops with no charge and no gauge move, and */
	/* every counted start meets exactly one gauge drop. */
	/* The owner check gates the pid clear only, the gauge drop */
	/* follows the claim with no owner gate, so a migrated stop */
	/* still pairs. */
	start = __sync_lock_test_and_set(&tctx->run_at, 0);
	if (start == 0) {
		flow_clear_running_if_owner(cpu, (u32)p->pid);
		return;
	}
	if (flow_time_before(now, start))
		delta = 0;
	else
		delta = now - start;
	/* Every segment counts raw time with no weight scaling. */
	/* Order carries weight through the runtime advance below. */
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	/* Runtime advances by the cached share with base on a miss. */
	/* A stale share self corrects at the next enqueue walk, so the */
	/* hot stop pays no walk for exactness it never needs. */
	eff = tctx->cached ? tctx->eweight :
	    (u32)FLOW_WEIGHT_BASE;
	tctx->vruntime = flow_vruntime_advance(tctx->vruntime,
	    delta, flow_eff_weight(p->scx.weight, eff));
	flow_llc_note_stop(tctx->run_llc);
	/* Pools drain by raw time with the tightest pool binding. */
	/* Unlimited hierarchies pass with no charge. The lookup */
	/* carries a reference with a paired release, and a null */
	/* lookup skips the charge with no trap. */
	{
		struct cgroup *cgrp = flow_task_cgrp(p);
		if (cgrp) {
			flow_bw_consume(cgrp, delta);
			flow_cgrp_put(cgrp);
		}
	}
	/* The exchange above already zeroed the start, so disable plus */
	/* exit stay once. */
	/* Owner gates the pid clear only, the gauge drop follows the */
	/* claim with no owner gate. */
	flow_clear_running_if_owner(cpu, (u32)p->pid);
	flow_on_cpu_dec();
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	__sync_fetch_and_add(&flow_stats.completions, 1);
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_stash *stash;
	u32 pid = (u32)p->pid;
	tctx = flow_get(p);
	if (!tctx)
		return;
	/* Fresh tasks hold no runtime, no key, no stamps, and no cache. */
	/* The first enqueue clamps past the floor with no credit. */
	tctx->deadline = 0;
	tctx->vruntime = 0;
	tctx->wait_at = 0;
	tctx->run_at = 0;
	tctx->cgid = 0;
	tctx->seq = 0;
	tctx->eweight = (u32)FLOW_WEIGHT_BASE;
	tctx->run_llc = 0;
	tctx->cached = false;
	tctx->queued = 0;
	tctx->generation = 0;
	/* A husk entry with no node belongs to a dead pid reuse. */
	/* Dropping it lets the first enqueue publish fresh with no */
	/* orphaned take. A slotted entry stays, since disable may */
	/* have parked a live node for reuse. */
	stash = flow_stash_lookup(pid);
	if (stash && READ_ONCE(stash->node) == NULL)
		bpf_map_delete_elem(&node_stor, &pid);
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	s32 cpu = scx_bpf_task_cpu(p);
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The gauge drop follows the claim with no owner gate. */
	/* The detach keeps the entry, so a returning task reuses */
	/* its node with no alloc. */
	flow_charge_leftover(p, tctx);
	flow_tree_detach(p, tctx);
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	struct flow_node *node;
	u32 pid = (u32)p->pid;
	s32 cpu = scx_bpf_task_cpu(p);
	(void)args;
	tctx = flow_lookup(p);
	/* Charge a running segment stopping never saw at most once. */
	/* The gauge drop follows the claim with no owner gate. */
	/* A taken node sits off tree by construction, since every add */
	/* consumes a take with the slot left null, so the entry drops */
	/* plus the node frees with exact pairing and no remove call. */
	/* A null take keeps the entry for the reap, since the node */
	/* flights through a pop with no pointer. */
	flow_charge_leftover(p, tctx);
	node = flow_tree_take(pid);
	if (node) {
		bpf_map_delete_elem(&node_stor, &pid);
		bpf_obj_drop(node);
	} else if (tctx) {
		WRITE_ONCE(tctx->queued, (u8)0);
	}
	flow_clear_running_if_owner(cpu, (u32)p->pid);
}
void BPF_STRUCT_OPS(flow_cpu_release, s32 cpu,
	struct scx_cpu_release_args *args)
{
	(void)args;
	/* Clear the stale running view with no charge. */
	/* The segment still ends through stopping or disable. */
	flow_clear_running(cpu);
}
