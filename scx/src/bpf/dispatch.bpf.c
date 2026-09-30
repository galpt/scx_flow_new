// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the flow core.
 *
 * Moves admitted tasks in tree order up to sixteen per pass.
 * The pass starts from the least key and follows successors with
 * at most twenty key probes so one pass never scans the tail more
 * than twenty times. Twenty covers sixteen moves plus four skip
 * slack so full batches never starve on sparse keys. Empty keys
 * skip through counts with no tail
 * scan and drained keys advance at once so fruitless rescans never
 * run. Each key scans the overflow tail and moves the first admitted
 * task with sequence, liveness, affinity checks. Duplicates leave in
 * park order within one key. Per CPU mismatch, missing order, stale
 * sequence skip with no tree drop and the daemon drops
 * shares through complete plus stale collection. Only the moved pid
 * drops its key when the stored key still matches. Empty tree or
 * stall moves one gated task with the same checks plus keyed drop
 * so progress stays bounded with no bypass. Over moves count
 * progress.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool veb_try_move_one(u32 key, s32 cpu)
{
	bool moved = false;
	struct task_struct *p;
	if (key >= (u32)FLOW_VEB_U)
		return false;
	if (cpu < 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		u32 pid;
		u32 *kp;
		u32 k2;
		struct flow_task_ctx *tctx;
		struct flow_order_entry *ord;
		if (moved)
			break;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		if (pid == 0) {
			bpf_task_release(t);
			continue;
		}
		kp = bpf_map_lookup_elem(&veb_pid, &pid);
		if (!kp) {
			bpf_task_release(t);
			continue;
		}
		k2 = READ_ONCE(*kp);
		if (k2 != key) {
			bpf_task_release(t);
			continue;
		}
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			continue;
		}
		tctx = flow_lookup(t);
		if (!tctx) {
			bpf_task_release(t);
			continue;
		}
		ord = bpf_map_lookup_elem(&order_stor, &pid);
		if (!ord) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			continue;
		}
		if (ord->seq == 0 || ord->seq != READ_ONCE(tctx->seq)) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			moved = true;
			bpf_task_release(t);
			veb_remove_if_key(pid, key);
			break;
		}
		bpf_task_release(t);
	}
	bpf_rcu_read_unlock();
	return moved;
}
static __noinline bool veb_fail_open_one(s32 cpu)
{
	bool moved = false;
	u32 reap_pid = 0;
	u32 reap_key = 0xFFFFFFFFU;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return false;
	}
	if (scx_bpf_dsq_nr_queued(flow_overflow_dsq()) == 0)
		return false;
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, flow_overflow_dsq(), 0) {
		struct task_struct *t;
		u32 pid;
		u32 *kp;
		u32 k2;
		struct flow_task_ctx *tctx;
		struct flow_order_entry *ord;
		if (moved)
			break;
		t = bpf_task_from_pid(p->pid);
		if (!t)
			continue;
		pid = (u32)t->pid;
		if (pid == 0) {
			bpf_task_release(t);
			continue;
		}
		kp = bpf_map_lookup_elem(&veb_pid, &pid);
		if (!kp) {
			bpf_task_release(t);
			continue;
		}
		k2 = READ_ONCE(*kp);
		if (k2 >= (u32)FLOW_VEB_U) {
			bpf_task_release(t);
			continue;
		}
		if (!flow_entry_ok(cpu, t, 0)) {
			bpf_task_release(t);
			continue;
		}
		tctx = flow_lookup(t);
		if (!tctx) {
			bpf_task_release(t);
			continue;
		}
		ord = bpf_map_lookup_elem(&order_stor, &pid);
		if (!ord) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			continue;
		}
		if (ord->seq == 0 || ord->seq != READ_ONCE(tctx->seq)) {
			bpf_task_release(t);
			__sync_fetch_and_add(&flow_stats.parks, 1);
			continue;
		}
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, t,
		    (u64)SCX_DSQ_LOCAL_ON | (u64)cpu, 0)) {
			moved = true;
			reap_pid = pid;
			reap_key = k2;
			bpf_task_release(t);
			break;
		}
		bpf_task_release(t);
	}
	bpf_rcu_read_unlock();
	if (moved) {
		if (reap_pid != 0 && reap_key != 0xFFFFFFFFU)
			veb_remove_if_key(reap_pid, reap_key);
		return true;
	}
	return false;
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	u32 cur;
	int attempt;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	cur = veb_min();
	if (cur == 0xFFFFFFFFU) {
		if (veb_fail_open_one(cpu))
			__sync_fetch_and_add(&flow_stats.over_moves, 1);
		return;
	}
	bpf_for(attempt, 0, 20) {
		u32 *cntp;
		bool got;
		u32 *after;
		if ((u64)moved >= (u64)FLOW_DISPATCH_MAX_BATCH)
			break;
		if (cur == 0xFFFFFFFFU)
			break;
		cntp = veb_cnt_ptr(cur);
		if (!cntp || READ_ONCE(*cntp) == 0) {
			cur = veb_succ(cur);
			continue;
		}
		got = veb_try_move_one(cur, cpu);
		if (got) {
			moved++;
			after = veb_cnt_ptr(cur);
			if (!after || READ_ONCE(*after) == 0)
				cur = veb_succ(cur);
			continue;
		}
		cur = veb_succ(cur);
	}
	if (moved) {
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
		return;
	}
	if (veb_fail_open_one(cpu))
		__sync_fetch_and_add(&flow_stats.over_moves, 1);
}
