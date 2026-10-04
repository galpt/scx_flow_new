// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch with bounded drain plus steal plus fail open.
 *
 * Each pass drains local plus node plus machine plus overflow plus
 * steal in order with at most one move per tier bounded by remaining
 * slots and visits capped at eight per pass shared across tiers. The
 * overflow tier holds FIFO bursts with mask wins, so overload still
 * drains with no priority inversion. The steal tier scans four to
 * eight peers proportional to remaining visits with queue runnable
 * hints plus a saturated early out when tiers still hold work. A Q1
 * only fast path drains the local tier alone when peers hold no work,
 * so the common single queue pass skips three empty moves plus the
 * steal polls. The best candidate cache advances the cursor on a
 * successful steal, so the next pass starts past the drained peer with
 * no hotspot. Fail open moves through the shared mask gate, so one
 * foreign head never stalls its tier. The level follows after all
 * moves with the same CPU only and stays transition only.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Depth probe with own plus local plus node plus running. */
static __noinline bool flow_perf_busy(s32 cpu)
{
	s32 own;
	s32 local;
	u64 depth = 0;
	struct flow_cpu_state *st;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	own = scx_bpf_dsq_nr_queued(flow_local_dsq((u32)cpu));
	if (own > 0)
		depth += (u64)own;
	local = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu);
	if (local > 0)
		depth += (u64)local;
	{
		u32 node = flow_cpu_node((u32)cpu);
		if (node < (u32)FLOW_MAX_NODES &&
		    (u64)node < nr_node_ids) {
			s32 shared = scx_bpf_dsq_nr_queued(flow_node_dsq(node));
			if (shared > 0)
				depth += (u64)shared;
		}
	}
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		depth += 1;
	return depth > 0;
}
/* Core perf set with transition only store. */
static __noinline void flow_perf_set(s32 cpu, u32 want)
{
	u32 cap;
	u32 key;
	u32 *last;
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	if (want != (u32)FLOW_CPU_PERF_HALF &&
	    want != (u32)FLOW_CPU_PERF_MAX)
		return;
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
	if (READ_ONCE(*last) == want)
		return;
	__sync_lock_test_and_set(last, want);
	scx_bpf_cpuperf_set(cpu, want);
}
static __always_inline void flow_perf_update(s32 cpu)
{
	if (flow_perf_busy(cpu))
		flow_perf_set(cpu, (u32)FLOW_CPU_PERF_MAX);
	else
		flow_perf_set(cpu, (u32)FLOW_CPU_PERF_HALF);
}
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 budget;
	u32 left;
	u32 visits = 0;
	u32 local_moved = 0;
	u32 node_moved = 0;
	u32 machine_moved = 0;
	u32 overflow_moved = 0;
	u64 own_local;
	u32 node;
	u64 node_dsq;
	u64 machine_dsq;
	u64 overflow_dsq;
	(void)prev;
	if (unlikely(cpu < 0))
		return;
	if (unlikely(!flow_cpu_live((u32)cpu))) {
		flow_gate_reject();
		return;
	}
	budget = scx_bpf_dispatch_nr_slots();
	if (unlikely(budget == 0))
		goto out;
	own_local = flow_local_dsq((u32)cpu);
	node = flow_cpu_node((u32)cpu);
	if (node >= (u32)FLOW_MAX_NODES ||
	    (u64)node >= nr_node_ids)
		node = 0;
	node_dsq = flow_node_dsq(node);
	machine_dsq = flow_machine_dsq();
	overflow_dsq = flow_overflow_dsq();
	left = budget;
	/* Queue runnable hints hoist the four tier depths once. Each tier */
	/* move runs only when its hint shows queued work, so empty tiers */
	/* skip the RCU scan with no visit cost. The same hints feed the */
	/* steal early out with no second poll, so the pass pays four */
	/* queue reads total with no duplicate. */
	{
		s32 lq0 = scx_bpf_dsq_nr_queued(own_local);
		s32 nq0 = scx_bpf_dsq_nr_queued(node_dsq);
		s32 mq0 = scx_bpf_dsq_nr_queued(machine_dsq);
		s32 oq0 = scx_bpf_dsq_nr_queued(overflow_dsq);
		bool q1_only = lq0 > 0 && nq0 <= 0 && mq0 <= 0 && oq0 <= 0;
		/* Q1 only fast path drains the local tier alone. The common */
		/* single queue pass skips three empty moves plus the steal */
		/* backlog with the same order plus the same counts. */
		if (q1_only && likely(left) &&
		    likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			local_moved = flow_move_one(own_local, cpu, &visits);
			if (local_moved > left)
				local_moved = left;
			left -= local_moved;
			goto account;
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (lq0 > 0) {
				local_moved = flow_move_one(own_local, cpu, &visits);
				if (local_moved > left)
					local_moved = left;
				left -= local_moved;
			}
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (nq0 > 0) {
				node_moved = flow_move_one(node_dsq, cpu, &visits);
				if (node_moved > left)
					node_moved = left;
				left -= node_moved;
			}
		}
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (mq0 > 0) {
				machine_moved = flow_move_one(machine_dsq, cpu, &visits);
				if (machine_moved > left)
					machine_moved = left;
				left -= machine_moved;
			}
		}
		/* Overflow FIFO tier with the same visit cap and mask wins. */
		/* Bursts past tier order drain here in arrival order. */
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			if (oq0 > 0) {
				overflow_moved = flow_move_one(overflow_dsq, cpu, &visits);
				if (overflow_moved > left)
					overflow_moved = left;
				left -= overflow_moved;
			}
		}
		/* Steal tier last with a bounded 4 to 8 peer window. Only */
		/* steals when tiers drained, so busy passes skip cheap with */
		/* the hoisted hints and no second poll. Narrow means empty */
		/* peers skip with no RCU through the per peer hint in the */
		/* shared steal, so the effective scan stays small. */
		if (likely(left) && likely(visits < (u32)FLOW_DISPATCH_MAX_VISIT)) {
			u32 steal_moved = 0;
			struct flow_cpu_state *cst;
			u32 cursor;
			u64 backlog = 0;
			if (lq0 > 0)
				backlog = flow_sat_add(backlog, (u64)lq0);
			if (nq0 > 0)
				backlog = flow_sat_add(backlog, (u64)nq0);
			if (mq0 > 0)
				backlog = flow_sat_add(backlog, (u64)mq0);
			if (oq0 > 0)
				backlog = flow_sat_add(backlog, (u64)oq0);
			if (backlog == 0) {
				u64 nr = nr_cpu_ids;
				cst = flow_cpu((u32)cpu);
				cursor = cst ? READ_ONCE(cst->cursor) : (u32)cpu;
				steal_moved = flow_steal_one(cpu, &visits, cursor);
				if (steal_moved > left)
					steal_moved = left;
				left -= steal_moved;
				local_moved += steal_moved;
				/* Best candidate cache advances past the drained */
				/* peer on success, so the next steal starts */
				/* fresh with no hotspot and no extra scan. */
				if (steal_moved && cst && nr > 1 &&
				    nr <= (u64)FLOW_MAX_CPUS) {
					u32 n = (u32)nr;
					u32 next = flow_wrap_idx((u64)cursor + 1ULL, n);
					__sync_lock_test_and_set(&cst->cursor, next);
				}
			}
		}
	}
account:
	flow_account_local(local_moved + overflow_moved);
	flow_account_node(node_moved);
	flow_account_machine(machine_moved);
out:
	flow_perf_update(cpu);
}
