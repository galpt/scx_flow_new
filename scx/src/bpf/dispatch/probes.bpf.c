// SPDX-License-Identifier: GPL-2.0
/*
 * Ordered pick plus consume for the dispatch pass.
 *
 * Holds one fused pass with the head fast path plus one RCU section
 * for the miss path. The head path validates one cached pid with a
 * single task read then moves it in one tail walk, so hits skip the
 * pick walk. The miss path tracks the least key then deadline then
 * owned then pid in one tail walk then moves it in a second walk
 * within the same RCU section, so one lock covers pick plus move with
 * no extra acquire. Task state holds key plus deadline plus owner
 * from admit time, so the mask plus one state read picks the least
 * with no extra index lookup and no reference, and only the picked
 * pid takes a reference at move time. The head keeps the earliest
 * deadline then smallest pid per low key byte with best effort order,
 * so hits skip the full tail walk while misses fall back with no
 * wrong move. Live stays proven once at entry, so the per element
 * cost stays one mask test with no live branch. The queue handle
 * stays hoisted once at entry, so depth reads pay no dsq lookup per
 * step beyond the call. The move revalidates pid plus key plus
 * deadline plus owner with affinity, liveness checks and no sequence
 * gate, so any CPU takes the earliest work it may run with pid reuse
 * safe. Key plus deadline may match across tasks in the same instant,
 * so the owner view heals to the live owner with pid plus key plus
 * deadline still guarding reuse. A recheck miss skips stale and keeps
 * walking within the batch with the fallback left for empty plus
 * corrupt plus persistent stale, so ordered first keeps every parked
 * task preferred. Stale heads clear on ordered plus fallback moves
 * plus the teardown drop, so a running pid never lingers as a head.
 * Drops run at teardown, so the hot path keeps no deletes. Runs
 * noinline with scalar CPU with bounded loops, so the verifier stays
 * small with one RCU section per move and no outer lock.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline bool veb_consume_best(s32 cpu)
{
	u32 pid = 0;
	u32 key = (u32)FLOW_VEB_EMPTY;
	u64 deadline = 0;
	u32 owner = 0;
	u32 moved_pid = 0;
	bool moved = false;
	u64 ov;
	struct task_struct *p;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	/* Queue handle stays hoisted, so depth plus scans pay no dsq */
	/* lookup per step beyond the call. */
	ov = flow_overflow_dsq();
	if (scx_bpf_dsq_nr_queued(ov) == 0)
		return false;
	/* Head first skips the pick walk when the cached pid for the */
	/* least key still holds key with mask, so a deep tail pays one */
	/* task read plus one move walk instead of two walks. Rejects */
	/* sit at the top key with the far deadline, so the same head */
	/* still orders them last with no extra gate. */
	if (flow_head_pick(cpu, &pid, &key, &deadline, &owner)) {
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, ov, 0) {
			if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p,
			    pid, key, deadline, owner, &moved_pid)) {
				moved = true;
				break;
			}
		}
		bpf_rcu_read_unlock();
		/* Head clears on both outcomes when it still names the */
		/* wanted pid, so a running pid never lingers while other */
		/* keys stay. Fallback moves clear the same way, so a */
		/* fallback pid never poisons the next ordered pick with */
		/* the next pass falling back to the scan. */
		flow_head_clear(pid, key);
		return moved;
	}
	/* Miss holds pick plus move in one RCU section with the best */
	/* tracked in locals then moved at the end, so one lock covers */
	/* both walks with no extra acquire. */
	{
		u32 best_pid = 0;
		u32 best_key = (u32)FLOW_VEB_EMPTY;
		u64 best_deadline = (u64)~0ULL;
		u32 best_rank = 0xFFFFFFFFu;
		u32 best_owner = 0;
		bpf_rcu_read_lock();
		bpf_for_each(scx_dsq, p, ov, 0) {
			u32 iter_pid;
			struct flow_task_ctx *tctx;
			u32 k;
			u64 d;
			u32 own;
			u32 rank;
			bool better;
			/* Iterator never holds null here, so no null branch. */
			/* Task state alone orders every parked task with no */
			/* extra lookup, since admits and top key rejects all */
			/* carry key plus deadline. */
			iter_pid = (u32)p->pid;
			if (iter_pid == 0)
				continue;
			/* Live proven at entry, so mask alone gates here. */
			if (!flow_mask_ok(cpu, p))
				continue;
			tctx = flow_lookup(p);
			if (!tctx)
				continue;
			k = READ_ONCE(tctx->key);
			if (k >= (u32)FLOW_VEB_U)
				continue;
			d = READ_ONCE(tctx->deadline);
			if (d == 0)
				continue;
			own = READ_ONCE(tctx->admit_cpu);
			/* Owned sorts before unowned with smaller pid */
			/* first, so one rank folds both tiebreaks: pids */
			/* stay below bit 31 while unowned sets it. */
			rank = iter_pid |
			    (own == (u32)cpu ? 0u : 0x80000000u);
			/* Key folds into deadline with no extra level: key */
			/* stays quantize of deadline with saturate at top, */
			/* so deadline order already implies key order with */
			/* equal deadlines sharing one key. Key stays above */
			/* solely to skip corrupt plus to carry the move */
			/* recheck, while deadline then rank order the pick. */
			/* Single better check keeps one update site with */
			/* no nested takes, so the verifier walks one flat */
			/* chain. */
			if (best_pid == 0)
				better = true;
			else if (d != best_deadline)
				better = d < best_deadline;
			else
				better = rank < best_rank;
			if (!better)
				continue;
			best_pid = iter_pid;
			best_key = k;
			best_deadline = d;
			best_rank = rank;
			best_owner = own;
		}
		if (best_pid == 0) {
			bpf_rcu_read_unlock();
			return false;
		}
		/* The pick tracked the best with no reference, so the */
		/* move below takes the sole reference with pid plus key */
		/* plus deadline plus owner guarding reuse. */
		bpf_for_each(scx_dsq, p, ov, 0) {
			if (flow_move_candidate(BPF_FOR_EACH_ITER, cpu, p,
			    best_pid, best_key, best_deadline, best_owner,
			    &moved_pid)) {
				moved = true;
				break;
			}
		}
		bpf_rcu_read_unlock();
		/* Head clears when it still names the wanted pid, so a */
		/* running pid never lingers while other keys stay. */
		flow_head_clear(best_pid, best_key);
		return moved;
	}
}
