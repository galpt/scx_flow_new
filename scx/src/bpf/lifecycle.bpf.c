/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	struct flow_cpu_state *st;
	s32 cpu;
	u8 group;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	if (tctx)
		tctx->run_at = flow_now();
	if (tctx && tctx->group ==
	    (u8)FLOW_GROUP_HOG)
		group = (u8)FLOW_GROUP_HOG;
	else
		group = (u8)FLOW_GROUP_LIGHT;
	if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
		if (scx_bpf_cpuperf_set)
			scx_bpf_cpuperf_set(cpu,
			    flow_perf_for_group(group));
	}
	if (cpu < 0)
		goto inc;
	if (!flow_cpu_live((u32)cpu))
		goto inc;
	st = flow_cpu((u32)cpu);
	if (st) {
		u64 est = tctx ?
		    flow_clamp_est(tctx->est_ns) : 0;
		st->running_est = est;
		st->running_pid = (u32)p->pid;
	}
inc:
	__sync_fetch_and_add(&flow_stats.on_cpu, 1);
}
void BPF_STRUCT_OPS(flow_dequeue, struct task_struct *p,
	u64 deq_flags)
{
	(void)p;
	(void)deq_flags;
}
/* Pressure refresh from per CPU queued counts capped */
/* at 4. Sums light plus hog queued tasks over per CPU */
/* queues in halves order with early stop when both hit */
/* 4. Halves matches dispatch isolation with no table */
/* cost. Park stays out, so the measure tracks CPU */
/* pressure only with one pass and bounded cost. Stores */
/* depths plus allowance for snapshot with no task field. */
/* Returns the allowance for the burst check. Stopping */
/* only, never dispatch. */
static __always_inline u64 flow_refresh_pressure(void)
{
	u64 light = 0;
	u64 hog = 0;
	u64 allow;
	s32 cpu;
	bpf_for(cpu, 0, 1024) {
		u64 dsq;
		u64 n;
		u8 g;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		g = flow_group_of_cpu((u32)cpu,
		    nr_cpu_ids);
		dsq = flow_dsq_for_cpu((u32)cpu);
		n = scx_bpf_dsq_nr_queued(dsq);
		if (g == (u8)FLOW_GROUP_LIGHT) {
			light += n;
			if (light >= 4)
				light = 4;
		} else {
			hog += n;
			if (hog >= 4)
				hog = 4;
		}
		if (light >= 4 && hog >= 4)
			break;
	}
	allow = flow_burst_allowance(light);
	flow_light_depth = light;
	flow_hog_depth = hog;
	flow_burst_allowance_ns = allow;
	return allow;
}
/* Burn step for one stop with window plus burst plus wake. */
/* Burst allowance adapts to light depth with 4ms quiet to */
/* 2ms mild to 1ms floor during flood. Short blocks below */
/* 1ms count toward 8 for fast promote. Burn must stay low, */
/* so burn breaks the wake streak. Middle window keeps wake */
/* hits with no reset. Slow path with 64 low wins stays */
/* intact with no wake change. Stopping only, never dispatch. */
static __always_inline void flow_classify(
	struct flow_task_ctx *tctx, u64 now,
	u64 delta)
{
	u8 group;
	u64 sum;
	u64 allow;
	if (!tctx)
		return;
	group = tctx->group;
	if (group != (u8)FLOW_GROUP_LIGHT &&
	    group != (u8)FLOW_GROUP_HOG) {
		group = (u8)FLOW_GROUP_LIGHT;
		tctx->group = group;
	}
	sum = (u64)tctx->burn + delta;
	if (sum > 0xffffffffULL)
		sum = 0xffffffffULL;
	tctx->burn = (u32)sum;
	allow = flow_refresh_pressure();
	if (flow_burst_hot_at(delta, allow)) {
		tctx->wake_hits = 0;
		if (group ==
		    (u8)FLOW_GROUP_LIGHT) {
			tctx->group =
			    (u8)FLOW_GROUP_HOG;
			tctx->low_runs = 0;
			tctx->win_start = now;
			tctx->burn = 0;
			__sync_fetch_and_add(
			    &flow_stats.group_demote,
			    1);
		} else {
			tctx->low_runs = 0;
		}
		return;
	}
	if (flow_wake_short(delta)) {
		if (group == (u8)FLOW_GROUP_HOG) {
			if (flow_burn_low(tctx->burn)) {
				u16 hits = tctx->wake_hits;
				if (hits < 0xffff)
					hits++;
				tctx->wake_hits = hits;
				if (flow_wake_ready(hits)) {
					tctx->group =
					    (u8)FLOW_GROUP_LIGHT;
					tctx->low_runs = 0;
					tctx->wake_hits = 0;
					tctx->win_start = now;
					tctx->burn = 0;
					__sync_fetch_and_add(
					    &flow_stats.group_promote,
					    1);
					__sync_fetch_and_add(
					    &flow_stats.group_wake_promote,
					    1);
					return;
				}
			} else {
				tctx->wake_hits = 0;
			}
		} else {
			tctx->wake_hits = 0;
		}
	}
	if (tctx->win_start == 0) {
		tctx->win_start = now;
		return;
	}
	if (!flow_win_ready(now, tctx->win_start))
		return;
	if (flow_burn_hot(tctx->burn)) {
		tctx->wake_hits = 0;
		if (group ==
		    (u8)FLOW_GROUP_LIGHT) {
			tctx->group =
			    (u8)FLOW_GROUP_HOG;
			tctx->low_runs = 0;
			__sync_fetch_and_add(
			    &flow_stats.group_demote,
			    1);
		} else {
			tctx->low_runs = 0;
		}
		tctx->win_start = now;
		tctx->burn = 0;
		return;
	}
	if (flow_burn_low(tctx->burn)) {
		if (group == (u8)FLOW_GROUP_HOG) {
			if (tctx->low_runs < 255)
				tctx->low_runs++;
			if (tctx->low_runs >=
			    (u8)FLOW_PROMOTE_WINS) {
				tctx->group =
				    (u8)FLOW_GROUP_LIGHT;
				tctx->low_runs = 0;
				tctx->wake_hits = 0;
				__sync_fetch_and_add(
				    &flow_stats.group_promote,
				    1);
			}
		} else {
			if (tctx->low_runs <
			    (u8)FLOW_PROMOTE_WINS)
				tctx->low_runs++;
		}
		tctx->win_start = now;
		tctx->burn = 0;
		return;
	}
	tctx->low_runs = 0;
	tctx->wake_hits = 0;
	tctx->win_start = now;
	tctx->burn = 0;
}
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p,
	bool runnable)
{
	struct flow_task_ctx *tctx;
	s32 cpu;
	u64 now;
	u64 delta;
	u64 est;
	u64 scaled;
	u64 nv;
	tctx = flow_lookup(p);
	cpu = scx_bpf_task_cpu(p);
	now = flow_now();
	if (!tctx || !tctx->run_at ||
	    tctx->run_at == (u64)-1) {
		flow_clear_running(cpu);
		flow_on_cpu_dec();
		return;
	}
	if (now >= tctx->run_at)
		delta = now - tctx->run_at;
	else
		delta = 0;
	est = flow_clamp_est(delta);
	tctx->est_ns = est;
	__sync_fetch_and_add(&flow_stats.total_runtime, delta);
	flow_classify(tctx, now, delta);
	flow_clear_running(cpu);
	flow_on_cpu_dec();
	tctx->run_at = 0;
	scaled = flow_scale_by_weight(est,
	    (u32)FLOW_WEIGHT);
	nv = flow_vruntime_add(tctx->vruntime, scaled);
	tctx->vruntime = nv;
	if (cpu >= 0 && flow_cpu_live((u32)cpu)) {
		struct flow_cpu_state *st;
		st = flow_cpu((u32)cpu);
		if (st) {
			if (!runnable) {
				u64 dsq;
				dsq = flow_dsq_for_cpu((u32)cpu);
				if (scx_bpf_dsq_nr_queued(dsq) == 0 &&
				    scx_bpf_dsq_nr_queued(
				    (u64)SCX_DSQ_LOCAL_ON |
				    (u64)cpu) == 0) {
					if (nv != 0)
						st->frontier =
						    flow_frontier_idle(nv);
				} else {
					st->frontier =
					    flow_frontier_max(
					    st->frontier, nv);
				}
			} else {
				st->frontier = flow_frontier_max(
				    st->frontier, nv);
			}
		}
	}
	if (runnable) {
		__sync_fetch_and_add(&flow_stats.requeues, 1);
		return;
	}
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
void BPF_STRUCT_OPS(flow_enable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	tctx = flow_get(p);
	if (!tctx)
		return;
	tctx->est_ns = 0;
	tctx->run_at = 0;
	tctx->vruntime = 0;
	tctx->deadline = (u64)-1;
	tctx->win_start = 0;
	tctx->burn = 0;
	tctx->group = (u8)FLOW_GROUP_LIGHT;
	tctx->low_runs = 0;
	tctx->wake_hits = 0;
}
void BPF_STRUCT_OPS(flow_disable, struct task_struct *p)
{
	struct flow_task_ctx *tctx;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
void BPF_STRUCT_OPS(flow_exit_task, struct task_struct *p,
	struct scx_exit_task_args *args)
{
	struct flow_task_ctx *tctx;
	(void)args;
	tctx = flow_lookup(p);
	if (!tctx)
		return;
	if (tctx->deadline == (u64)-1)
		return;
	__sync_fetch_and_add(&flow_stats.completions, 1);
	tctx->deadline = (u64)-1;
}
