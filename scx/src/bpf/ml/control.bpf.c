// SPDX-License-Identifier: GPL-2.0
/*
 * ML control for the flow scheduler at 4.8.14.
 *
 * Holds the learnable RED bounds that let ML own admit plus drop with
 * outer safety still checked. Tolerance learns within outer 0 to 256us
 * defaulting to 64us for hard batch only, Emax learns within outer
 * 64us to 1ms defaulting to 256us, each clamped to its outer with
 * defaults on miss or legacy version. Hard means batch non-latency
 * while critical means latency-critical via the unified latency test,
 * so no separate class holds past latency. Critical tolerance stays
 * zero with no learned slack, so urgent work stays strict. Kick rides
 * the capped nudge shaped fair key with PRIQ only, while placement
 * tests the deadline plus drain, so learnable inputs drive admit plus
 * drop plus kick with bounds and accuracy stays observability-only.
 * Runs with one map read plus clamps, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_ml_red_tol_ns - learnable tolerance with outer 0 to 256us.
 *
 * Reads the model red_tol_ns with version 1 else the 64us default, then
 * clamps to outer 0 to 256us, so one learned value never holds past the
 * default Emax. A zero stored value stays zero with no default fill.
 *
 * Outlined with noinline to keep verifier headroom with one shared copy,
 * so newcomer plus reclaim share the same fetch with no inline growth.
 *
 * Returns: learnable tolerance in nanos from 0 to 256us.
 */
static __noinline u64 flow_ml_red_tol_ns(void)
{
	u32 key = 0;
	struct flow_online_model *m;
	u64 v;
	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return (u64)FLOW_RED_TOL_NS;
	if (READ_ONCE(m->version) != (u32)FLOW_ML_MODEL_VERSION)
		return (u64)FLOW_RED_TOL_NS;
	v = (u64)READ_ONCE(m->red_tol_ns);
	return flow_red_tol_clamp(v);
}
/**
 * flow_ml_red_emax_ns - learnable Emax with outer 64us to 1ms.
 *
 * Reads the model red_emax_ns with version 1 else the 256us default,
 * then clamps to outer 64us to 1ms, so one learned value never drops
 * past the victim gate nor holds past one quantum. Zero maps to the
 * 64us floor through the clamp with no extra branch.
 *
 * Outlined with noinline to keep verifier headroom with one shared copy,
 * so victim plus reclaim plus credit share the same fetch with no inline
 * growth.
 *
 * Returns: learnable Emax in nanos from 64us to 1ms.
 */
static __noinline u64 flow_ml_red_emax_ns(void)
{
	u32 key = 0;
	struct flow_online_model *m;
	u64 v;
	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return (u64)FLOW_RED_EMAX_NS;
	if (READ_ONCE(m->version) != (u32)FLOW_ML_MODEL_VERSION)
		return (u64)FLOW_RED_EMAX_NS;
	v = (u64)READ_ONCE(m->red_emax_ns);
	return flow_red_emax_clamp(v);
}
/**
 * struct flow_ml_feat - capped features for one train plus infer step.
 * @avg: burst average capped at the 1ms quantum.
 * @dev: burst deviation capped at the 1ms quantum.
 * @lag: direct lag within plus or minus 2ms via the lag bound.
 * @sleep: sleep capped at the 1ms quantum.
 * @w: effective share within 1 to 16384 via the helper.
 *
 * Bundles the burst capped inputs, so train plus infer share one fill
 * with no double capping and no order change.
 */
struct flow_ml_feat {
	u64 avg;
	u64 dev;
	s32 lag;
	u64 sleep;
	u32 w;
};
/**
 * flow_ml_feat - fill one capped feature set from task state.
 * @tctx: task state with avg plus dev plus vlag, null clears.
 * @sleep_ns: sleep time in nanos from the caller wrap-safe helper.
 * @eff_w: effective share from task times hint over 128.
 * @out: filled features, cleared on null task.
 *
 * Caps avg plus dev plus sleep at the quantum while lag stays direct
 * within the bound plus share stays within range, so train plus infer
 * agree on bursts with no wrap. Like fair.c, the caps pace learning,
 * unlike rt.c, no fixed priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so train plus infer share the same caps with no inline growth.
 */
static __noinline void flow_ml_feat(const struct flow_task_ctx *tctx,
	u64 sleep_ns, u32 eff_w, struct flow_ml_feat *out)
{
	if (!out)
		return;
	out->avg = 0;
	out->dev = 0;
	out->lag = 0;
	out->sleep = 0;
	out->w = 0;
	if (!tctx)
		return;
	out->avg = flow_ml_cap_burst((u64)READ_ONCE(tctx->avg_ns));
	out->dev = flow_ml_cap_burst((u64)READ_ONCE(tctx->dev_ns));
	out->lag = READ_ONCE(tctx->vlag);
	out->sleep = flow_ml_cap_burst(sleep_ns);
	out->w = eff_w;
}
/**
 * flow_ml_score - fixed point dot product plus bias for one step.
 * @f: capped features from flow_ml_feat, null reads zero.
 * @m: online model with weights plus bias, null reads zero.
 *
 * Sums burst capped avg plus dev plus sleep at the quantum plus direct
 * lag plus share times their weights with FP_SHIFT 8 plus bias, so one
 * score tracks bursts with shifts only. Like fair.c, the score paces
 * learning, unlike rt.c, no fixed priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so train plus nudge share the same dot with no inline growth.
 *
 * Returns: raw score in nanos before the slice clamp.
 */
static __noinline s64 flow_ml_score(const struct flow_ml_feat *f,
	const struct flow_online_model *m)
{
	struct flow_online_model *mm;
	s64 score = 0;
	if (!f || !m)
		return 0;
	mm = (struct flow_online_model *)m;
	score += ((s64)(f->avg >> 4) *
	    (s64)READ_ONCE(mm->w_avg)) >> (FLOW_ML_FP_SHIFT - 4);
	score += ((s64)(f->dev >> 4) *
	    (s64)READ_ONCE(mm->w_dev)) >> (FLOW_ML_FP_SHIFT - 4);
	score += ((s64)f->lag *
	    (s64)READ_ONCE(mm->w_lag)) >> FLOW_ML_FP_SHIFT;
	score += ((s64)(f->sleep >> 4) *
	    (s64)READ_ONCE(mm->w_sleep)) >> (FLOW_ML_FP_SHIFT - 4);
	score += ((s64)f->w *
	    (s64)READ_ONCE(mm->w_weight)) >> FLOW_ML_FP_SHIFT;
	score += (s64)READ_ONCE(mm->bias);
	return score;
}
/**
 * flow_ml_drift - drift the learnable RED bounds by one small step.
 * @m: online model with tol plus Emax, null drops.
 * @hit: per-sample hit from the 64us window, miss widens.
 *
 * Tightens toward the defaults by 16ns for tolerance plus 64ns for
 * Emax on hit, widens by 64ns plus 256ns on miss, each within outer 0
 * to 256us plus 64us to 1ms with CAS plus one retry, so ML owns admit
 * plus drop with safety still checked and accuracy never gates a
 * decision. Legacy rows past version 1 skip with no write.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy, so the train path keeps one drift with no inline growth.
 */
static __noinline void flow_ml_drift(struct flow_online_model *m, bool hit)
{
	u64 tol_cur;
	u64 emax_cur;
	u64 tol_nxt;
	u64 emax_nxt;
	u32 tol_old;
	u32 emax_old;
	if (!m)
		return;
	if (READ_ONCE(m->version) != (u32)FLOW_ML_MODEL_VERSION)
		return;
	tol_cur = (u64)READ_ONCE(m->red_tol_ns);
	emax_cur = (u64)READ_ONCE(m->red_emax_ns);
	tol_cur = flow_red_tol_clamp(tol_cur);
	emax_cur = flow_red_emax_clamp(emax_cur);
	if (hit) {
		tol_nxt = tol_cur > (u64)FLOW_RED_TOL_NS ?
		    tol_cur - 16ULL : tol_cur < (u64)FLOW_RED_TOL_NS ?
		    tol_cur + 16ULL : tol_cur;
		emax_nxt = emax_cur > (u64)FLOW_RED_EMAX_NS ?
		    emax_cur - 64ULL : emax_cur < (u64)FLOW_RED_EMAX_NS ?
		    emax_cur + 64ULL : emax_cur;
	} else {
		tol_nxt = flow_red_tol_clamp(flow_sat_add(tol_cur, 64ULL));
		emax_nxt = flow_red_emax_clamp(flow_sat_add(emax_cur, 256ULL));
	}
	tol_nxt = flow_red_tol_clamp(tol_nxt);
	emax_nxt = flow_red_emax_clamp(emax_nxt);
	tol_old = __sync_val_compare_and_swap(&m->red_tol_ns,
	    (u32)tol_cur, (u32)tol_nxt);
	if (tol_old != (u32)tol_cur) {
		tol_cur = (u64)READ_ONCE(m->red_tol_ns);
		tol_cur = flow_red_tol_clamp(tol_cur);
		if (hit) {
			tol_nxt = tol_cur > (u64)FLOW_RED_TOL_NS ?
			    tol_cur - 16ULL : tol_cur < (u64)FLOW_RED_TOL_NS ?
			    tol_cur + 16ULL : tol_cur;
		} else {
			tol_nxt = flow_red_tol_clamp(flow_sat_add(tol_cur, 64ULL));
		}
		tol_nxt = flow_red_tol_clamp(tol_nxt);
		tol_old = __sync_val_compare_and_swap(&m->red_tol_ns,
		    (u32)tol_cur, (u32)tol_nxt);
		(void)tol_old;
	}
	emax_old = __sync_val_compare_and_swap(&m->red_emax_ns,
	    (u32)emax_cur, (u32)emax_nxt);
	if (emax_old != (u32)emax_cur) {
		emax_cur = (u64)READ_ONCE(m->red_emax_ns);
		emax_cur = flow_red_emax_clamp(emax_cur);
		if (hit) {
			emax_nxt = emax_cur > (u64)FLOW_RED_EMAX_NS ?
			    emax_cur - 64ULL : emax_cur < (u64)FLOW_RED_EMAX_NS ?
			    emax_cur + 64ULL : emax_cur;
		} else {
			emax_nxt = flow_red_emax_clamp(flow_sat_add(emax_cur, 256ULL));
		}
		emax_nxt = flow_red_emax_clamp(emax_nxt);
		emax_old = __sync_val_compare_and_swap(&m->red_emax_ns,
		    (u32)emax_cur, (u32)emax_nxt);
		(void)emax_old;
	}
}
