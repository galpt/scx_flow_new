// SPDX-License-Identifier: GPL-2.0
/*
 * Online SGD for the flow scheduler at 4.8.14.
 *
 * Holds one batch-one train step for the global online model with
 * integer shifts only. The prediction forms a fixed point dot product
 * over capped avg plus dev plus vlag plus sleep plus eff_w with
 * FP_SHIFT 8, the raw error counts accuracy with a 64us hit window
 * plus saturating hits over total, the error then clamps to plus or
 * minus 64us, each gradient steps with LEARN_SHIFT 11 plus an s32
 * clamp, and each weight clamps to plus or minus 524288 with CAS.
 * Learnable RED bounds drift slowly with the hit signal within outer
 * 0 to 256us plus 64us to 1ms with defaults on legacy, so ML owns
 * admit plus drop with safety still checked. Updates use atomics via
 * fetch and add with no lock, so concurrent trains never tear. Runs
 * with shifts plus 64-bit multiplies and no divide, so the verifier
 * stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_ml_train_step - one online SGD step on the global model.
 * @tctx: task state with avg plus dev plus vlag, null drops.
 * @actual_delta: raw service in nanos of the stopping segment.
 * @sleep_ns: sleep time in nanos from the caller wrap-safe helper.
 * @eff_w: effective share from task times hint over 128.
 *
 * Forms the predicted burst as the fixed point dot product plus bias
 * with FP_SHIFT 8 over capped inputs, floors the prediction to the
 * 10us slice minimum plus caps it at the 1s predictor top, then takes
 * raw err as actual minus predicted and counts accuracy with a 64us
 * hit window plus saturating hits over total before clipping err to
 * plus or minus 64us. Each weight steps as err times its capped feature
 * shifted right by LEARN_SHIFT 11 with an s32 clamp plus fetch and add
 * atomics, and the count bumps once with saturation. Each weight then
 * clamps to plus or minus 524288 with CAS, so one step never wraps with
 * no lost clamp. Learnable RED bounds drift by one small step on the
 * hit signal within their outers with CAS, so one train never storms.
 * A null task plus a zero delta plus a missing row drops with no
 * update. Like fair.c, the step paces learning, unlike rt.c, no fixed
 * priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy. Called from stopping and enqueue; returns without an update
 * when state missing.
 */
static __noinline void flow_ml_train_step(const struct flow_task_ctx *tctx,
	u64 actual_delta, u64 sleep_ns, u32 eff_w)
{
	u32 key = 0;
	struct flow_online_model *m;
	s64 pred = 0;
	s64 err;
	s64 grad;
	s64 raw_err = 0;
	bool acc_hit = false;

	if (!tctx)
		return;
	if (actual_delta == 0)
		return;

	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return;

	/* Fixed point dot product over capped inputs with FP_SHIFT 8. */
	/* Caps keep a huge burst plus lag plus share from saturating */
	/* the score to the error clip on every step. */
	{
		u64 c_avg = flow_ml_cap_burst((u64)READ_ONCE(tctx->avg_ns));
		u64 c_dev = flow_ml_cap_burst((u64)READ_ONCE(tctx->dev_ns));
		s32 c_lag = flow_ml_cap_lag(READ_ONCE(tctx->vlag));
		u64 c_sleep = flow_ml_cap_burst(sleep_ns);
		u32 c_w = flow_ml_cap_w(eff_w);
		pred += ((s64)(c_avg >> 4) *
		    (s64)READ_ONCE(m->w_avg)) >> (FLOW_ML_FP_SHIFT - 4);
		pred += ((s64)(c_dev >> 4) *
		    (s64)READ_ONCE(m->w_dev)) >> (FLOW_ML_FP_SHIFT - 4);
		pred += ((s64)c_lag *
		    (s64)READ_ONCE(m->w_lag)) >> FLOW_ML_FP_SHIFT;
		pred += ((s64)(c_sleep >> 4) *
		    (s64)READ_ONCE(m->w_sleep)) >> (FLOW_ML_FP_SHIFT - 4);
		pred += ((s64)c_w *
		    (s64)READ_ONCE(m->w_weight)) >> FLOW_ML_FP_SHIFT;
		pred += (s64)READ_ONCE(m->bias);
	}

	if (pred < (s64)FLOW_SLICE_MIN_NS)
		pred = (s64)FLOW_SLICE_MIN_NS;
	if (pred > (s64)FLOW_PRED_MAX_NS)
		pred = (s64)FLOW_PRED_MAX_NS;

	/* Error against actual execution with accuracy first. */
	/* Raw err counts a hit when the absolute value stays at or below */
	/* 64us with saturating hits over total, so accuracy reads 0.0 to */
	/* 1.0 with higher better. The clip below keeps the gradient small. */
	{
		s64 raw = (s64)actual_delta - pred;
		bool hit = flow_ml_is_hit(raw);
		flow_count_ml_sample(hit);
		raw_err = raw;
		acc_hit = hit;
		err = raw;
	}

	/* Clip the error to plus or minus 64us. */
	if (err > (s64)FLOW_ML_GRAD_MAX_NS)
		err = (s64)FLOW_ML_GRAD_MAX_NS;
	else if (err < -((s64)FLOW_ML_GRAD_MAX_NS))
		err = -((s64)FLOW_ML_GRAD_MAX_NS);

	/* Atomic SGD updates over capped inputs with LEARN_SHIFT 11. */
	/* The s32 clamp keeps the cast with no truncate, so a huge */
	/* burst never wraps the weight add. */
	{
		u64 c_avg = flow_ml_cap_burst((u64)READ_ONCE(tctx->avg_ns));
		u64 c_dev = flow_ml_cap_burst((u64)READ_ONCE(tctx->dev_ns));
		s32 c_lag = flow_ml_cap_lag(READ_ONCE(tctx->vlag));
		u64 c_sleep = flow_ml_cap_burst(sleep_ns);
		u32 c_w = flow_ml_cap_w(eff_w);
		grad = (err * (s64)(c_avg >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_avg, flow_ml_grad_s32(grad));

		grad = (err * (s64)(c_dev >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_dev, flow_ml_grad_s32(grad));

		grad = (err * ((s64)c_lag >> 4)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_lag, flow_ml_grad_s32(grad));

		grad = (err * (s64)(c_sleep >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_sleep, flow_ml_grad_s32(grad));

		grad = (err * (s64)c_w) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_weight, flow_ml_grad_s32(grad));

		grad = err >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->bias, flow_ml_grad_s32(grad));
	}

	/* Bump the train count with saturation, so the count never wraps. */
	if (READ_ONCE(m->update_count) != 0xffffffffU)
		__sync_fetch_and_add(&m->update_count, 1);

	/* Clamp each weight to plus or minus 524288 with CAS. */
	flow_ml_clamp_one(&m->w_avg);
	flow_ml_clamp_one(&m->w_dev);
	flow_ml_clamp_one(&m->w_lag);
	flow_ml_clamp_one(&m->w_sleep);
	flow_ml_clamp_one(&m->w_weight);
	flow_ml_clamp_one(&m->bias);

	/* Drift the learnable RED bounds by one small step on the hit */
	/* signal with outer clamps plus CAS, so ML owns admit plus drop */
	/* with safety still checked. A hit tightens toward the defaults */
	/* by 16ns for tolerance plus 64ns for Emax, a miss widens by 64ns */
	/* plus 256ns, each within outer 0 to 256us plus 64us to 1ms with */
	/* one retry and no storm. Legacy rows with version past 1 skip */
	/* with no write, so old headers never drive the bounds. */
	{
		u32 ver = READ_ONCE(m->version);
		if (ver == (u32)FLOW_ML_MODEL_VERSION) {
			bool hit = acc_hit;
			(void)raw_err;
			u64 tol_cur = (u64)READ_ONCE(m->red_tol_ns);
			u64 emax_cur = (u64)READ_ONCE(m->red_emax_ns);
			u64 tol_nxt;
			u64 emax_nxt;
			u32 tol_old;
			u32 emax_old;
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
			(void)tol_old;
			emax_old = __sync_val_compare_and_swap(&m->red_emax_ns,
			    (u32)emax_cur, (u32)emax_nxt);
			(void)emax_old;
		}
	}
}
