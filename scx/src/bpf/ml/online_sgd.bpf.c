// SPDX-License-Identifier: GPL-2.0
/*
 * Online SGD for the flow scheduler.
 *
 * Holds one batch-one train step for the global online model with
 * integer shifts only. The prediction forms a fixed point dot product
 * over avg plus dev plus vlag plus sleep plus eff_w with FP_SHIFT 8
 * (SGD fixed point 8), the error clamps to plus or minus 64us
 * (SGD_GRAD_MAX 64us, FLOW_ML_GRAD_MAX_NS), each gradient steps with
 * LEARN_SHIFT 11 (SGD_LEARN_SHIFT 11, divisor 1/2048), and each weight
 * clamps to plus or minus 524288 (SGD_WEIGHT_BOUND, FLOW_ML_WEIGHT_BOUND)
 * with saturation. Updates use atomics via fetch and add with no lock,
 * so concurrent trains never tear. Runs with shifts plus 64-bit
 * multiplies and no divide, so the verifier stays small.
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
 * with FP_SHIFT 8, floors the prediction to the 10us slice minimum,
 * then takes err as actual minus predicted and clamps it to plus or
 * minus 64us. Each weight steps as err times its feature shifted right
 * by LEARN_SHIFT 11 with fetch and add atomics, and the count bumps
 * once. Each weight then clamps to plus or minus 524288 best effort
 * with saturation, so one step never wraps. A null task plus a zero
 * delta plus a missing row drops with no update. Like fair.c, the step
 * paces learning, unlike rt.c, no fixed priority holds.
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

	if (!tctx)
		return;
	if (actual_delta == 0)
		return;

	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return;

	/* Fixed point dot product with FP_SHIFT 8. */
	pred += ((s64)(READ_ONCE(tctx->avg_ns) >> 4) *
	    (s64)READ_ONCE(m->w_avg)) >> (FLOW_ML_FP_SHIFT - 4);
	pred += ((s64)(READ_ONCE(tctx->dev_ns) >> 4) *
	    (s64)READ_ONCE(m->w_dev)) >> (FLOW_ML_FP_SHIFT - 4);
	pred += ((s64)READ_ONCE(tctx->vlag) *
	    (s64)READ_ONCE(m->w_lag)) >> FLOW_ML_FP_SHIFT;
	pred += ((s64)(sleep_ns >> 4) *
	    (s64)READ_ONCE(m->w_sleep)) >> (FLOW_ML_FP_SHIFT - 4);
	pred += ((s64)eff_w *
	    (s64)READ_ONCE(m->w_weight)) >> FLOW_ML_FP_SHIFT;
	pred += (s64)READ_ONCE(m->bias);

	if (pred < (s64)FLOW_SLICE_MIN_NS)
		pred = (s64)FLOW_SLICE_MIN_NS;

	/* Error against actual execution. */
	err = (s64)actual_delta - pred;

	/* Clip the error to plus or minus 64us. */
	if (err > (s64)FLOW_ML_GRAD_MAX_NS)
		err = (s64)FLOW_ML_GRAD_MAX_NS;
	else if (err < -((s64)FLOW_ML_GRAD_MAX_NS))
		err = -((s64)FLOW_ML_GRAD_MAX_NS);

	/* Atomic SGD updates with LEARN_SHIFT 11. */
	grad = (err * (s64)(READ_ONCE(tctx->avg_ns) >> 6)) >>
	    FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->w_avg, (s32)grad);

	grad = (err * (s64)(READ_ONCE(tctx->dev_ns) >> 6)) >>
	    FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->w_dev, (s32)grad);

	grad = (err * ((s64)READ_ONCE(tctx->vlag) >> 4)) >>
	    FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->w_lag, (s32)grad);

	grad = (err * (s64)(sleep_ns >> 6)) >> FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->w_sleep, (s32)grad);

	grad = (err * (s64)eff_w) >> FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->w_weight, (s32)grad);

	grad = err >> FLOW_ML_LEARN_SHIFT;
	__sync_fetch_and_add(&m->bias, (s32)grad);

	__sync_fetch_and_add(&m->update_count, 1);

	/* Clamp each weight to plus or minus 524288 best effort. */
	if (m->w_avg > (s32)FLOW_ML_WEIGHT_BOUND)
		m->w_avg = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->w_avg < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->w_avg = -((s32)FLOW_ML_WEIGHT_BOUND);
	if (m->w_dev > (s32)FLOW_ML_WEIGHT_BOUND)
		m->w_dev = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->w_dev < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->w_dev = -((s32)FLOW_ML_WEIGHT_BOUND);
	if (m->w_lag > (s32)FLOW_ML_WEIGHT_BOUND)
		m->w_lag = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->w_lag < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->w_lag = -((s32)FLOW_ML_WEIGHT_BOUND);
	if (m->w_sleep > (s32)FLOW_ML_WEIGHT_BOUND)
		m->w_sleep = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->w_sleep < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->w_sleep = -((s32)FLOW_ML_WEIGHT_BOUND);
	if (m->w_weight > (s32)FLOW_ML_WEIGHT_BOUND)
		m->w_weight = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->w_weight < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->w_weight = -((s32)FLOW_ML_WEIGHT_BOUND);
	if (m->bias > (s32)FLOW_ML_WEIGHT_BOUND)
		m->bias = (s32)FLOW_ML_WEIGHT_BOUND;
	if (m->bias < -((s32)FLOW_ML_WEIGHT_BOUND))
		m->bias = -((s32)FLOW_ML_WEIGHT_BOUND);
}
