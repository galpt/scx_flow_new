// SPDX-License-Identifier: GPL-2.0
/*
 * Online SGD for the flow scheduler at 4.8.14.
 *
 * Holds one batch-one train step for the global online model with
 * integer shifts only. The prediction forms a fixed point dot product
 * over burst capped avg plus dev plus sleep at the quantum plus direct
 * lag plus share with FP_SHIFT 8, the raw error counts accuracy
 * observability-only with a 64us hit window plus saturating hits over
 * total, the error then clamps to plus or minus 64us, each gradient
 * steps with LEARN_SHIFT 11 plus an s32 clamp, and each weight clamps
 * to plus or minus 524288 with CAS plus one retry. Learnable RED
 * bounds drift slowly with the per-sample hit signal within outer 0
 * to 256us plus 64us to 1ms with defaults on legacy, so ML owns admit
 * plus drop with safety still checked and accuracy never gates a
 * decision. Updates use atomics via fetch and add with no lock plus a
 * CAS loop for the shared count, so concurrent trains never tear nor
 * wrap. Runs with shifts plus 64-bit multiplies and no divide, so the
 * verifier stays small.
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
 * with FP_SHIFT 8 over burst capped inputs at the quantum plus direct
 * lag plus share, floors the prediction to the 10us slice minimum plus
 * caps it at the 1s predictor top, then takes raw err as actual minus
 * predicted and counts accuracy observability-only with a 64us hit
 * window plus saturating hits over total before clipping err to plus
 * or minus 64us. Each weight steps as err times its burst capped or
 * direct feature shifted right by LEARN_SHIFT 11 with an s32 clamp plus
 * fetch and add atomics, and the count bumps once with a CAS loop at
 * max, so concurrent trains never wrap. Each weight then clamps to
 * plus or minus 524288 with CAS plus one retry, so one step never
 * wraps with no lost clamp. Learnable RED bounds drift by one small
 * step on the per-sample hit signal within their outers with CAS plus
 * one retry, so one train never storms and the aggregate accuracy
 * never gates a decision. A null task plus a zero delta plus a missing
 * row drops with no update. Like fair.c, the step paces learning,
 * unlike rt.c, no fixed priority holds.
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
	struct flow_ml_feat feat;
	s64 pred = 0;
	s64 err;
	s64 grad;
	bool acc_hit = false;

	if (!tctx)
		return;
	if (actual_delta == 0)
		return;

	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return;

	/* One shared fill feeds the dot plus the gradients, so the second */
	/* capping pass drops with no behavior change. Burst caps keep a */
	/* huge avg plus dev plus sleep from saturating the score to the */
	/* error clip on every step, while lag stays within plus or minus */
	/* 2ms via the lag bound plus share stays within 1 to 16384 via */
	/* the effective helper with no extra cap, so train plus infer */
	/* agree on bursts with one shared fill keeping the verifier small. */
	flow_ml_feat(tctx, sleep_ns, eff_w, &feat);
	pred = flow_ml_score(&feat, m);

	if (pred < (s64)FLOW_SLICE_MIN_NS)
		pred = (s64)FLOW_SLICE_MIN_NS;
	if (pred > (s64)FLOW_PRED_MAX_NS)
		pred = (s64)FLOW_PRED_MAX_NS;

	/* Error against actual execution with accuracy first. */
	/* Raw err counts a hit observability-only when the absolute value */
	/* stays at or below 64us with saturating hits over total, so */
	/* accuracy reads 0.0 to 1.0 with higher better and never gates a */
	/* decision. The clip below keeps the gradient small. */
	{
		s64 raw = (s64)actual_delta - pred;
		bool hit = flow_ml_is_hit(raw);
		flow_count_ml_sample(hit);
		acc_hit = hit;
		err = raw;
	}

	/* Clip the error to plus or minus 64us. */
	if (err > (s64)FLOW_ML_GRAD_MAX_NS)
		err = (s64)FLOW_ML_GRAD_MAX_NS;
	else if (err < -((s64)FLOW_ML_GRAD_MAX_NS))
		err = -((s64)FLOW_ML_GRAD_MAX_NS);

	/* Atomic SGD updates over the shared fill with LEARN_SHIFT 11. */
	/* The s32 clamp keeps the cast with no truncate, so a huge */
	/* burst never wraps the weight add with lag plus share already */
	/* bounded with no extra cap. */
	{
		grad = (err * (s64)(feat.avg >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_avg, flow_ml_grad_s32(grad));

		grad = (err * (s64)(feat.dev >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_dev, flow_ml_grad_s32(grad));

		grad = (err * ((s64)feat.lag >> 4)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_lag, flow_ml_grad_s32(grad));

		grad = (err * (s64)(feat.sleep >> 6)) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_sleep, flow_ml_grad_s32(grad));

		grad = (err * (s64)feat.w) >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->w_weight, flow_ml_grad_s32(grad));

		grad = err >> FLOW_ML_LEARN_SHIFT;
		__sync_fetch_and_add(&m->bias, flow_ml_grad_s32(grad));
	}

	/* Bump the train count with a CAS loop at max, so concurrent */
	/* trains never wrap past max with no lost bump. Per CPU stats */
	/* saturate without a loop since each CPU owns its row, while */
	/* this global row needs the loop with no lock. */
	{
		s32 i;
		bpf_for(i, 0, 4) {
			u32 cur = READ_ONCE(m->update_count);
			u32 old;
			if (cur == 0xffffffffU)
				break;
			old = __sync_val_compare_and_swap(&m->update_count,
			    cur, cur + 1);
			if (old == cur)
				break;
		}
	}

	/* Clamp each weight to plus or minus 524288 with CAS plus retry. */
	flow_ml_clamp_one(&m->w_avg);
	flow_ml_clamp_one(&m->w_dev);
	flow_ml_clamp_one(&m->w_lag);
	flow_ml_clamp_one(&m->w_sleep);
	flow_ml_clamp_one(&m->w_weight);
	flow_ml_clamp_one(&m->bias);

	/* Drift the learnable RED bounds by one small step on the */
	/* per-sample hit signal with outer clamps plus CAS plus one retry, */
	/* so ML owns admit plus drop with safety still checked and the */
	/* aggregate accuracy never gates a decision. A hit tightens toward */
	/* the defaults by 16ns for tolerance plus 64ns for Emax, a miss */
	/* widens by 64ns plus 256ns, each within outer 0 to 256us plus */
	/* 64us to 1ms with no storm. The asymmetric step needs near 80% */
	/* hits to hold steady, so weak accuracy drifts to the outer with */
	/* safety still checked. Legacy rows with version past 1 skip with */
	/* no write, so old headers never drive the bounds. Outlined with */
	/* no extra inline growth. */
	flow_ml_drift(m, acc_hit);
}
