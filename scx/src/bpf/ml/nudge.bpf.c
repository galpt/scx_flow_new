// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline nudge for the flow scheduler.
 *
 * Holds the inference dot product that maps task features through the
 * global online model to one capped correction with integer shifts
 * only. The score sums avg plus dev plus vlag plus sleep plus eff_w
 * times their weights with FP_SHIFT 8 plus bias, then clamps to plus
 * or minus 250us, so one nudge never holds past one quarter quantum.
 * A missing row or a null task fails closed to zero,
 * so the deterministic shift-3 EMA baseline owns deadline math.
 * Runs with shifts plus 64-bit multiplies, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_ml_deadline_nudge - capped correction from task features.
 * @tctx: task state with avg plus dev plus vlag, null fails closed.
 * @sleep_ns: sleep time in nanos from the caller wrap-safe helper.
 * @eff_w: effective share from task times hint over 128.
 *
 * Forms the fixed point score plus bias with FP_SHIFT 8 over capped
 * inputs, reads the stored max clamp with fail closed to 250us when
 * the row holds zero or past 250us, then clamps the score to that
 * bound. A cross-task row stays global by design with the bound plus
 * fail closed keeping one task from holding another past one quarter
 * quantum. Like fair.c, the nudge paces order, unlike rt.c, no fixed
 * priority holds.
 *
 * Outlined with noinline to keep verifier headroom with one shared
 * copy. Called from the enqueue path; returns zero when state missing.
 *
 * Returns: clamped nudge in nanos from minus 250us to 250us, zero on
 * missing state.
 */
static __noinline s64 flow_ml_deadline_nudge(const struct flow_task_ctx *tctx,
	u64 sleep_ns, u32 eff_w)
{
	u32 key = 0;
	struct flow_online_model *m;
	s64 score = 0;
	s64 max_nudge;

	if (!tctx)
		return 0;

	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return 0;

	/* Capped dot product, so a huge burst never saturates the nudge. */
	{
		u64 c_avg = flow_ml_cap_burst((u64)READ_ONCE(tctx->avg_ns));
		u64 c_dev = flow_ml_cap_burst((u64)READ_ONCE(tctx->dev_ns));
		s32 c_lag = flow_ml_cap_lag(READ_ONCE(tctx->vlag));
		u64 c_sleep = flow_ml_cap_burst(sleep_ns);
		u32 c_w = flow_ml_cap_w(eff_w);
		score += ((s64)(c_avg >> 4) *
		    (s64)READ_ONCE(m->w_avg)) >> (FLOW_ML_FP_SHIFT - 4);
		score += ((s64)(c_dev >> 4) *
		    (s64)READ_ONCE(m->w_dev)) >> (FLOW_ML_FP_SHIFT - 4);
		score += ((s64)c_lag *
		    (s64)READ_ONCE(m->w_lag)) >> FLOW_ML_FP_SHIFT;
		score += ((s64)(c_sleep >> 4) *
		    (s64)READ_ONCE(m->w_sleep)) >> (FLOW_ML_FP_SHIFT - 4);
		score += ((s64)c_w *
		    (s64)READ_ONCE(m->w_weight)) >> FLOW_ML_FP_SHIFT;
		score += (s64)READ_ONCE(m->bias);
	}

	max_nudge = (s64)READ_ONCE(m->max_clamp_ns);
	if (max_nudge <= 0 || max_nudge > (s64)FLOW_ML_NUDGE_MAX_NS)
		max_nudge = (s64)FLOW_ML_NUDGE_MAX_NS;

	if (score > max_nudge)
		return max_nudge;
	if (score < -max_nudge)
		return -max_nudge;
	return score;
}
