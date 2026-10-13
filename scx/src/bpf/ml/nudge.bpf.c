// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline nudge for the flow scheduler at 4.8.14.
 *
 * Holds the inference dot product that maps task features through the
 * global online model to one capped correction with integer shifts
 * only. The score sums burst capped avg plus dev plus sleep at the
 * quantum plus direct lag plus share times their weights with FP_SHIFT
 * 8 plus bias, then clamps to plus or minus 250us, so one nudge never
 * holds past one quarter quantum. Each saturation counts one clamped
 * event with no wrap, so the snapshot tracks how often the model hits
 * its outer. ML shapes the fair key that drives tier plus kick with
 * PRIQ only plus outer safety still checked, while placement tests
 * the deadline plus drain. Accuracy stays observability-only with no
 * closed-loop gate. A missing row or a null task fails closed to zero,
 * so the deterministic shift-3 EMA baseline owns deadline math. Runs
 * with shifts plus 64-bit multiplies, so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/**
 * flow_ml_deadline_nudge - capped correction from task features.
 * @tctx: task state with avg plus dev plus vlag, null fails closed.
 * @sleep_ns: sleep time in nanos from the caller wrap-safe helper.
 * @eff_w: effective share from task times hint over 128.
 *
 * Forms the fixed point score plus bias with FP_SHIFT 8 over burst
 * capped inputs at the quantum plus direct lag plus share, reads the
 * stored max clamp with fail closed to 250us when the row holds zero
 * or past 250us, then clamps the score to that bound with one clamped
 * count on saturation. Burst caps keep a huge avg plus dev plus sleep
 * from saturating the score on every call, so train plus infer agree
 * where it matters with no wrap while lag stays within plus or minus
 * 2ms via the lag bound plus share stays within 1 to 16384 via the
 * effective helper with no extra cap. Three burst caps keep the
 * enqueue verifier under one million with no extra branch past the
 * bound. A cross-task row stays global by design with the bound plus
 * fail closed keeping one task from holding another past one quarter
 * quantum. The shaped fair key drives tier plus kick with outer margin
 * plus tail still checked, while placement tests the deadline, so ML
 * shapes order with bounds and stays observability-only on accuracy.
 * Like fair.c, the nudge paces order, unlike rt.c, no fixed priority
 * holds.
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
	struct flow_ml_feat feat;
	s64 score = 0;
	s64 max_nudge;

	if (!tctx)
		return 0;

	m = bpf_map_lookup_elem(&ml_online_model_stor, &key);
	if (!m)
		return 0;

	/* Burst caps at the quantum match train through the shared fill, */
	/* so infer never saturates past the train range on huge inputs. */
	/* Lag stays within plus or minus 2ms via the lag bound plus share */
	/* stays within 1 to 16384 via the effective helper, so no extra */
	/* cap keeps the verifier under one million with train plus infer */
	/* agreeing on bursts. Reuses the same feat plus score as train */
	/* with no second dot copy. */
	flow_ml_feat(tctx, sleep_ns, eff_w, &feat);
	score = flow_ml_score(&feat, m);

	max_nudge = (s64)READ_ONCE(m->max_clamp_ns);
	if (max_nudge <= 0 || max_nudge > (s64)FLOW_ML_NUDGE_MAX_NS)
		max_nudge = (s64)FLOW_ML_NUDGE_MAX_NS;

	if (score > max_nudge) {
		flow_count_ml_clamped();
		return max_nudge;
	}
	if (score < -max_nudge) {
		flow_count_ml_clamped();
		return -max_nudge;
	}
	return score;
}
