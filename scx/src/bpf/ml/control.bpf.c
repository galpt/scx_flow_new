// SPDX-License-Identifier: GPL-2.0
/*
 * ML control for the flow scheduler at 4.8.14.
 *
 * Holds the learnable RED bounds that let ML own admit plus drop with
 * outer safety still checked. Tolerance learns within outer 0 to 256us
 * defaulting to 64us, Emax learns within outer 64us to 1ms defaulting
 * to 256us, each clamped to its outer with defaults on miss or legacy
 * version. Critical tolerance stays zero with no learned slack, so
 * urgent work stays strict. Placement plus kick ride the capped nudge
 * shaped fair key with PRIQ only, so one learnable input drives all
 * four decisions with bounds. Runs with one map read plus clamps, so
 * the verifier stays small.
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
