// SPDX-License-Identifier: GPL-2.0
/*
 * vEB least and greatest helpers for the flow core.
 *
 * Holds cached reads and bitmap scans for least and greatest.
 * Cached reads use the root with fail closed empty on faults.
 * Scans walk summary then clusters with bounded loops.
 * The least helper takes the smaller of cached and scan so stale
 * high views never miss live low keys. All helpers stay bounded
 * so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline u32 veb_cluster_first(u32 h)
{
	int w;
	if (h >= 256)
		return 256;
	bpf_for(w, 0, 4) {
		u32 idx;
		u64 *p;
		u64 v;
		int b;
		if (w < 0 || w >= 4)
			continue;
		idx = h * 4 + (u32)w;
		p = veb_clu_ptr(idx);
		if (!p)
			continue;
		v = READ_ONCE(*p);
		if (!v)
			continue;
		b = veb_first_bit(v);
		if (b < 0 || b >= 64)
			continue;
		return (u32)w * 64 + (u32)b;
	}
	return 256;
}
static __noinline u32 veb_cluster_last(u32 h)
{
	int w;
	u32 best = 256;
	if (h >= 256)
		return 256;
	bpf_for(w, 0, 4) {
		u32 idx;
		u64 *p;
		u64 v;
		int b;
		if (w < 0 || w >= 4)
			continue;
		idx = h * 4 + (u32)w;
		p = veb_clu_ptr(idx);
		if (!p)
			continue;
		v = READ_ONCE(*p);
		if (!v)
			continue;
		b = veb_last_bit(v);
		if (b < 0 || b >= 64)
			continue;
		best = (u32)w * 64 + (u32)b;
	}
	if (best >= 256)
		return 256;
	return best;
}
static __noinline u32 veb_scan_min(void)
{
	int w;
	bpf_for(w, 0, 4) {
		u32 idx;
		u64 *p;
		u64 v;
		int b;
		u32 h;
		u32 l;
		if (w < 0 || w >= 4)
			continue;
		idx = (u32)w;
		p = veb_sum_ptr(idx);
		if (!p)
			continue;
		v = READ_ONCE(*p);
		if (!v)
			continue;
		b = veb_first_bit(v);
		if (b < 0 || b >= 64)
			continue;
		h = (u32)w * 64 + (u32)b;
		if (h >= 256)
			continue;
		l = veb_cluster_first(h);
		if (l >= 256)
			continue;
		return h * 256 + l;
	}
	return 0xFFFFFFFFU;
}
static __noinline u32 veb_scan_max(void)
{
	int w;
	bpf_for(w, 0, 4) {
		int r = 3 - w;
		u32 idx;
		u64 *p;
		u64 v;
		int b;
		u32 h;
		u32 l;
		if (r < 0 || r >= 4)
			continue;
		idx = (u32)r;
		p = veb_sum_ptr(idx);
		if (!p)
			continue;
		v = READ_ONCE(*p);
		if (!v)
			continue;
		b = veb_last_bit(v);
		if (b < 0 || b >= 64)
			continue;
		h = (u32)r * 64 + (u32)b;
		if (h >= 256)
			continue;
		l = veb_cluster_last(h);
		if (l >= 256)
			continue;
		return h * 256 + l;
	}
	return 0xFFFFFFFFU;
}
static __noinline u32 veb_cached_min(void)
{
	struct veb_root *r = veb_root_ptr();
	if (!r)
		return 0xFFFFFFFFU;
	if (!READ_ONCE(r->has))
		return 0xFFFFFFFFU;
	return READ_ONCE(r->min);
}
static __noinline u32 veb_cached_max(void)
{
	struct veb_root *r = veb_root_ptr();
	if (!r)
		return 0xFFFFFFFFU;
	if (!READ_ONCE(r->has))
		return 0xFFFFFFFFU;
	return READ_ONCE(r->max);
}
static __noinline u32 veb_min(void)
{
	u32 c = veb_cached_min();
	u32 s = veb_scan_min();
	if (c == 0xFFFFFFFFU)
		return s;
	if (s == 0xFFFFFFFFU)
		return c;
	if (c < s)
		return c;
	return s;
}
