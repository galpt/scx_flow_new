// SPDX-License-Identifier: GPL-2.0
/*
 * vEB scalar helpers for the flow core.
 *
 * Holds quantize, high, low, bit scans.
 * Quantize maps deadlines to keys with saturate at top.
 * High splits the high eight bits. Low splits the low eight bits.
 * Bit scans find first and last set bits within one word.
 * Map shims bound every index so the verifier sees safe access.
 * All helpers stay small so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __always_inline u32 veb_quant(u64 deadline)
{
	u64 k = deadline >> FLOW_QUANT_SHIFT;
	if (k > 65535ULL)
		k = 65535ULL;
	return (u32)k;
}
static __always_inline u32 veb_high(u32 k)
{
	return k >> 8;
}
static __always_inline u32 veb_low(u32 k)
{
	return k & 255U;
}
static __noinline int veb_first_bit(u64 w)
{
	int i;
	bpf_for(i, 0, 64) {
		u64 bit;
		if (i < 0 || i >= 64)
			continue;
		bit = 1ULL << (u64)i;
		if (w & bit)
			return i;
	}
	return 64;
}
static __noinline int veb_last_bit(u64 w)
{
	int i;
	bpf_for(i, 0, 64) {
		int b = 63 - i;
		u64 bit;
		if (b < 0 || b >= 64)
			continue;
		bit = 1ULL << (u64)b;
		if (w & bit)
			return b;
	}
	return -1;
}
static __always_inline u64 *veb_sum_ptr(u32 idx)
{
	if (idx >= 4)
		return 0;
	return bpf_map_lookup_elem(&veb_summary, &idx);
}
static __always_inline u64 *veb_clu_ptr(u32 idx)
{
	if (idx >= 1024)
		return 0;
	return bpf_map_lookup_elem(&veb_clusters, &idx);
}
static __always_inline u32 *veb_cnt_ptr(u32 k)
{
	if (k >= 65536)
		return 0;
	return bpf_map_lookup_elem(&veb_counts, &k);
}
static __always_inline struct veb_root *veb_root_ptr(void)
{
	u32 k = 0;
	return bpf_map_lookup_elem(&veb_root, &k);
}
