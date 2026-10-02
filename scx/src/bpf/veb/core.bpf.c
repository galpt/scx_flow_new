// SPDX-License-Identifier: GPL-2.0
/*
 * vEB scalar helpers for the flow core.
 *
 * Holds quantize, high, low, bit scans.
 * Quantize maps deadlines to keys with saturate at top.
 * High splits the high eight bits. Low splits the low eight bits.
 * Bit scans use count trailing plus leading zeros with zero check
 * so one word resolves in constant time. Map shims bound every
 * index so the verifier sees safe access. All helpers stay small
 * so the verifier stays small. Root updates race across CPUs and
 * readers take the smaller of cached plus scan so stale high views
 * never miss live low keys.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __always_inline u32 veb_quant(u64 deadline)
{
	u64 k = deadline >> FLOW_QUANT_SHIFT;
	if (k >= (u64)FLOW_VEB_U)
		k = (u64)FLOW_VEB_U - 1;
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
static __always_inline int veb_first_bit(u64 w)
{
	if (!w)
		return 64;
	return __builtin_ctzll(w);
}
static __always_inline int veb_last_bit(u64 w)
{
	if (!w)
		return -1;
	return 63 - __builtin_clzll(w);
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
	if (k >= (u32)FLOW_VEB_U)
		return 0;
	return bpf_map_lookup_elem(&veb_counts, &k);
}
static __always_inline struct veb_root *veb_root_ptr(void)
{
	u32 k = 0;
	return bpf_map_lookup_elem(&veb_root, &k);
}
