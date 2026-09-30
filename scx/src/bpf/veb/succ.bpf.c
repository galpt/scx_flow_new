// SPDX-License-Identifier: GPL-2.0
/*
 * vEB successor helper for the flow core.
 *
 * Holds the least key above one key with fail closed empty.
 * The helper checks home cluster, summary, next cluster.
 * All steps use bounded loops so the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline u32 veb_succ(u32 x)
{
	u32 h;
	u32 l;
	u32 hw;
	u32 hb;
	u32 idx;
	u64 *p;
	u64 v;
	u64 mask;
	u64 masked;
	int b;
	int w;
	if (x >= 65535)
		return 0xFFFFFFFFU;
	if (x >= 65536)
		return 0xFFFFFFFFU;
	h = veb_high(x);
	l = veb_low(x);
	if (h >= 256)
		return 0xFFFFFFFFU;
	hw = l >> 6;
	hb = l & 63;
	if (hw < 4) {
		idx = h * 4 + hw;
		p = veb_clu_ptr(idx);
		if (p) {
			v = READ_ONCE(*p);
			if (hb >= 63)
				mask = 0;
			else
				mask = ~0ULL << (hb + 1);
			masked = v & mask;
			if (masked) {
				b = veb_first_bit(masked);
				if (b >= 0 && b < 64)
					return h * 256 + hw * 64 + (u32)b;
			}
		}
		bpf_for(w, 0, 4) {
			int cand = (int)hw + 1 + w;
			u32 ww;
			if (cand < 0 || cand >= 4)
				continue;
			ww = (u32)cand;
			idx = h * 4 + ww;
			p = veb_clu_ptr(idx);
			if (!p)
				continue;
			v = READ_ONCE(*p);
			if (!v)
				continue;
			b = veb_first_bit(v);
			if (b < 0 || b >= 64)
				continue;
			return h * 256 + ww * 64 + (u32)b;
		}
	}
	{
		u32 sh = h >> 6;
		u32 sb = h & 63;
		if (sh < 4) {
			idx = sh;
			p = veb_sum_ptr(idx);
			if (p) {
				v = READ_ONCE(*p);
				if (sb >= 63)
					mask = 0;
				else
					mask = ~0ULL << (sb + 1);
				masked = v & mask;
				if (masked) {
					b = veb_first_bit(masked);
					if (b >= 0 && b < 64) {
						u32 h2 = sh * 64 + (u32)b;
						u32 l2;
						if (h2 < 256) {
							l2 = veb_cluster_first(h2);
							if (l2 < 256)
								return h2 * 256 + l2;
						}
					}
				}
			}
			bpf_for(w, 0, 4) {
				int cand = (int)sh + 1 + w;
				u32 sw;
				u64 sv;
				int sb2;
				u32 h2;
				u32 l2;
				if (cand < 0 || cand >= 4)
					continue;
				sw = (u32)cand;
				p = veb_sum_ptr(sw);
				if (!p)
					continue;
				sv = READ_ONCE(*p);
				if (!sv)
					continue;
				sb2 = veb_first_bit(sv);
				if (sb2 < 0 || sb2 >= 64)
					continue;
				h2 = sw * 64 + (u32)sb2;
				if (h2 >= 256)
					continue;
				l2 = veb_cluster_first(h2);
				if (l2 >= 256)
					continue;
				return h2 * 256 + l2;
			}
		}
	}
	return 0xFFFFFFFFU;
}
