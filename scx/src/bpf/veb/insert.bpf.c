// SPDX-License-Identifier: GPL-2.0
/*
 * vEB insert helper for the flow core.
 *
 * Holds one key insert with duplicate check and saturate.
 * Same key duplicates return at once with no refresh. Fresh keys
 * drop the old key then join the fresh key. Counts bump first then pid links then bits plus root follow
 * so a full pid map never leaves phantom keys. Root least and
 * greatest move solely outward with compare and swap so concurrent
 * CPUs never miss live low keys. Bit sets retry four times then
 * give up as benign with the next insert retrying the same bit.
 * Count compare and swap gives up after four tries with one park.
 * Faults fail closed with parks.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void veb_set_clu_bit(u32 idx, u64 bit)
{
	int i;
	bpf_for(i, 0, 4) {
		u64 *p;
		u64 cur;
		u64 nxt;
		u64 old;
		p = veb_clu_ptr(idx);
		if (!p)
			return;
		cur = READ_ONCE(*p);
		if (cur & bit)
			return;
		nxt = cur | bit;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return;
	}
}
static __noinline void veb_set_sum_bit(u32 idx, u64 bit)
{
	int i;
	bpf_for(i, 0, 4) {
		u64 *p;
		u64 cur;
		u64 nxt;
		u64 old;
		p = veb_sum_ptr(idx);
		if (!p)
			return;
		cur = READ_ONCE(*p);
		if (cur & bit)
			return;
		nxt = cur | bit;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return;
	}
}
static __noinline void veb_root_insert(u32 k)
{
	struct veb_root *r;
	int i;
	r = veb_root_ptr();
	if (!r)
		return;
	if (!READ_ONCE(r->has)) {
		u32 old = __sync_val_compare_and_swap(&r->has, 0, 1);
		if (old == 0) {
			WRITE_ONCE(r->min, k);
			WRITE_ONCE(r->max, k);
			return;
		}
	}
	bpf_for(i, 0, 4) {
		u32 cur = READ_ONCE(r->min);
		u32 old;
		if (k >= cur)
			break;
		old = __sync_val_compare_and_swap(&r->min, cur, k);
		if (old == cur)
			break;
	}
	bpf_for(i, 0, 4) {
		u32 cur = READ_ONCE(r->max);
		u32 old;
		if (k <= cur)
			break;
		old = __sync_val_compare_and_swap(&r->max, cur, k);
		if (old == cur)
			break;
	}
}
static __noinline void veb_insert(u32 pid, u64 deadline)
{
	u32 k;
	u32 h;
	u32 l;
	u32 cidx;
	u32 sidx;
	u64 cbit;
	u64 sbit;
	u32 *oldp;
	bool done = false;
	int i;
	if (pid == 0)
		return;
	k = veb_quant(deadline);
	oldp = bpf_map_lookup_elem(&veb_pid, &pid);
	if (oldp) {
		u32 old = READ_ONCE(*oldp);
		if (old == k)
			return;
		veb_remove(pid);
	}
	h = veb_high(k);
	l = veb_low(k);
	cidx = h * 4 + (l >> 6);
	sidx = h >> 6;
	if (cidx >= 1024 || sidx >= 4)
		return;
	cbit = 1ULL << (u64)(l & 63);
	sbit = 1ULL << (u64)(h & 63);
	bpf_for(i, 0, 4) {
		u32 *cntp = veb_cnt_ptr(k);
		u32 cur;
		u32 nxt;
		u32 old;
		long upd;
		int j;
		if (!cntp)
			return;
		cur = READ_ONCE(*cntp);
		if (cur == (u32)FLOW_VEB_EMPTY) {
			__sync_fetch_and_add(&flow_stats.parks, 1);
			return;
		}
		nxt = cur + 1;
		old = __sync_val_compare_and_swap(cntp, cur, nxt);
		if (old != cur)
			continue;
		upd = bpf_map_update_elem(&veb_pid, &pid, &k, BPF_ANY);
		if (upd != 0) {
			bpf_for(j, 0, 4) {
				u32 *rp = veb_cnt_ptr(k);
				u32 rc;
				u32 rn;
				u32 ro;
				if (!rp)
					break;
				rc = READ_ONCE(*rp);
				if (rc == 0)
					break;
				rn = rc - 1;
				ro = __sync_val_compare_and_swap(rp, rc, rn);
				if (ro == rc)
					break;
			}
			__sync_fetch_and_add(&flow_stats.parks, 1);
			return;
		}
		veb_set_clu_bit(cidx, cbit);
		veb_set_sum_bit(sidx, sbit);
		if (cur == 0)
			veb_root_insert(k);
		done = true;
		break;
	}
	if (!done)
		__sync_fetch_and_add(&flow_stats.parks, 1);
}
