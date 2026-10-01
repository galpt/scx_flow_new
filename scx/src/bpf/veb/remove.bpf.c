// SPDX-License-Identifier: GPL-2.0
/*
 * vEB remove helper for the flow core.
 *
 * Holds one pid remove with last key cleanup and root refresh.
 * Lifecycle owns its pid row on stopping, disable, exit so unkeyed
 * remove drops solely its own key with teardown as the single reaper
 * and the hot path keeping no deletes. Last key clears cluster and
 * summary bits then refreshes root.
 * A zero count still clears stale bits so empty keys never linger.
 * Counts drop with compare and swap so concurrent CPUs stay
 * consistent. Four tries then give up with one park and the next
 * remove retries the same key. Bit clears retry four times then
 * give up as benign with the next remove retrying the same bit.
 * Callers with a per CPU view use the keyed remove so a reused pid
 * never drops a fresh key. Faults fail closed with parks.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __noinline void veb_clear_clu_bit(u32 idx, u64 bit)
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
		if (!(cur & bit))
			return;
		nxt = cur & ~bit;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return;
	}
}
static __noinline void veb_clear_sum_bit(u32 idx, u64 bit)
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
		if (!(cur & bit))
			return;
		nxt = cur & ~bit;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return;
	}
}
static __noinline bool veb_cluster_empty(u32 h)
{
	int w;
	if (h >= 256)
		return true;
	bpf_for(w, 0, 4) {
		u32 idx;
		u64 *p;
		if (w < 0 || w >= 4)
			continue;
		idx = h * 4 + (u32)w;
		p = veb_clu_ptr(idx);
		if (!p)
			continue;
		if (READ_ONCE(*p))
			return false;
	}
	return true;
}
static __noinline void veb_root_remove(u32 k)
{
	struct veb_root *r = veb_root_ptr();
	u32 cmn;
	u32 cmx;
	u32 nmn;
	u32 nmx;
	int i;
	if (!r)
		return;
	cmn = veb_cached_min();
	cmx = veb_cached_max();
	if (k != cmn && k != cmx)
		return;
	if (k == cmn) {
		nmn = veb_scan_min();
		if (nmn == (u32)FLOW_VEB_EMPTY) {
			u32 old = __sync_val_compare_and_swap(&r->has, 1, 0);
			if (old == 1) {
				WRITE_ONCE(r->min, (u32)FLOW_VEB_EMPTY);
				WRITE_ONCE(r->max, (u32)FLOW_VEB_EMPTY);
			}
		} else {
			bpf_for(i, 0, 4) {
				u32 cur = READ_ONCE(r->min);
				u32 old;
				if (cur != k)
					break;
				old = __sync_val_compare_and_swap(&r->min, cur, nmn);
				if (old == cur)
					break;
			}
		}
	}
	if (k == cmx) {
		nmx = veb_scan_max();
		if (nmx == (u32)FLOW_VEB_EMPTY) {
			u32 old = __sync_val_compare_and_swap(&r->has, 1, 0);
			if (old == 1) {
				WRITE_ONCE(r->min, (u32)FLOW_VEB_EMPTY);
				WRITE_ONCE(r->max, (u32)FLOW_VEB_EMPTY);
			}
		} else {
			bpf_for(i, 0, 4) {
				u32 cur = READ_ONCE(r->max);
				u32 old;
				if (cur != k)
					break;
				old = __sync_val_compare_and_swap(&r->max, cur, nmx);
				if (old == cur)
					break;
			}
		}
	}
}
static __noinline bool veb_remove(u32 pid)
{
	u32 *kp;
	u32 k;
	u32 h;
	u32 l;
	u32 cidx;
	u64 cbit;
	bool zero_found = false;
	bool dropped = false;
	int i;
	if (pid == 0)
		return false;
	kp = bpf_map_lookup_elem(&veb_pid, &pid);
	if (!kp)
		return false;
	k = READ_ONCE(*kp);
	if (k >= (u32)FLOW_VEB_U) {
		bpf_map_delete_elem(&veb_pid, &pid);
		return false;
	}
	bpf_for(i, 0, 4) {
		u32 *cntp = veb_cnt_ptr(k);
		u32 cur;
		u32 nxt;
		u32 old;
		if (!cntp) {
			bpf_map_delete_elem(&veb_pid, &pid);
			return false;
		}
		cur = READ_ONCE(*cntp);
		if (cur == 0) {
			bpf_map_delete_elem(&veb_pid, &pid);
			zero_found = true;
			break;
		}
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(cntp, cur, nxt);
		if (old != cur)
			continue;
		bpf_map_delete_elem(&veb_pid, &pid);
		if (cur != 1)
			return true;
		dropped = true;
		break;
	}
	if (!dropped && !zero_found) {
		__sync_fetch_and_add(&flow_stats.parks, 1);
		return false;
	}
	h = veb_high(k);
	l = veb_low(k);
	cidx = h * 4 + (l >> 6);
	if (cidx >= 1024)
		return true;
	cbit = 1ULL << (u64)(l & 63);
	{
		u32 *cntp = veb_cnt_ptr(k);
		if (cntp && READ_ONCE(*cntp) != 0)
			return true;
	}
	veb_clear_clu_bit(cidx, cbit);
	if (veb_cluster_empty(h)) {
		u32 sidx = h >> 6;
		if (sidx < 4) {
			u64 sbit = 1ULL << (u64)(h & 63);
			veb_clear_sum_bit(sidx, sbit);
		}
	}
	veb_root_remove(k);
	return true;
}
