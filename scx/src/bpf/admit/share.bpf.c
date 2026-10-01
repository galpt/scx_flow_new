// SPDX-License-Identifier: GPL-2.0
/*
 * Admitted share math plus per CPU ledger for the flow core.
 *
 * Holds the per CPU admitted sums with saturating add plus drop.
 * Shares derive from the fixed slice over the weight derived period
 * with the same clamp plus period plus permille math as the daemon
 * oracle. Adds check the nine hundred fifty bound before the store
 * so use stays feasible. Drops floor at zero so a double drop never
 * goes negative. Compare and swap loops retry four times then give
 * up as benign with the next op retrying the same value. All helpers
 * stay small so the verifier stays small. Ledger lives in the core
 * with rings as observability solely.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
static __always_inline u64 *flow_admitted_ptr(u32 cpu)
{
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return 0;
	return bpf_map_lookup_elem(&admitted_stor, &cpu);
}
static __noinline bool flow_admit_try_add(u32 cpu, u64 share)
{
	int i;
	u64 *p;
	if (share == 0)
		return true;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	p = flow_admitted_ptr(cpu);
	if (!p)
		return false;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*p);
		u64 nxt;
		u64 old;
		if (!flow_admit_ok(cur, share))
			return false;
		nxt = cur + share;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return true;
	}
	return false;
}
static __noinline void flow_admitted_sub(u32 cpu, u64 share)
{
	int i;
	u64 *p;
	if (share == 0)
		return;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	p = flow_admitted_ptr(cpu);
	if (!p)
		return;
	bpf_for(i, 0, 4) {
		u64 cur = READ_ONCE(*p);
		u64 nxt;
		u64 old;
		if (cur >= share)
			nxt = cur - share;
		else
			nxt = 0;
		old = __sync_val_compare_and_swap(p, cur, nxt);
		if (old == cur)
			return;
	}
}
