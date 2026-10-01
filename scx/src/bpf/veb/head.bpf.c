// SPDX-License-Identifier: GPL-2.0
/*
 * Head plus placement hints for the flow core.
 *
 * Holds one head entry per low key byte with the earliest deadline
 * then smallest pid for that slot, plus one placement entry per task
 * hash with the last admitted CPU. The head lets the least pick try
 * one cached pid with a single task read instead of a full tail walk,
 * while the placement hint steers the next park toward the previous
 * owner when still allowed. The head skips the owned tiebreak, so the
 * smallest pid wins within the same key plus deadline while the full
 * scan still uses owned then pid. Both stay best effort with
 * validation before use and no extra counter, so stale views fall
 * back with no wrong move. Heads clear on ordered plus FIFO moves
 * plus the teardown drop, so a running pid never lingers as a head.
 * A moved owner heals in place, so migration keeps the hit with no
 * extra scan. All helpers stay small with no loop so the verifier
 * stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
struct flow_head {
	u32 key;
	u32 pid;
	u64 deadline;
	u32 owner;
	u32 pad;
};
struct flow_place {
	u32 pid;
	u32 cpu;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct flow_head);
} head_by_low SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct flow_place);
} place_by_pid SEC(".maps");
/* Head store with earliest deadline then smallest pid in one place. */
/* Gives the cached head for the low byte, keeping the earliest */
/* deadline then smallest pid for the same key and overwriting on a */
/* new key with no extra lookup. Owned stays out here, so the */
/* smallest pid wins within the same key plus deadline while the */
/* full scan still uses owned then pid. Stale heads clear on ordered */
/* plus FIFO moves plus the teardown drop, so a miss falls back with */
/* no wrong move. */
/* Noinline with scalar inputs so the admit path verifies once apart */
/* from the enqueue entry. */
static __noinline void flow_head_store(u32 pid, u32 key,
	u64 deadline, u32 owner)
{
	u32 slot;
	struct flow_head *h;
	u32 ck;
	u32 cp;
	u64 cd;
	if (pid == 0)
		return;
	if (key >= (u32)FLOW_VEB_U)
		return;
	if (deadline == 0)
		return;
	if ((u64)owner >= (u64)FLOW_MAX_CPUS)
		return;
	slot = key & 255;
	if (slot >= 256)
		return;
	h = bpf_map_lookup_elem(&head_by_low, &slot);
	if (!h)
		return;
	ck = READ_ONCE(h->key);
	cp = READ_ONCE(h->pid);
	cd = READ_ONCE(h->deadline);
	if (cp == 0 || ck != key) {
		WRITE_ONCE(h->key, key);
		WRITE_ONCE(h->pid, pid);
		WRITE_ONCE(h->deadline, deadline);
		WRITE_ONCE(h->owner, owner);
		return;
	}
	if (deadline < cd) {
		WRITE_ONCE(h->pid, pid);
		WRITE_ONCE(h->deadline, deadline);
		WRITE_ONCE(h->owner, owner);
		return;
	}
	if (deadline == cd && pid < cp) {
		WRITE_ONCE(h->pid, pid);
		WRITE_ONCE(h->owner, owner);
	}
}
/* Head pick with one cached pid in one place. */
/* Reads the least key inside with the cached pid for that key, giving */
/* true with the live task values when it still holds share plus key */
/* with mask, so the least pick skips the full tail walk. A moved owner */
/* heals in place, so a repark on another CPU keeps the hit with live */
/* values while pid plus key plus deadline still guard reuse. Owned */
/* stays out of the head order, so the smallest pid wins within the same */
/* key plus deadline while the full scan still uses owned then pid. */
/* Stale views miss with no state, so the caller falls back to the full */
/* scan. Noinline with scalar CPU so the pick path verifies once apart */
/* from the dispatch entry with no stack args. */
static __noinline bool flow_head_pick(s32 cpu,
	u32 *out_pid, u32 *out_key, u64 *out_deadline, u32 *out_owner)
{
	u32 want_key;
	u32 slot;
	struct flow_head *h;
	u32 pid;
	struct task_struct *t;
	u32 tpid;
	struct flow_task_ctx *tctx;
	u32 k;
	u64 d;
	u32 owner;
	u32 want_owner;
	bool ok = false;
	if (cpu < 0)
		return false;
	if (!flow_cpu_live((u32)cpu))
		return false;
	want_key = veb_min();
	if (want_key >= (u32)FLOW_VEB_U)
		return false;
	if (want_key == (u32)FLOW_VEB_EMPTY)
		return false;
	slot = want_key & 255;
	if (slot >= 256)
		return false;
	h = bpf_map_lookup_elem(&head_by_low, &slot);
	if (!h)
		return false;
	if (READ_ONCE(h->key) != want_key)
		return false;
	pid = READ_ONCE(h->pid);
	if (pid == 0)
		return false;
	want_owner = READ_ONCE(h->owner);
	t = bpf_task_from_pid(pid);
	if (!t)
		return false;
	tpid = (u32)t->pid;
	if (tpid != pid)
		goto out;
	if (!flow_mask_ok(cpu, t))
		goto out;
	tctx = flow_lookup(t);
	if (!tctx)
		goto out;
	if (READ_ONCE(tctx->admit_share) == 0)
		goto out;
	k = READ_ONCE(tctx->key);
	if (k != want_key)
		goto out;
	d = READ_ONCE(tctx->deadline);
	if (d == 0)
		goto out;
	owner = READ_ONCE(tctx->admit_cpu);
	if ((u64)owner >= (u64)FLOW_MAX_CPUS)
		goto out;
	if (owner != want_owner) {
		/* Heal the slot to the live owner, so migration keeps */
		/* warmth with no extra scan while pid plus key plus */
		/* deadline still guard reuse. */
		WRITE_ONCE(h->owner, owner);
	}
	/* Callers pass non null outputs, so no null branch here. */
	*out_pid = tpid;
	*out_key = k;
	*out_deadline = d;
	*out_owner = owner;
	ok = true;
out:
	bpf_task_release(t);
	return ok;
}
/* Head clear with key plus pid match in one place. */
/* Clears the slot solely when it still holds the given pid with the */
/* same key, so ordered plus FIFO moves plus the teardown drop free */
/* the slot while other keys stay. Noinline with scalar inputs so moves */
/* plus drops verify once apart from their callers. */
static __noinline void flow_head_clear(u32 pid, u32 key)
{
	u32 slot;
	struct flow_head *h;
	if (pid == 0)
		return;
	if (key >= (u32)FLOW_VEB_U)
		return;
	slot = key & 255;
	if (slot >= 256)
		return;
	h = bpf_map_lookup_elem(&head_by_low, &slot);
	if (!h)
		return;
	if (READ_ONCE(h->key) != key)
		return;
	if (READ_ONCE(h->pid) != pid)
		return;
	WRITE_ONCE(h->pid, 0);
	WRITE_ONCE(h->deadline, 0);
	WRITE_ONCE(h->owner, 0);
}
/* Placement store with task hash in one place. */
/* Holds the last admitted CPU for the task hash with overwrite, so */
/* the next park can try the previous owner when still allowed. */
/* Best effort with no clear, since revalidation drops stale views. */
/* Noinline with scalar inputs so the admit path verifies once. */
static __noinline void flow_place_store(u32 pid, u32 cpu)
{
	u32 slot;
	struct flow_place *h;
	if (pid == 0)
		return;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	slot = pid & 1023;
	if (slot >= 1024)
		return;
	h = bpf_map_lookup_elem(&place_by_pid, &slot);
	if (!h)
		return;
	WRITE_ONCE(h->pid, pid);
	WRITE_ONCE(h->cpu, cpu);
}
/* Placement hint with mask revalidation in one place. */
/* Gives the cached CPU solely when it still matches the task pid */
/* with live plus allowed, so a pinned task reuses its owner while */
/* other tasks fall back with no wrong CPU. Safety stays with the */
/* caller recheck plus the move affinity gate. Noinline so both */
/* placement paths verify once. */
static __noinline s32 flow_place_hint(u32 pid,
	const struct task_struct *p)
{
	u32 slot;
	struct flow_place *h;
	u32 cpu;
	if (pid == 0)
		return -1;
	if (!p)
		return -1;
	slot = pid & 1023;
	if (slot >= 1024)
		return -1;
	h = bpf_map_lookup_elem(&place_by_pid, &slot);
	if (!h)
		return -1;
	if (READ_ONCE(h->pid) != pid)
		return -1;
	cpu = READ_ONCE(h->cpu);
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return -1;
	if (!flow_cpu_ok(p, (s32)cpu))
		return -1;
	return (s32)cpu;
}
