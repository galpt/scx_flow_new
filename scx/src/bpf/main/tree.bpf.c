// SPDX-License-Identifier: GPL-2.0
/*
 * Deadline tree plus park ring for the core.
 *
 * One global tree orders every queued task by deadline then
 * sequence with a pure signed compare on both fields. Nodes obey a
 * take plus tree xor invariant. Every add consumes a take with the
 * slot left null, every pop leaves the slot null until restash,
 * and every restash fills the slot only for a node just removed.
 * A taken node therefore always sits off tree, and a null take
 * means on tree or in flight. Removal reads safe on a missing
 * node, so the rare defensive remove never corrupts. The park ring
 * holds pids in arrival order with head plus tail under the same
 * lock, and a full ring fails open to the global queue. The floor
 * tracks the last dispatched deadline with a monotonic max, so
 * sleepers clamp with no credit. The sequence hands out one
 * arrival order tick per insert with an atomic add.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Pure key order for the tree with signed diffs only. */
/* Equal deadlines fall back to sequence, so arrivals with the same */
/* deadline keep first in first out order with no tie stall. */
static bool flow_edf_less_cb(struct bpf_rb_node *a,
	const struct bpf_rb_node *b)
{
	struct flow_node *na;
	struct flow_node *nb;
	na = container_of(a, struct flow_node, rb);
	nb = container_of(b, struct flow_node, rb);
	return flow_edf_less(na->deadline, na->seq,
	    nb->deadline, nb->seq);
}
/* Stash slot for one pid with no create. */
static struct flow_stash *flow_stash_lookup(u32 pid)
{
	return bpf_map_lookup_elem(&node_stor, &pid);
}
/* Take the off tree node for one pid with no wait. */
/* Null means the node sits on the tree or flights through a pop, */
/* so the caller marks for the reap instead of stalling. The reap */
/* at the next pop frees with no leak and no lost wakeup. */
static __noinline struct flow_node *flow_tree_take(u32 pid)
{
	struct flow_stash *stash;
	stash = flow_stash_lookup(pid);
	if (!stash)
		return NULL;
	return bpf_kptr_xchg(&stash->node, NULL);
}
/* Return one node to its stash slot with live node wins. */
/* A non null slot means a fresher node arrived for the pid, so the */
/* returned node drops with no double free and the live one stays. */
static __noinline void flow_tree_give(u32 pid,
	struct flow_node *node)
{
	struct flow_stash *stash;
	struct flow_node *old;
	if (!node)
		return;
	stash = flow_stash_lookup(pid);
	if (!stash) {
		bpf_obj_drop(node);
		return;
	}
	old = bpf_kptr_xchg(&stash->node, node);
	if (old)
		bpf_obj_drop(old);
}
/* Fetch one fresh node for one pid with take else alloc. */
/* A present entry takes with ownership moved out, and a null take */
/* means on tree or in flight with no alloc wasted. A missing entry */
/* publishes a husk first, then the fresh node moves in with an */
/* exchange, so map ownership transfers exactly once. A lost publish */
/* race drops the spare with the winner kept. Runs before the lock */
/* with no tree touch, so alloc plus map paths stay outside. */
static __noinline struct flow_node *flow_tree_fetch(u32 pid)
{
	struct flow_stash *stash;
	struct flow_node *node;
	struct flow_node *fresh;
	struct flow_node *old;
	struct flow_stash husk = {};
	stash = flow_stash_lookup(pid);
	if (stash)
		return bpf_kptr_xchg(&stash->node, NULL);
	if (bpf_map_update_elem(&node_stor, &pid, &husk,
	    BPF_NOEXIST) != 0) {
		stash = flow_stash_lookup(pid);
		if (!stash)
			return NULL;
		return bpf_kptr_xchg(&stash->node, NULL);
	}
	stash = flow_stash_lookup(pid);
	if (!stash)
		return NULL;
	fresh = bpf_obj_new(typeof(*fresh));
	if (!fresh) {
		bpf_map_delete_elem(&node_stor, &pid);
		return NULL;
	}
	fresh->deadline = 0;
	fresh->seq = 0;
	fresh->pid = pid;
	old = bpf_kptr_xchg(&stash->node, fresh);
	/* A non null old cannot happen on a fresh husk, but a */
	/* return keeps both nodes live with no drop either way. */
	/* Fresh stays published as the spare, and old serves. */
	if (old)
		return old;
	return bpf_kptr_xchg(&stash->node, NULL);
}
/* Add one taken node under the lock with queued set. */
/* The caller fills the key before the call, so the locked section */
/* holds no walk and no alloc. A set queued flag marks tree membership */
/* for the reap and the double enqueue guard. */
static __always_inline void flow_tree_add_locked(
	struct flow_node *node, struct flow_task_ctx *tctx)
{
	bpf_rbtree_add(&edf_tree, &node->rb, flow_edf_less_cb);
	if (tctx)
		WRITE_ONCE(tctx->queued, (u8)1);
}
/* Remove one taken node under the lock with queued clear. */
/* Removal reads safe on a missing node with a null return, so a */
/* double remove never corrupts the tree. A clear queued flag keeps */
/* the reap check exact after the unlock. */
static __always_inline void flow_tree_remove_locked(
	struct flow_node *node, struct flow_task_ctx *tctx)
{
	bpf_rbtree_remove(&edf_tree, &node->rb);
	if (tctx)
		WRITE_ONCE(tctx->queued, (u8)0);
}
/* Pop the head node under the lock with floor advance. */
/* The floor takes the monotonic max with the popped deadline, so */
/* later clamps never trail dispatched order. Null means an empty */
/* tree with no floor move. The caller owns the returned node past */
/* the unlock with the queued flag still set until restash. */
static __noinline struct flow_node *flow_tree_pop(void)
{
	struct bpf_rb_node *rb;
	struct flow_node *node;
	u64 floor;
	bpf_spin_lock(&edf_lock);
	rb = bpf_rbtree_first(&edf_tree);
	if (!rb) {
		bpf_spin_unlock(&edf_lock);
		return NULL;
	}
	rb = bpf_rbtree_remove(&edf_tree, rb);
	bpf_spin_unlock(&edf_lock);
	if (!rb)
		return NULL;
	node = container_of(rb, struct flow_node, rb);
	floor = READ_ONCE(flow_floor);
	if (flow_time_before(floor, node->deadline))
		WRITE_ONCE(flow_floor, node->deadline);
	return node;
}
/* Push one pid to the park ring under the lock. */
/* False means a full ring, so the caller fails open to global with */
/* no stall and no overwrite. The tail wraps with a mask free add, */
/* so concurrent pushes never tear past the bound. */
static __noinline bool flow_park_push(u32 pid)
{
	u32 head;
	u32 tail;
	u32 key;
	u64 n = (u64)FLOW_PARK_NR;
	if (!n)
		return false;
	bpf_spin_lock(&edf_lock);
	head = READ_ONCE(flow_park_head);
	tail = READ_ONCE(flow_park_tail);
	if ((u64)(tail - head) >= n) {
		bpf_spin_unlock(&edf_lock);
		return false;
	}
	key = tail % (u32)n;
	bpf_spin_unlock(&edf_lock);
	if (bpf_map_update_elem(&park_ring, &key, &pid,
	    BPF_ANY) != 0)
		return false;
	__sync_fetch_and_add(&flow_park_tail, 1);
	return true;
}
/* Pop one pid from the park ring with snapshot plus revalidate. */
/* The head plus tail snapshot under the lock with no map call, */
/* since calls stay illegal inside the section. Array slots never */
/* move, so the lookup past the unlock reads stable memory. A */
/* second section advances the head only when it still matches, */
/* so a concurrent pop wins once with the loser aborting. Pushes */
/* cannot overwrite the snapshotted slot, since the full check */
/* under the push lock excludes the wrap index while the head */
/* holds. False means an empty ring or a lost race with no head */
/* move and no slot drop. */
static __noinline bool flow_park_pop(u32 *pid_out)
{
	u32 head;
	u32 tail;
	u32 key;
	u32 *slot;
	u32 pid;
	u64 n = (u64)FLOW_PARK_NR;
	if (!pid_out || !n)
		return false;
	bpf_spin_lock(&edf_lock);
	head = READ_ONCE(flow_park_head);
	tail = READ_ONCE(flow_park_tail);
	if (head == tail) {
		bpf_spin_unlock(&edf_lock);
		return false;
	}
	key = head % (u32)n;
	bpf_spin_unlock(&edf_lock);
	slot = bpf_map_lookup_elem(&park_ring, &key);
	if (!slot)
		return false;
	pid = *slot;
	bpf_spin_lock(&edf_lock);
	if (READ_ONCE(flow_park_head) != head) {
		bpf_spin_unlock(&edf_lock);
		return false;
	}
	WRITE_ONCE(flow_park_head, head + 1);
	bpf_spin_unlock(&edf_lock);
	*pid_out = pid;
	return true;
}
/* Mark one tree node detached for one pid with entry kept. */
/* Takes no reference and removes nothing, so no token ever leaks. */
/* The reap at the next pop completes the removal with exact drop, */
/* and a returning task reuses its stashed node with no alloc. */
static __noinline void flow_tree_detach(struct task_struct *p,
	struct flow_task_ctx *tctx)
{
	(void)p;
	if (tctx)
		WRITE_ONCE(tctx->queued, (u8)0);
}
/* Hand out one arrival sequence tick with an atomic add. */
/* Wraps past the full range with the signed compare keeping order */
/* across the wrap, so no reset path ever stalls inserts. */
static __always_inline u64 flow_seq_next(void)
{
	return __sync_fetch_and_add(&flow_seq, 1) + 1;
}
