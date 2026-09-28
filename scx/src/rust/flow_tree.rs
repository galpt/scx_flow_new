// SPDX-License-Identifier: GPL-2.0
//! Deadline tree helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! One global tree ordered by deadline then sequence with a FIFO park ring.

/// Homeless scan visits at most 4 per pass. Fixed with no knob.
pub const GLOBAL_SCAN: u32 = 4;
/// Park recycle visits one head per pass. Fixed with no knob.
pub const PARK_BATCH: u32 = 1;
/// Live task nodes at most. Fixed with no knob.
pub const NODE_MAX: u64 = 32768;
/// Park ring slots at most. Fixed with no knob.
pub const PARK_NR: u64 = 4096;
/// Frequency slots at most. Fixed with no knob.
pub const LLC_MAX: u64 = 64;
/// Minimum gap between frequency transitions in nanos at 16ms.
/// Sits inside the 10ms to 32ms window with no knob.
pub const CPUFREQ_MIN_NS: u64 = 16_000_000;
/// Least gap admitted in nanos at 10ms.
pub const CPUFREQ_MIN_FLOOR_NS: u64 = 10_000_000;
/// Largest gap admitted in nanos at 32ms.
pub const CPUFREQ_MIN_CEIL_NS: u64 = 32_000_000;

/// True when the first key orders before the second key.
/// Pure signed diffs on both fields with no other input, so equal
/// deadlines fall back to arrival sequence with no tie stall.
#[cfg(test)]
pub fn edf_less(a_deadline: u64, a_seq: u64, b_deadline: u64, b_seq: u64) -> bool {
    if a_deadline != b_deadline {
        return (a_deadline.wrapping_sub(b_deadline) as i64) < 0;
    }
    (a_seq.wrapping_sub(b_seq) as i64) < 0
}

/// Park ring with head plus tail over a fixed bound.
/// Models the BPF arrival order queue with wrapping counters.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct ParkRing {
    slots: Vec<Option<u32>>,
    head: u64,
    tail: u64,
}

#[cfg(test)]
impl ParkRing {
    /// Empty ring over the fixed slot count.
    pub fn new() -> Self {
        Self {
            slots: vec![None; PARK_NR as usize],
            head: 0,
            tail: 0,
        }
    }

    /// Push one pid with false on a full ring.
    pub fn push(&mut self, pid: u32) -> bool {
        if self.tail.wrapping_sub(self.head) >= PARK_NR {
            return false;
        }
        let key = (self.tail % PARK_NR) as usize;
        self.slots[key] = Some(pid);
        self.tail = self.tail.wrapping_add(1);
        true
    }

    /// Pop one pid with None on an empty ring.
    pub fn pop(&mut self) -> Option<u32> {
        if self.head == self.tail {
            return None;
        }
        let key = (self.head % PARK_NR) as usize;
        let out = self.slots[key].take();
        if out.is_some() {
            self.head = self.head.wrapping_add(1);
        }
        out
    }

    /// Count of parked pids.
    pub fn len(&self) -> u64 {
        self.tail.wrapping_sub(self.head)
    }
}

/// True when one popped node reaps instead of serving.
/// Gone tasks, non tree members, and sequence mismatches from pid
/// reuse all reap, so stale nodes never run and never re-tree.
#[cfg(test)]
pub fn pop_stale(task_gone: bool, queued: u8, seq_ok: bool) -> bool {
    task_gone || queued != QUEUED_TREE || !seq_ok
}

/// True when one reap also deletes the stash entry.
/// A null slot means no fresher node arrived, so the entry drops
/// with the node. A live slot stays, so the replacement survives.
#[cfg(test)]
pub fn reap_deletes_entry(slot_null: bool) -> bool {
    slot_null
}

/// Membership states of one task across tree plus ring.
/// Zero means idle, one means on the tree, two means parked.
/// Mirrors the BPF queue flag with no other values admitted.
#[cfg(test)]
pub const QUEUED_IDLE: u8 = 0;
/// On the deadline tree.
#[cfg(test)]
pub const QUEUED_TREE: u8 = 1;
/// In the park ring.
#[cfg(test)]
pub const QUEUED_PARK: u8 = 2;

/// True when one popped head serves from the tree.
/// Needs tree membership with a matching sequence, so parked or
/// idle or reused nodes reap instead of running twice.
#[cfg(test)]
pub fn tree_serves(queued: u8, seq_ok: bool) -> bool {
    queued == QUEUED_TREE && seq_ok
}

/// True when one popped ring pid serves from the park.
/// Needs park membership, so a stale ring pid from an earlier park
/// drops with the live tree node left alone.
#[cfg(test)]
pub fn park_serves(queued: u8) -> bool {
    queued == QUEUED_PARK
}

/// True when a duplicate arrival restores tree membership.
/// Restores only from idle with a live entry and a null slot, so a
/// duplicate while on tree keeps its key and a duplicate while
/// parked stays parked with no tree move. The wait stamp still
/// refreshes on every duplicate path.
#[cfg(test)]
pub fn enqueue_restores_tree(queued: u8, entry_exists: bool, slot_null: bool) -> bool {
    queued == QUEUED_IDLE && entry_exists && slot_null
}

/// Frequency transition decision for one cache domain.
/// Boosts past the gap when busy and unboosted, rests past the gap
/// when idle and boosted, else holds. Models the BPF timer tick
/// with hysteresis on both edges.
#[cfg(test)]
pub fn llc_want_boost(busy: u32, boosted: bool, now: u64, last: u64) -> Option<bool> {
    if now < last || now - last < CPUFREQ_MIN_NS {
        return None;
    }
    if busy != 0 && !boosted {
        return Some(true);
    }
    if busy == 0 && boosted {
        return Some(false);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn consts_are_fixed() {
        assert_eq!(crate::flow_edf::DISPATCH_BATCH, 16);
        assert_eq!(PARK_BATCH, 1);
        assert_eq!(GLOBAL_SCAN, 4);
        assert_eq!(NODE_MAX, 32768);
        assert_eq!(PARK_NR, 4096);
        assert_eq!(LLC_MAX, 64);
        assert_eq!(CPUFREQ_MIN_NS, 16_000_000);
        assert_eq!(CPUFREQ_MIN_FLOOR_NS, 10_000_000);
        assert_eq!(CPUFREQ_MIN_CEIL_NS, 32_000_000);
    }

    #[test]
    fn less_orders_deadline_then_sequence() {
        assert!(edf_less(100, 5, 200, 1));
        assert!(!edf_less(200, 1, 100, 5));
        assert!(edf_less(100, 5, 100, 6));
        assert!(!edf_less(100, 6, 100, 6));
        assert!(!edf_less(100, 6, 100, 5));
    }

    #[test]
    fn less_wraps_safe_on_both_fields() {
        assert!(edf_less(u64::MAX, 1, 2, 3));
        assert!(!edf_less(2, 3, u64::MAX, 1));
        assert!(edf_less(7, u64::MAX, 7, 2));
        assert!(!edf_less(7, 2, 7, u64::MAX));
    }

    #[test]
    fn tree_model_pops_deadline_order() {
        let mut tree: BTreeMap<(u64, u64), u32> = BTreeMap::new();
        tree.insert((200, 2), 7);
        tree.insert((100, 9), 3);
        tree.insert((100, 4), 5);
        let first = tree.pop_first().unwrap();
        assert_eq!(first, ((100, 4), 5));
        let second = tree.pop_first().unwrap();
        assert_eq!(second, ((100, 9), 3));
        let third = tree.pop_first().unwrap();
        assert_eq!(third, ((200, 2), 7));
        assert!(tree.pop_first().is_none());
    }

    #[test]
    fn ring_keeps_arrival_order() {
        let mut ring = ParkRing::new();
        assert_eq!(ring.len(), 0);
        assert!(ring.push(11));
        assert!(ring.push(22));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.pop(), Some(11));
        assert_eq!(ring.pop(), Some(22));
        assert_eq!(ring.pop(), None);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn ring_full_fails_open() {
        let mut ring = ParkRing::new();
        for pid in 0..PARK_NR as u32 {
            assert!(ring.push(pid));
        }
        assert_eq!(ring.len(), PARK_NR);
        assert!(!ring.push(PARK_NR as u32));
        assert_eq!(ring.pop(), Some(0));
        assert!(ring.push(PARK_NR as u32));
    }

    #[test]
    fn ring_wraps_past_u32() {
        let mut ring = ParkRing::new();
        ring.head = u64::MAX - 1;
        ring.tail = u64::MAX - 1;
        assert!(ring.push(5));
        assert_eq!(ring.pop(), Some(5));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn stale_pops_reap_with_slot_rule() {
        assert!(pop_stale(true, QUEUED_TREE, true));
        assert!(pop_stale(false, QUEUED_IDLE, true));
        assert!(pop_stale(false, QUEUED_PARK, true));
        assert!(pop_stale(false, QUEUED_TREE, false));
        assert!(!pop_stale(false, QUEUED_TREE, true));
        assert!(reap_deletes_entry(true));
        assert!(!reap_deletes_entry(false));
    }

    #[test]
    fn membership_gates_serve_paths() {
        assert_eq!(QUEUED_IDLE, 0);
        assert_eq!(QUEUED_TREE, 1);
        assert_eq!(QUEUED_PARK, 2);
        assert!(tree_serves(QUEUED_TREE, true));
        assert!(!tree_serves(QUEUED_TREE, false));
        assert!(!tree_serves(QUEUED_PARK, true));
        assert!(!tree_serves(QUEUED_IDLE, true));
        assert!(park_serves(QUEUED_PARK));
        assert!(!park_serves(QUEUED_TREE));
        assert!(!park_serves(QUEUED_IDLE));
    }

    #[test]
    fn duplicate_restores_tree_only_from_idle() {
        assert!(enqueue_restores_tree(QUEUED_IDLE, true, true));
        assert!(!enqueue_restores_tree(QUEUED_TREE, true, true));
        assert!(!enqueue_restores_tree(QUEUED_PARK, true, true));
        assert!(!enqueue_restores_tree(QUEUED_IDLE, false, true));
        assert!(!enqueue_restores_tree(QUEUED_IDLE, true, false));
        assert!(!enqueue_restores_tree(QUEUED_IDLE, false, false));
    }

    #[test]
    fn frequency_holds_inside_gap() {
        assert_eq!(llc_want_boost(1, false, 1_000, 0), None);
        assert_eq!(llc_want_boost(0, true, 1_000, 0), None);
        assert_eq!(llc_want_boost(1, false, 0, 1_000), None);
    }

    #[test]
    fn frequency_boosts_busy_past_gap() {
        let t = CPUFREQ_MIN_NS;
        assert_eq!(llc_want_boost(3, false, t, 0), Some(true));
        assert_eq!(llc_want_boost(3, true, t + 1, 0), None);
        assert_eq!(llc_want_boost(0, false, t + 1, 0), None);
    }

    #[test]
    fn frequency_rests_idle_past_gap() {
        let t = CPUFREQ_MIN_NS;
        assert_eq!(llc_want_boost(0, true, t, 0), Some(false));
        assert_eq!(llc_want_boost(0, true, t - 1, 0), None);
        assert_eq!(llc_want_boost(2, false, t, 0), Some(true));
    }
}
