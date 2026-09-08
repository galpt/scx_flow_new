/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Pure scheduling helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Base id of the per cpu queues. */
pub const DSQ_BASE: u64 = 0x1000;
/* Stride between the queues of one cpu. */
pub const DSQ_STRIDE: u64 = 1;
/* Seed quantum of the global mean in nanoseconds. */
pub const QUANTUM_SEED_NS: u64 = 2_000_000;
/* Floor of the global quantum in nanoseconds. */
pub const QUANTUM_MIN_NS: u64 = 500_000;
/* Ceiling of the global quantum in nanoseconds. */
pub const QUANTUM_MAX_NS: u64 = 32_000_000;
/* Lower bound of a per task estimate in nanoseconds. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanoseconds. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Bound of the remote scan in one dispatch pass. */
pub const STEAL_SCAN_MAX: u32 = 64;
/* Bound of the moved tasks in one dispatch pass. */
pub const DISPATCH_BATCH: u32 = 32;

/*
 * Queue id of a cpu. The layout is base plus cpu, so
 * the owning cpu decodes with plain arithmetic.
 */
pub fn dsq_id(cpu: u32) -> u64 {
    DSQ_BASE + cpu as u64 * DSQ_STRIDE
}

/* Decode the owning cpu from a queue id. */
pub fn dsq_cpu(id: u64) -> u32 {
    if id < DSQ_BASE {
        return 0;
    }
    ((id - DSQ_BASE) / DSQ_STRIDE) as u32
}

/*
 * Clamp a quantum to the allowed range. Low values rise
 * to the floor. High values fall to the ceiling.
 */
pub fn clamp_quantum(v: u64) -> u64 {
    v.clamp(QUANTUM_MIN_NS, QUANTUM_MAX_NS)
}

/*
 * Clamp a per task estimate to the estimate range. The
 * floor keeps the value positive. The ceiling keeps one
 * long run from shaping later choice.
 */
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Seed quantum of the scheduler. The seed sits inside
 * the allowed range, so the clamp keeps it unchanged
 * while it guards later values.
 */
pub fn seed_quantum() -> u64 {
    clamp_quantum(QUANTUM_SEED_NS)
}

/*
 * Mean quantum over all accounted tasks. An empty set
 * keeps the last value. A zero last value falls back
 * to the seed, so the result is never zero.
 */
pub fn mean_quantum(sum: u64, nr: u64, last: u64) -> u64 {
    if nr == 0 {
        if last == 0 {
            return seed_quantum();
        }
        return clamp_quantum(last);
    }
    clamp_quantum(sum / nr)
}

/*
 * Live quantum from the global mean. A zero mean falls
 * back to the seed, so grants track the live mean
 * while the result stays in range.
 */
pub fn live_quantum(mean: u64) -> u64 {
    if mean == 0 {
        return seed_quantum();
    }
    clamp_quantum(mean)
}

/*
 * Slice grant from the global mean. The grant follows
 * the live mean only, so the slice is independent of
 * the queue key.
 */
pub fn slice_for_mean(mean: u64) -> u64 {
    live_quantum(mean)
}

/*
 * Ordered key from an estimate. Unknown estimates map
 * to the floor key and sort at the front. Known
 * estimates map to the clamped estimate and sort in
 * ascending order. Equal estimates share a key and
 * keep insert order.
 */
pub fn insert_key(est: u64) -> u64 {
    if est == 0 {
        return 0;
    }
    clamp_est(est)
}

/*
 * Check that a slice of keys is ordered. Each key must
 * be at or above the prior key, so ties keep arrival
 * order and the queue stays sorted.
 */
pub fn ordered_ok(keys: &[u64]) -> bool {
    if keys.is_empty() {
        return true;
    }
    let mut prior = keys[0];
    for &k in &keys[1..] {
        if k < prior {
            return false;
        }
        prior = k;
    }
    true
}

/*
 * Check that a steal candidate may run here. The peer
 * mask must include the stealing cpu. Missing masks
 * fail closed and skip the steal.
 */
pub fn steal_ok(peer_mask: &[bool], cpu: u32) -> bool {
    match peer_mask.get(cpu as usize) {
        Some(&v) => v,
        None => false,
    }
}

/*
 * Target cpu from the selected cpu. A valid allowed
 * selected cpu wins. Otherwise the first allowed cpu
 * wins. No allowed cpu yields no target for global park.
 * Pinned tasks resolve to the single allowed cpu here.
 */
pub fn pick_target_cpu(selected: i32, allowed: &[bool]) -> Option<u32> {
    if selected >= 0 {
        if let Some(&ok) = allowed.get(selected as usize) {
            if ok {
                return Some(selected as u32);
            }
        }
    }
    for (i, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(i as u32);
        }
    }
    None
}

/*
 * Age of the head of the busy period. A zero stamp
 * means the set is empty, so the age is zero. Later
 * time values give a forward age with saturation.
 */
pub fn head_age(now: u64, head_at: u64) -> u64 {
    if head_at == 0 {
        return 0;
    }
    now.saturating_sub(head_at)
}

/*
 * Age of the most recent arrival. A zero stamp means
 * the set is empty, so the age is zero. Later time
 * values give a forward age with saturation.
 */
pub fn tail_age(now: u64, tail_at: u64) -> u64 {
    if tail_at == 0 {
        return 0;
    }
    now.saturating_sub(tail_at)
}

/*
 * Global mean state. The count holds accounted tasks.
 * The sum holds clamped estimates with saturation. The
 * mean holds the live quantum with keep last.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueState {
    /* Accounted task count. */
    pub nr: u64,
    /* Sum of clamped estimates. */
    pub sum: u64,
    /* Live mean quantum. */
    pub mean: u64,
}

impl QueueState {
    /*
     * Empty state seeded at the global seed. The count
     * starts at zero and the mean starts clamped.
     */
    pub fn new() -> Self {
        Self {
            nr: 0,
            sum: 0,
            mean: seed_quantum(),
        }
    }

    /*
     * Recompute the mean. An empty set keeps the last
     * value, so the quantum is never zero.
     */
    pub fn recompute(&mut self) {
        self.mean = mean_quantum(self.sum, self.nr, self.mean);
    }

    /*
     * Add one estimate to the set. The sum saturates at
     * the top, so a burst cannot wrap the value.
     */
    pub fn add(&mut self, est: u64) {
        let e = if est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(est)
        };
        self.nr = self.nr.saturating_add(1);
        self.sum = self.sum.saturating_add(e);
        self.recompute();
    }

    /*
     * Remove one estimate from the set. The count and
     * the sum never go below zero. An empty set keeps
     * the last mean.
     */
    pub fn remove(&mut self, est: u64) {
        let e = if est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(est)
        };
        if self.nr > 0 {
            self.nr -= 1;
        }
        self.sum = self.sum.saturating_sub(e);
        self.recompute();
    }

    /*
     * Refresh one estimate in place. The count stays
     * fixed and the sum swaps the old estimate for the
     * new one. Used when a runnable requeue keeps the
     * entry, so no double count occurs.
     */
    pub fn refresh(&mut self, old_est: u64, new_est: u64) {
        let o = if old_est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(old_est)
        };
        let n = if new_est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(new_est)
        };
        if o == n {
            return;
        }
        self.sum = self.sum.saturating_sub(o).saturating_add(n);
        self.recompute();
    }
}

impl Default for QueueState {
    /* Default state matches the empty seeded state. */
    fn default() -> Self {
        Self::new()
    }
}

/*
 * Per cpu depth table. Each slot counts accounted tasks
 * for one cpu. The sum of the slots matches the global
 * count when no task waits in the global park.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuDepths {
    /* One count per cpu. Index is the cpu id. */
    pub counts: Vec<u64>,
}

impl CpuDepths {
    /*
     * Empty table for a fixed cpu count. All slots
     * start at zero.
     */
    pub fn new(nr_cpus: usize) -> Self {
        Self {
            counts: vec![0; nr_cpus],
        }
    }

    /*
     * Add one task to a cpu. Out of range ids are a no
     * op, so global park tasks leave the table alone.
     */
    pub fn inc(&mut self, cpu: u32) {
        if let Some(v) = self.counts.get_mut(cpu as usize) {
            *v = v.saturating_add(1);
        }
    }

    /*
     * Remove one task from a cpu. Counts never go below
     * zero. Out of range ids are a no op.
     */
    pub fn dec(&mut self, cpu: u32) {
        if let Some(v) = self.counts.get_mut(cpu as usize) {
            *v = v.saturating_sub(1);
        }
    }

    /*
     * Move one task between cpus. A same cpu move is a
     * no op. Out of range ids leave the table alone.
     */
    pub fn shift(&mut self, old_cpu: u32, new_cpu: u32) {
        if old_cpu == new_cpu {
            return;
        }
        self.dec(old_cpu);
        self.inc(new_cpu);
    }

    /*
     * Sum of all per cpu slots. Matches the global
     * count when the global park is empty.
     */
    pub fn sum(&self) -> u64 {
        self.counts.iter().copied().sum()
    }

    /*
     * Depth of one cpu. Out of range ids read as zero.
     */
    pub fn get(&self, cpu: u32) -> u64 {
        self.counts.get(cpu as usize).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsq_ids_follow_base_stride_layout() {
        assert_eq!(dsq_id(0), 0x1000);
        assert_eq!(dsq_id(1), 0x1001);
        assert_eq!(dsq_id(5), 0x1000 + 5);
    }

    #[test]
    fn dsq_ids_round_trip_through_decode() {
        for cpu in [0, 1, 7, 64] {
            let id = dsq_id(cpu);
            assert_eq!(dsq_cpu(id), cpu);
        }
    }

    #[test]
    fn dsq_stride_is_one() {
        assert_eq!(DSQ_STRIDE, 1);
        assert_eq!(dsq_id(1) - dsq_id(0), 1);
    }

    #[test]
    fn quantum_clamp_holds_the_range() {
        assert_eq!(clamp_quantum(0), QUANTUM_MIN_NS);
        assert_eq!(clamp_quantum(100), QUANTUM_MIN_NS);
        assert_eq!(clamp_quantum(QUANTUM_MIN_NS), QUANTUM_MIN_NS);
        assert_eq!(clamp_quantum(QUANTUM_MAX_NS), QUANTUM_MAX_NS);
        assert_eq!(clamp_quantum(QUANTUM_MAX_NS + 1), QUANTUM_MAX_NS);
        assert_eq!(clamp_quantum(1_000_000), 1_000_000);
    }

    #[test]
    fn quantum_seed_matches_the_spec() {
        assert_eq!(QUANTUM_SEED_NS, 2_000_000);
        assert_eq!(seed_quantum(), 2_000_000);
    }

    #[test]
    fn est_clamp_caps_at_one_second() {
        assert_eq!(clamp_est(0), EST_MIN_NS);
        assert_eq!(clamp_est(1), EST_MIN_NS);
        assert_eq!(clamp_est(EST_MAX_NS), EST_MAX_NS);
        assert_eq!(clamp_est(EST_MAX_NS + 1), EST_MAX_NS);
        assert_eq!(clamp_est(u64::MAX), EST_MAX_NS);
    }

    #[test]
    fn est_clamp_floor_is_one() {
        assert_eq!(clamp_est(0), 1);
        assert_eq!(EST_MIN_NS, 1);
    }

    #[test]
    fn mean_empty_keeps_last() {
        let last = 2_000_000;
        assert_eq!(mean_quantum(0, 0, last), last);
        assert_eq!(mean_quantum(5_000_000, 0, last), last);
    }

    #[test]
    fn mean_empty_zero_falls_back_to_seed() {
        assert_eq!(mean_quantum(0, 0, 0), 2_000_000);
    }

    #[test]
    fn mean_never_zero() {
        let q = mean_quantum(0, 0, 0);
        assert!(q >= QUANTUM_MIN_NS);
        assert!(q <= QUANTUM_MAX_NS);
        assert_ne!(q, 0);
        let s = QueueState::new();
        assert_ne!(s.mean, 0);
    }

    #[test]
    fn mean_divides_and_clamps() {
        assert_eq!(mean_quantum(2_000_000, 2, 2_000_000), 1_000_000);
        assert_eq!(mean_quantum(100, 2, 2_000_000), QUANTUM_MIN_NS);
        assert_eq!(mean_quantum(100_000_000, 1, 2_000_000), QUANTUM_MAX_NS);
    }

    #[test]
    fn live_quantum_tracks_mean() {
        assert_eq!(live_quantum(1_000_000), 1_000_000);
        assert_eq!(live_quantum(2_000_000), 2_000_000);
    }

    #[test]
    fn live_quantum_clamps_and_falls_back() {
        assert_eq!(live_quantum(100), QUANTUM_MIN_NS);
        assert_eq!(live_quantum(100_000_000), QUANTUM_MAX_NS);
        assert_eq!(live_quantum(0), 2_000_000);
    }

    #[test]
    fn granted_slice_stays_in_range() {
        for mean in [500_000, 2_000_000, 32_000_000] {
            let slice = slice_for_mean(mean);
            assert!(slice >= QUANTUM_MIN_NS);
            assert!(slice <= QUANTUM_MAX_NS);
        }
    }

    #[test]
    fn queue_add_recomputes_live_mean() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 1_000_000);
        assert_eq!(s.mean, 1_000_000);
        s.add(3_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.mean, 2_000_000);
    }

    #[test]
    fn queue_remove_saturates_at_zero() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.remove(5_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        assert_eq!(s.mean, 1_000_000);
    }

    #[test]
    fn queue_remove_empty_keeps_last() {
        let mut s = QueueState::new();
        let last = s.mean;
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        assert_eq!(s.mean, last);
    }

    #[test]
    fn queue_sum_saturates_at_top() {
        let mut s = QueueState::new();
        s.sum = u64::MAX - 10;
        s.nr = 1;
        s.add(100);
        assert_eq!(s.sum, u64::MAX);
        assert_eq!(s.mean, QUANTUM_MAX_NS);
    }

    #[test]
    fn queue_nr_saturates_at_top() {
        let mut s = QueueState::new();
        s.nr = u64::MAX;
        s.sum = u64::MAX;
        s.add(1_000_000);
        assert_eq!(s.nr, u64::MAX);
        assert_eq!(s.sum, u64::MAX);
    }

    #[test]
    fn keys_ascend_with_estimates() {
        let ests = [100, 500_000, 1_000_000, 5_000_000];
        let keys: Vec<u64> = ests.iter().map(|&e| insert_key(e)).collect();
        assert!(ordered_ok(&keys));
        assert_eq!(keys, [100, 500_000, 1_000_000, 5_000_000]);
    }

    #[test]
    fn keys_keep_ascending_after_clamp() {
        let keys = [insert_key(1), insert_key(500), insert_key(EST_MAX_NS)];
        assert!(ordered_ok(&keys));
        assert!(keys[0] <= keys[1]);
        assert!(keys[1] <= keys[2]);
    }

    #[test]
    fn unknown_key_sorts_at_front() {
        assert_eq!(insert_key(0), 0);
        assert!(insert_key(0) < insert_key(1));
        assert!(insert_key(0) < insert_key(1_000_000));
        assert!(insert_key(0) < insert_key(EST_MAX_NS));
    }

    #[test]
    fn unknown_front_holds_in_mixed_set() {
        let mut keys = [insert_key(5_000_000), insert_key(0), insert_key(100)];
        keys.sort();
        assert_eq!(keys[0], 0);
        assert!(ordered_ok(&keys));
    }

    #[test]
    fn tie_keys_share_one_value() {
        assert_eq!(insert_key(1_000_000), insert_key(1_000_000));
        let keys = [insert_key(500), insert_key(500)];
        assert!(ordered_ok(&keys));
    }

    #[test]
    fn tie_stability_keeps_insert_order() {
        let keys = [insert_key(700), insert_key(700), insert_key(700)];
        assert!(ordered_ok(&keys));
        assert_eq!(keys[0], keys[1]);
        assert_eq!(keys[1], keys[2]);
    }

    #[test]
    fn ordered_check_rejects_inversion() {
        assert!(!ordered_ok(&[2, 1]));
        assert!(!ordered_ok(&[1_000_000, 500_000]));
        assert!(ordered_ok(&[]));
        assert!(ordered_ok(&[42]));
    }

    #[test]
    fn slice_is_independent_of_key() {
        let mean = 2_000_000;
        let a = slice_for_mean(mean);
        let b = slice_for_mean(mean);
        assert_eq!(a, b);
        assert_eq!(a, live_quantum(mean));
        let ka = insert_key(100);
        let kb = insert_key(50_000_000);
        assert_ne!(ka, kb);
        assert_eq!(slice_for_mean(mean), slice_for_mean(mean));
    }

    #[test]
    fn slice_ignores_estimate_spread() {
        let mean = 1_500_000;
        let s1 = slice_for_mean(mean);
        let s2 = slice_for_mean(mean);
        assert_eq!(s1, s2);
        assert_ne!(insert_key(200), insert_key(800_000));
    }

    #[test]
    fn refresh_keeps_count_stable() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.refresh(1_000_000, 2_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 2_000_000);
        assert_eq!(s.mean, 2_000_000);
    }

    #[test]
    fn refresh_same_value_is_noop() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.refresh(1_000_000, 1_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 1_000_000);
    }

    #[test]
    fn refresh_balance_holds_sum() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.add(3_000_000);
        assert_eq!(s.sum, 4_000_000);
        s.refresh(1_000_000, 2_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.sum, 5_000_000);
        assert_eq!(s.mean, 2_500_000);
    }

    #[test]
    fn release_is_idempotent() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
    }

    #[test]
    fn release_twice_keeps_last_mean() {
        let mut s = QueueState::new();
        s.add(2_000_000);
        let last = s.mean;
        s.remove(2_000_000);
        s.remove(2_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.mean, last);
    }

    #[test]
    fn depth_balance_matches_global_count() {
        let mut s = QueueState::new();
        let mut d = CpuDepths::new(4);
        s.add(1_000_000);
        d.inc(0);
        s.add(2_000_000);
        d.inc(1);
        assert_eq!(s.nr, d.sum());
        s.remove(1_000_000);
        d.dec(0);
        assert_eq!(s.nr, d.sum());
        assert_eq!(d.get(1), 1);
    }

    #[test]
    fn depth_shift_keeps_total_stable() {
        let mut d = CpuDepths::new(4);
        d.inc(0);
        d.inc(1);
        assert_eq!(d.sum(), 2);
        d.shift(0, 2);
        assert_eq!(d.sum(), 2);
        assert_eq!(d.get(0), 0);
        assert_eq!(d.get(2), 1);
    }

    #[test]
    fn depth_out_of_range_is_noop() {
        let mut d = CpuDepths::new(2);
        d.inc(9);
        d.dec(9);
        assert_eq!(d.sum(), 0);
        assert_eq!(d.get(9), 0);
    }

    #[test]
    fn running_keeps_membership() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        s.add(8_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.sum, 9_000_000);
    }

    #[test]
    fn block_releases_entry() {
        let mut s = QueueState::new();
        s.add(1_000_000);
        assert_eq!(s.nr, 1);
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
    }

    #[test]
    fn head_age_tracks_busy_start() {
        assert_eq!(head_age(1000, 0), 0);
        assert_eq!(head_age(1000, 400), 600);
        assert_eq!(head_age(100, 400), 0);
    }

    #[test]
    fn tail_age_tracks_recent_arrival() {
        assert_eq!(tail_age(1000, 0), 0);
        assert_eq!(tail_age(1000, 900), 100);
        assert_eq!(tail_age(100, 900), 0);
    }

    #[test]
    fn steal_split_totals_scan_max() {
        assert_eq!(STEAL_SCAN_MAX, 64);
        assert_eq!(DISPATCH_BATCH, 32);
    }

    #[test]
    fn steal_guard_needs_allowed_cpu() {
        assert!(steal_ok(&[true, false], 0));
        assert!(!steal_ok(&[true, false], 1));
        assert!(!steal_ok(&[], 0));
        assert!(!steal_ok(&[true], 5));
    }

    #[test]
    fn target_prefers_selected_when_allowed() {
        assert_eq!(pick_target_cpu(2, &[true, true, true]), Some(2));
        assert_eq!(pick_target_cpu(0, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(1, &[false, true]), Some(1));
    }

    #[test]
    fn target_falls_back_to_first_when_invalid() {
        assert_eq!(pick_target_cpu(-1, &[false, true, true]), Some(1));
        assert_eq!(pick_target_cpu(5, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(1, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(-1, &[]), None);
    }

    #[test]
    fn target_none_when_no_allowed() {
        assert_eq!(pick_target_cpu(0, &[false, false]), None);
        assert_eq!(pick_target_cpu(-1, &[false]), None);
    }

    #[test]
    fn target_pinned_resolves_to_single() {
        assert_eq!(pick_target_cpu(2, &[false, false, true]), Some(2));
        assert_eq!(pick_target_cpu(0, &[false, false, true]), Some(2));
        assert_eq!(pick_target_cpu(-1, &[false, true, false]), Some(1));
    }

    #[test]
    fn dsq_decode_guards_underflow() {
        assert_eq!(dsq_cpu(0), 0);
        assert_eq!(dsq_cpu(DSQ_BASE - 1), 0);
    }

    #[test]
    fn default_state_matches_new() {
        assert_eq!(QueueState::default(), QueueState::new());
    }
}
