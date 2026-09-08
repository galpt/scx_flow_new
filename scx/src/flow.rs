/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Pure scheduling helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Base id of the per cpu per level queues. */
pub const DSQ_BASE: u64 = 0x1000;
/* Stride between the queues of one cpu. */
pub const DSQ_STRIDE: u64 = 3;
/* Number of feedback levels. */
pub const NR_LEVELS: u32 = 3;
/* Seed quantum of the top level in nanoseconds. */
pub const L0_QUANTUM_NS: u64 = 1_000_000;
/* Seed quantum of the middle level in nanoseconds. */
pub const L1_QUANTUM_NS: u64 = 2_000_000;
/* Seed quantum of the bottom level in nanoseconds. */
pub const L2_QUANTUM_NS: u64 = 8_000_000;
/* Floor of a level quantum in nanoseconds. */
pub const QUANTUM_MIN_NS: u64 = 500_000;
/* Ceiling of a level quantum in nanoseconds. */
pub const QUANTUM_MAX_NS: u64 = 32_000_000;
/* Short name of the quantum floor in nanoseconds. */
pub const Q_MIN_NS: u64 = 500_000;
/* Short name of the quantum ceiling in nanoseconds. */
pub const Q_MAX_NS: u64 = 32_000_000;
/* Lower bound of a per task estimate in nanoseconds. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanoseconds. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Bound of the remote scan in one dispatch pass. */
pub const STEAL_SCAN_MAX: u32 = 64;
/* Bound of the top level steal checks. */
pub const STEAL_L0: u32 = 22;
/* Bound of the middle level steal checks. */
pub const STEAL_L1: u32 = 21;
/* Bound of the bottom level steal checks. */
pub const STEAL_L2: u32 = 21;
/* Bound of the moved tasks in one dispatch pass. */
pub const DISPATCH_BATCH: u32 = 32;

/*
 * Queue id of a cpu and level pair. The layout is base
 * plus cpu times stride plus level.
 */
pub fn dsq_id(cpu: u32, level: u32) -> u64 {
    DSQ_BASE + cpu as u64 * DSQ_STRIDE + level as u64
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
 * Seed quantum of a level. The seeds sit inside the
 * allowed range, so the clamp keeps them unchanged
 * while it guards later values.
 */
pub fn seed_for_level(level: u32) -> u64 {
    let v = match level {
        0 => L0_QUANTUM_NS,
        1 => L1_QUANTUM_NS,
        _ => L2_QUANTUM_NS,
    };
    clamp_quantum(v)
}

/*
 * Quantum of a level. The seeds sit inside the allowed
 * range, so the clamp keeps them while guarding later
 * values.
 */
pub fn quantum_for_level(level: u32) -> u64 {
    seed_for_level(level)
}

/*
 * Mean quantum of a level. An empty level keeps the
 * last value. A zero last value falls back to the
 * seed, so the result is never zero.
 */
pub fn mean_quantum(level: u32, sum: u64, nr: u64, last: u64) -> u64 {
    if nr == 0 {
        if last == 0 {
            return seed_for_level(level);
        }
        return clamp_quantum(last);
    }
    clamp_quantum(sum / nr)
}

/*
 * Live quantum of a level. The value comes from the
 * caller supplied means, so grants track the live
 * means. A zero entry falls back to the seed. Bad
 * levels fall back to the top.
 */
pub fn live_quantum_for_level(level: u32, means: &[u64]) -> u64 {
    let lvl = if level_ok(level) { level } else { 0 };
    match means.get(lvl as usize) {
        Some(&v) if v != 0 => clamp_quantum(v),
        _ => seed_for_level(lvl),
    }
}

/*
 * Pick a level from an estimate. Unknown estimates go
 * to the top. Known estimates use the first level with
 * a live mean at or above the estimate. Large estimates
 * fall to the bottom.
 */
pub fn pick_level(est: u64, means: &[u64]) -> u32 {
    if est == 0 {
        return 0;
    }
    let e = clamp_est(est);
    let q0 = live_quantum_for_level(0, means);
    if e <= q0 {
        return 0;
    }
    let q1 = live_quantum_for_level(1, means);
    if e <= q1 {
        return 1;
    }
    2
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
 * Per level mean state. The count holds queued tasks.
 * The sum holds clamped estimates with saturation. The
 * quantum holds the live mean with keep last.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelState {
    /* Queued task count. */
    pub nr: u64,
    /* Sum of clamped estimates. */
    pub sum_rem: u64,
    /* Live mean quantum. */
    pub quantum: u64,
}

impl LevelState {
    /*
     * Empty state seeded at the level seed. The count
     * starts at zero and the quantum starts clamped.
     */
    pub fn new(level: u32) -> Self {
        Self {
            nr: 0,
            sum_rem: 0,
            quantum: seed_for_level(level),
        }
    }

    /*
     * Recompute the mean. An empty level keeps the last
     * value, so the quantum is never zero.
     */
    pub fn recompute(&mut self, level: u32) {
        self.quantum = mean_quantum(level, self.sum_rem, self.nr, self.quantum);
    }

    /*
     * Add one estimate to a level. The sum saturates at
     * the top, so a burst cannot wrap the value.
     */
    pub fn add(&mut self, level: u32, est: u64) {
        let e = clamp_est(est);
        self.nr = self.nr.saturating_add(1);
        self.sum_rem = self.sum_rem.saturating_add(e);
        self.recompute(level);
    }

    /*
     * Remove one estimate from a level. The count and
     * the sum never go below zero. An empty level keeps
     * the last quantum.
     */
    pub fn remove(&mut self, level: u32, est: u64) {
        let e = clamp_est(est);
        if self.nr > 0 {
            self.nr -= 1;
        }
        self.sum_rem = self.sum_rem.saturating_sub(e);
        self.recompute(level);
    }
}

/*
 * Move one estimate between levels. A same level move
 * refreshes the sum for a new estimate without moving
 * the count.
 */
pub fn move_between_levels(
    levels: &mut [LevelState; 3],
    old: u32,
    new: u32,
    old_est: u64,
    new_est: u64,
) {
    if !level_ok(old) || !level_ok(new) {
        return;
    }
    let o = clamp_est(old_est);
    let n = clamp_est(new_est);
    if old == new {
        let st = &mut levels[old as usize];
        st.sum_rem = st.sum_rem.saturating_sub(o).saturating_add(n);
        st.recompute(old);
        return;
    }
    levels[old as usize].remove(old, o);
    levels[new as usize].add(new, n);
}

/*
 * Initial level of a new task. Every task starts at the
 * top and moves down only.
 */
pub fn initial_level() -> u32 {
    0
}

/*
 * Next level after a full slice was consumed. The bottom
 * level stays at the bottom. There is no move up.
 */
pub fn next_level(level: u32) -> u32 {
    if level >= NR_LEVELS - 1 {
        NR_LEVELS - 1
    } else {
        level + 1
    }
}

/*
 * Check that a level names a real level. Used before
 * queue arithmetic.
 */
pub fn level_ok(level: u32) -> bool {
    level < NR_LEVELS
}

/*
 * Top level with queued work. Empty higher levels are
 * skipped. Empty input yields no level. The result
 * models strict top down drain with no level cap.
 */
pub fn top_with_work(queued: [bool; 3]) -> Option<u32> {
    if queued[0] {
        return Some(0);
    }
    if queued[1] {
        return Some(1);
    }
    if queued[2] {
        return Some(2);
    }
    None
}

/* Decode the owning cpu from a queue id. */
pub fn dsq_cpu(id: u64) -> u32 {
    if id < DSQ_BASE {
        return 0;
    }
    ((id - DSQ_BASE) / DSQ_STRIDE) as u32
}

/* Decode the level from a queue id. */
pub fn dsq_level(id: u64) -> u32 {
    if id < DSQ_BASE {
        return 0;
    }
    ((id - DSQ_BASE) % DSQ_STRIDE) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsq_ids_follow_base_stride_layout() {
        assert_eq!(dsq_id(0, 0), 0x1000);
        assert_eq!(dsq_id(0, 1), 0x1001);
        assert_eq!(dsq_id(0, 2), 0x1002);
        assert_eq!(dsq_id(1, 0), 0x1003);
        assert_eq!(dsq_id(1, 1), 0x1004);
        assert_eq!(dsq_id(5, 2), 0x1000 + 5 * 3 + 2);
    }

    #[test]
    fn dsq_ids_round_trip_through_decode() {
        for cpu in [0, 1, 7, 64] {
            for level in [0, 1, 2] {
                let id = dsq_id(cpu, level);
                assert_eq!(dsq_cpu(id), cpu);
                assert_eq!(dsq_level(id), level);
            }
        }
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
    fn quantum_seeds_match_the_spec() {
        assert_eq!(quantum_for_level(0), 1_000_000);
        assert_eq!(quantum_for_level(1), 2_000_000);
        assert_eq!(quantum_for_level(2), 8_000_000);
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
        assert_eq!(mean_quantum(1, 0, 0, last), last);
        assert_eq!(mean_quantum(1, 5_000_000, 0, last), last);
    }

    #[test]
    fn mean_empty_zero_falls_back_to_seed() {
        assert_eq!(mean_quantum(0, 0, 0, 0), 1_000_000);
        assert_eq!(mean_quantum(1, 0, 0, 0), 2_000_000);
        assert_eq!(mean_quantum(2, 0, 0, 0), 8_000_000);
    }

    #[test]
    fn mean_never_zero() {
        let q = mean_quantum(0, 0, 0, 0);
        assert!(q >= QUANTUM_MIN_NS);
        assert!(q <= QUANTUM_MAX_NS);
        assert_ne!(q, 0);
        let s = LevelState::new(0);
        assert_ne!(s.quantum, 0);
    }

    #[test]
    fn mean_divides_and_clamps() {
        assert_eq!(mean_quantum(0, 2_000_000, 2, 1_000_000), 1_000_000);
        assert_eq!(mean_quantum(0, 100, 2, 8_000_000), QUANTUM_MIN_NS);
        assert_eq!(mean_quantum(0, 100_000_000, 1, 1_000_000), QUANTUM_MAX_NS);
    }

    #[test]
    fn level_add_recomputes_live_mean() {
        let mut s = LevelState::new(0);
        s.add(0, 1_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum_rem, 1_000_000);
        assert_eq!(s.quantum, 1_000_000);
        s.add(0, 3_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.quantum, 2_000_000);
    }

    #[test]
    fn level_remove_saturates_at_zero() {
        let mut s = LevelState::new(0);
        s.add(0, 1_000_000);
        s.remove(0, 5_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum_rem, 0);
        assert_eq!(s.quantum, 1_000_000);
    }

    #[test]
    fn level_remove_empty_keeps_last() {
        let mut s = LevelState::new(1);
        let last = s.quantum;
        s.remove(1, 1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum_rem, 0);
        assert_eq!(s.quantum, last);
    }

    #[test]
    fn level_sum_saturates_at_top() {
        let mut s = LevelState::new(0);
        s.sum_rem = u64::MAX - 10;
        s.nr = 1;
        s.add(0, 100);
        assert_eq!(s.sum_rem, u64::MAX);
        assert_eq!(s.quantum, QUANTUM_MAX_NS);
    }

    #[test]
    fn level_nr_saturates_at_top() {
        let mut s = LevelState::new(0);
        s.nr = u64::MAX;
        s.sum_rem = u64::MAX;
        s.add(0, 1_000_000);
        assert_eq!(s.nr, u64::MAX);
        assert_eq!(s.sum_rem, u64::MAX);
    }

    #[test]
    fn move_between_levels_shifts_counts() {
        let mut levels: [LevelState; 3] =
            [LevelState::new(0), LevelState::new(1), LevelState::new(2)];
        levels[0].add(0, 1_000_000);
        assert_eq!(levels[0].nr, 1);
        move_between_levels(&mut levels, 0, 1, 1_000_000, 2_000_000);
        assert_eq!(levels[0].nr, 0);
        assert_eq!(levels[0].sum_rem, 0);
        assert_eq!(levels[1].nr, 1);
        assert_eq!(levels[1].sum_rem, 2_000_000);
    }

    #[test]
    fn move_same_level_refreshes_sum() {
        let mut levels: [LevelState; 3] =
            [LevelState::new(0), LevelState::new(1), LevelState::new(2)];
        levels[0].add(0, 1_000_000);
        move_between_levels(&mut levels, 0, 0, 1_000_000, 2_000_000);
        assert_eq!(levels[0].nr, 1);
        assert_eq!(levels[0].sum_rem, 2_000_000);
        assert_eq!(levels[0].quantum, 2_000_000);
    }

    #[test]
    fn live_quantum_tracks_means() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        assert_eq!(live_quantum_for_level(0, &means), 1_000_000);
        assert_eq!(live_quantum_for_level(1, &means), 2_000_000);
        assert_eq!(live_quantum_for_level(2, &means), 8_000_000);
    }

    #[test]
    fn live_quantum_clamps_and_falls_back() {
        let means = [100, 100_000_000, 0];
        assert_eq!(live_quantum_for_level(0, &means), QUANTUM_MIN_NS);
        assert_eq!(live_quantum_for_level(1, &means), QUANTUM_MAX_NS);
        assert_eq!(live_quantum_for_level(2, &means), 8_000_000);
    }

    #[test]
    fn granted_slice_stays_in_range() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        for level in [0, 1, 2] {
            let q = live_quantum_for_level(level, &means);
            let slice = clamp_quantum(q);
            assert!(slice >= QUANTUM_MIN_NS);
            assert!(slice <= QUANTUM_MAX_NS);
        }
    }

    #[test]
    fn level_assign_starts_at_top() {
        assert_eq!(initial_level(), 0);
        assert!(level_ok(initial_level()));
    }

    #[test]
    fn demote_one_moves_down_only() {
        assert_eq!(next_level(0), 1);
        assert_eq!(next_level(1), 2);
        assert_eq!(next_level(2), 2);
    }

    #[test]
    fn level_guard_rejects_out_of_range() {
        assert!(level_ok(0));
        assert!(level_ok(2));
        assert!(!level_ok(3));
        assert!(!level_ok(u32::MAX));
    }

    #[test]
    fn pick_unknown_goes_to_top() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        assert_eq!(pick_level(0, &means), 0);
    }

    #[test]
    fn pick_fits_first_live_mean() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        assert_eq!(pick_level(500_000, &means), 0);
        assert_eq!(pick_level(1_000_000, &means), 0);
        assert_eq!(pick_level(1_500_000, &means), 1);
        assert_eq!(pick_level(2_000_000, &means), 1);
        assert_eq!(pick_level(5_000_000, &means), 2);
    }

    #[test]
    fn pick_overflow_goes_to_bottom() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        assert_eq!(pick_level(9_000_000, &means), 2);
        assert_eq!(pick_level(EST_MAX_NS, &means), 2);
        assert_eq!(pick_level(u64::MAX, &means), 2);
    }

    #[test]
    fn pick_tracks_live_means() {
        let means = [500_000, 500_000, 500_000];
        assert_eq!(pick_level(500_000, &means), 0);
        assert_eq!(pick_level(600_000, &means), 2);
    }

    #[test]
    fn drain_prefers_top_down() {
        assert_eq!(top_with_work([true, true, true]), Some(0));
        assert_eq!(top_with_work([true, false, true]), Some(0));
        assert_eq!(top_with_work([false, true, true]), Some(1));
        assert_eq!(top_with_work([false, false, true]), Some(2));
        assert_eq!(top_with_work([false, false, false]), None);
    }

    #[test]
    fn drain_stays_while_backlogged() {
        assert_eq!(top_with_work([true, true, false]), Some(0));
        assert_eq!(top_with_work([false, true, false]), Some(1));
    }

    #[test]
    fn steal_split_totals_scan_max() {
        assert_eq!(STEAL_L0 + STEAL_L1 + STEAL_L2, STEAL_SCAN_MAX);
        assert_eq!(STEAL_L0, 22);
        assert_eq!(STEAL_L1, 21);
        assert_eq!(STEAL_L2, 21);
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
    fn live_bad_level_falls_back_to_top() {
        let means = [1_000_000, 2_000_000, 8_000_000];
        assert_eq!(live_quantum_for_level(99, &means), 1_000_000);
        assert_eq!(live_quantum_for_level(u32::MAX, &means), 1_000_000);
    }

    #[test]
    fn next_wrap_stays_at_bottom() {
        assert_eq!(next_level(u32::MAX), 2);
        assert_eq!(next_level(99), 2);
        assert_eq!(next_level(3), 2);
    }

    #[test]
    fn dsq_decode_guards_underflow() {
        assert_eq!(dsq_cpu(0), 0);
        assert_eq!(dsq_level(0), 0);
        assert_eq!(dsq_cpu(DSQ_BASE - 1), 0);
        assert_eq!(dsq_level(DSQ_BASE - 1), 0);
    }
}
