/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Pure scheduling helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Count of tiers kept by the scheduler. */
pub const NTIERS: u32 = 2;
/* Fixed slice of the interactive tier in nanos. */
pub const QUANTUM_TIER0_NS: u64 = 500_000;
/* Fixed slice of the batch tier in nanos. */
pub const QUANTUM_TIER1_NS: u64 = 8_000_000;
/* Burst length that counts as short in nanos. */
pub const SHORT_BOUND_NS: u64 = 1_000_000;
/* Short blocks that earn a move up. */
pub const PROMOTE_STREAK: u32 = 3;
/* Upper bound of the block streak. */
pub const STREAK_CAP: u32 = 7;
/* Interactive serves per batch serve. */
pub const DEFICIT_SERVES: u64 = 8;
/* Minimum gap between busy preemptions in nanos. */
pub const PREEMPT_GAP_NS: u64 = 1_000_000;
/* Bound of the moved tasks in one pass. */
pub const DISPATCH_BATCH: u32 = 32;
/* Shared DSQ of the batch tier. */
#[cfg(test)]
pub const DSQ_BATCH: u64 = 0x2000;
/* Park DSQ for tasks with no target. */
#[cfg(test)]
pub const DSQ_PARK: u64 = 0x2001;
/* Lower bound of a per task estimate in nanos. */
#[cfg(test)]
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanos. */
#[cfg(test)]
pub const EST_MAX_NS: u64 = 1_000_000_000;

/*
 * Check that a tier index names a real tier. Used to
 * guard per tier array access.
 */
pub fn tier_ok(tier: u32) -> bool {
    tier < NTIERS
}

/*
 * Fixed slice of one tier in nanos. Unknown tiers fall
 * back to the interactive slice, so the result stays
 * usable.
 */
pub fn quantum_tier(tier: u32) -> u64 {
    if tier == 1 {
        QUANTUM_TIER1_NS
    } else {
        QUANTUM_TIER0_NS
    }
}

/*
 * Clamp a per task estimate to the estimate range. The
 * floor keeps the value positive. The ceiling keeps a
 * single long run from shaping later choice.
 */
#[cfg(test)]
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Check that a burst burned the full grant. A zero
 * grant never counts as burned, so a missing grant
 * holds the tier.
 */
#[cfg(test)]
pub fn burned(grant: u64, delta: u64) -> bool {
    if grant == 0 {
        return false;
    }
    delta >= grant
}

/*
 * Check that a burst counts as short. Bursts below the
 * bound earn the streak. Bursts at or past the bound
 * reset the streak.
 */
#[cfg(test)]
pub fn is_short(delta: u64) -> bool {
    delta < SHORT_BOUND_NS
}

/*
 * Next streak after one voluntary block. Short blocks
 * step forward with saturation at the cap. Long blocks
 * reset to zero.
 */
#[cfg(test)]
pub fn streak_next(streak: u32, delta: u64) -> u32 {
    if !is_short(delta) {
        return 0;
    }
    if streak >= STREAK_CAP {
        return STREAK_CAP;
    }
    streak + 1
}

/*
 * Check that a streak earns a move up. Streaks at or
 * past the bound earn the reward. Younger streaks
 * hold.
 */
#[cfg(test)]
pub fn should_promote(streak: u32) -> bool {
    streak >= PROMOTE_STREAK
}

/*
 * Next tier after a run. A runnable task that burned
 * the full grant moves from interactive to batch. All
 * other tasks hold the tier.
 */
#[cfg(test)]
pub fn next_on_burn(tier: u32, runnable: bool, is_burned: bool) -> u32 {
    if !runnable {
        return tier;
    }
    if !is_burned {
        return tier;
    }
    if tier == 0 {
        return 1;
    }
    tier
}

/*
 * Check that the batch tier may be served now. An empty
 * batch tier never serves. An empty interactive tier
 * serves batch at once. A busy interactive tier serves
 * batch only after enough interactive serves.
 */
#[cfg(test)]
pub fn deficit_should_serve(s0: u64, w0: bool, w1: bool) -> bool {
    if !w1 {
        return false;
    }
    if !w0 {
        return true;
    }
    s0 >= DEFICIT_SERVES
}

/*
 * Next deficit count after one run. Batch runs reset
 * to zero. Interactive runs step forward with
 * saturation at the bound.
 */
#[cfg(test)]
pub fn deficit_next(served0: u64, served_tier: u32) -> u64 {
    if served_tier == 1 {
        return 0;
    }
    if served0 >= DEFICIT_SERVES {
        return DEFICIT_SERVES;
    }
    served0 + 1
}

/*
 * Check that one vruntime sorts before another. Used
 * to advance the floor with the smallest waiting
 * value.
 */
#[cfg(test)]
pub fn vruntime_before(a: u64, b: u64) -> bool {
    a < b
}

/*
 * Advance a vruntime by one burst with saturation. The
 * top value sticks, so a burst cannot wrap the order.
 */
#[cfg(test)]
pub fn vruntime_advance(base: u64, delta: u64) -> u64 {
    base.saturating_add(delta)
}

/*
 * Advance the floor to the smallest waiting value. The
 * floor only moves forward, so later joins never pass
 * waiting work.
 */
#[cfg(test)]
pub fn floor_advance(floor: u64, vtime: u64) -> u64 {
    if vruntime_before(floor, vtime) {
        vtime
    } else {
        floor
    }
}

/*
 * Check that a busy preemption may be sent now. Gaps
 * at or past the bound allow the kick. Shorter gaps
 * hold the kick. A clock step back allows the kick, so
 * a skew never blocks progress for long.
 */
#[cfg(test)]
pub fn preempt_gap_ok(now: u64, last: u64) -> bool {
    if now < last {
        return true;
    }
    now - last >= PREEMPT_GAP_NS
}

/*
 * Target cpu from the selected cpu. A valid allowed
 * selected cpu wins. Otherwise the first allowed cpu
 * wins. No allowed cpu yields no target for park use.
 * Pinned tasks resolve to the single allowed cpu here.
 */
#[cfg(test)]
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
 * Running view of one cpu for tests. Mirrors the BPF
 * cpu state fields used by the dashboard. Zero pid
 * means idle.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningView {
    /* Estimate of the task now on the cpu. */
    pub est: u64,
    /* Pid now on the cpu. Zero when idle. */
    pub pid: u32,
    /* Tier of the task now on the cpu. */
    pub tier: u32,
}

#[cfg(test)]
impl RunningView {
    /*
     * Idle view with all fields at zero. Matches the
     * cleared BPF state after stopping.
     */
    pub fn idle() -> Self {
        Self {
            est: 0,
            pid: 0,
            tier: 0,
        }
    }

    /*
     * True when no task runs on the cpu. The dashboard
     * uses the pid for this check.
     */
    pub fn is_idle(&self) -> bool {
        self.pid == 0
    }

    /*
     * Clear the view to idle. Mirrors the stopping path
     * that clears the BPF running fields at once.
     */
    pub fn clear(&mut self) {
        self.est = 0;
        self.pid = 0;
        self.tier = 0;
    }
}

/*
 * Per tier counts for tests. Each slot counts joined
 * tasks in one tier across all cpus. The sum matches
 * the joined total.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TierCounts {
    /* Joined tasks per tier. Index is the tier. */
    pub nr: [u64; 2],
}

#[cfg(test)]
impl TierCounts {
    /*
     * Empty counts with both tiers at zero. Matches
     * the BPF state after init.
     */
    pub fn new() -> Self {
        Self { nr: [0, 0] }
    }

    /*
     * Join one task to a tier. Unknown tiers join the
     * interactive tier, so the count stays balanced.
     */
    pub fn join(&mut self, tier: u32) {
        let t = if tier_ok(tier) { tier as usize } else { 0 };
        self.nr[t] = self.nr[t].saturating_add(1);
    }

    /*
     * Leave one task from a tier. Counts never go below
     * zero. Unknown tiers leave the interactive tier.
     */
    pub fn leave(&mut self, tier: u32) {
        let t = if tier_ok(tier) { tier as usize } else { 0 };
        self.nr[t] = self.nr[t].saturating_sub(1);
    }

    /*
     * Move one task between tiers. A same tier move is
     * a no op. Unknown tiers map to interactive.
     */
    pub fn shift(&mut self, old: u32, new: u32) {
        let o = if tier_ok(old) { old } else { 0 };
        let n = if tier_ok(new) { new } else { 0 };
        if o == n {
            return;
        }
        self.leave(o);
        self.join(n);
    }

    /*
     * Sum of both tiers. Matches the joined total.
     */
    pub fn sum(&self) -> u64 {
        self.nr[0].saturating_add(self.nr[1])
    }
}

#[cfg(test)]
impl Default for TierCounts {
    /* Default counts match the empty state. */
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn tier_ids_match_spec() {
        assert!(tier_ok(0));
        assert!(tier_ok(1));
        assert!(!tier_ok(2));
        assert_eq!(NTIERS, 2);
        assert_eq!(DSQ_BATCH, 0x2000);
        assert_eq!(DSQ_PARK, 0x2001);
        assert_ne!(DSQ_BATCH, DSQ_PARK);
    }

    #[test]
    fn quanta_match_spec() {
        assert_eq!(QUANTUM_TIER0_NS, 500_000);
        assert_eq!(QUANTUM_TIER1_NS, 8_000_000);
        assert_eq!(quantum_tier(0), 500_000);
        assert_eq!(quantum_tier(1), 8_000_000);
        assert_eq!(quantum_tier(2), 500_000);
        assert_eq!(quantum_tier(99), 500_000);
    }

    #[test]
    fn short_bound_matches_spec() {
        assert_eq!(SHORT_BOUND_NS, 1_000_000);
        assert_eq!(PROMOTE_STREAK, 3);
        assert_eq!(STREAK_CAP, 7);
        assert_eq!(DEFICIT_SERVES, 8);
        assert_eq!(PREEMPT_GAP_NS, 1_000_000);
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
    fn est_is_last_burst_with_no_smoothing() {
        let first = clamp_est(1_000_000);
        let second = clamp_est(8_000_000);
        assert_eq!(second, 8_000_000);
        assert_ne!(first, second);
    }

    #[test]
    fn burn_boundary_holds_below_grant() {
        let grant0 = QUANTUM_TIER0_NS;
        assert!(!burned(grant0, grant0 - 1));
        assert!(burned(grant0, grant0));
        assert!(burned(grant0, grant0 + 1));
        let grant1 = QUANTUM_TIER1_NS;
        assert!(!burned(grant1, grant1 - 1));
        assert!(burned(grant1, grant1));
        assert!(burned(grant1, grant1 + 1));
        assert!(!burned(0, 0));
        assert!(!burned(0, 1_000_000));
    }

    #[test]
    fn burn_uses_stored_grant_not_slice() {
        let grant = QUANTUM_TIER0_NS;
        let other = QUANTUM_TIER1_NS;
        assert!(burned(grant, grant));
        assert!(!burned(grant, grant - 1));
        assert!(burned(other, other));
        assert!(!burned(other, grant));
    }

    #[test]
    fn demotion_moves_down_one_on_full_burn() {
        assert_eq!(next_on_burn(0, true, true), 1);
        assert_eq!(next_on_burn(1, true, true), 1);
    }

    #[test]
    fn demotion_holds_on_block_or_short_run() {
        assert_eq!(next_on_burn(0, false, true), 0);
        assert_eq!(next_on_burn(1, false, true), 1);
        assert_eq!(next_on_burn(0, true, false), 0);
        assert_eq!(next_on_burn(1, true, false), 1);
        assert_eq!(next_on_burn(1, false, false), 1);
    }

    #[test]
    fn demotion_property_holds_or_moves_one() {
        for tier in [0, 1] {
            for runnable in [false, true] {
                for delta in [0, 500_000, 8_000_000] {
                    let grant = quantum_tier(tier);
                    let hit = burned(grant, delta);
                    let next = next_on_burn(tier, runnable, hit);
                    if tier == 0 && runnable && hit {
                        assert_eq!(next, 1);
                    } else {
                        assert_eq!(next, tier);
                    }
                }
            }
        }
    }

    #[test]
    fn streak_short_boundary_needs_full_wait() {
        assert!(!is_short(SHORT_BOUND_NS));
        assert!(!is_short(SHORT_BOUND_NS + 1));
        assert!(is_short(SHORT_BOUND_NS - 1));
        assert!(is_short(0));
        assert_eq!(streak_next(0, SHORT_BOUND_NS - 1), 1);
        assert_eq!(streak_next(0, SHORT_BOUND_NS), 0);
        assert_eq!(streak_next(2, SHORT_BOUND_NS), 0);
    }

    #[test]
    fn streak_steps_with_saturation_at_cap() {
        assert_eq!(streak_next(0, 100), 1);
        assert_eq!(streak_next(2, 100), 3);
        assert_eq!(streak_next(6, 100), 7);
        assert_eq!(streak_next(7, 100), 7);
        assert_eq!(streak_next(7, 5_000_000), 0);
        assert_eq!(streak_next(3, 5_000_000), 0);
    }

    #[test]
    fn promotion_needs_three_short_blocks() {
        assert!(!should_promote(0));
        assert!(!should_promote(1));
        assert!(!should_promote(2));
        assert!(should_promote(3));
        assert!(should_promote(7));
    }

    #[test]
    fn streak_promotion_sequence() {
        let mut streak = 0;
        streak = streak_next(streak, 100_000);
        assert_eq!(streak, 1);
        assert!(!should_promote(streak));
        streak = streak_next(streak, 200_000);
        assert_eq!(streak, 2);
        assert!(!should_promote(streak));
        streak = streak_next(streak, 300_000);
        assert_eq!(streak, 3);
        assert!(should_promote(streak));
        streak = streak_next(streak, 2_000_000);
        assert_eq!(streak, 0);
        assert!(!should_promote(streak));
    }

    #[test]
    fn tier_transition_burn_then_streak() {
        let mut tier = 0;
        let grant = quantum_tier(tier);
        let delta = grant;
        assert!(burned(grant, delta));
        tier = next_on_burn(tier, true, true);
        assert_eq!(tier, 1);
        let mut streak = 0;
        for d in [100_000, 200_000, 300_000] {
            streak = streak_next(streak, d);
        }
        assert!(should_promote(streak));
        tier = 0;
        assert!(tier_ok(tier));
    }

    #[test]
    fn deficit_needs_batch_backlog() {
        assert!(!deficit_should_serve(8, true, false));
        assert!(!deficit_should_serve(0, true, false));
        assert!(!deficit_should_serve(8, false, false));
    }

    #[test]
    fn deficit_serves_eight_to_one() {
        assert!(!deficit_should_serve(0, true, true));
        assert!(!deficit_should_serve(7, true, true));
        assert!(deficit_should_serve(8, true, true));
        assert!(deficit_should_serve(8, false, true));
        assert!(deficit_should_serve(0, false, true));
    }

    #[test]
    fn deficit_next_tracks_interactive_serves() {
        assert_eq!(deficit_next(0, 0), 1);
        assert_eq!(deficit_next(7, 0), 8);
        assert_eq!(deficit_next(8, 0), 8);
        assert_eq!(deficit_next(8, 1), 0);
        assert_eq!(deficit_next(3, 1), 0);
    }

    #[test]
    fn deficit_sequence_holds_ratio() {
        let mut served0 = 0;
        for _ in 0..8 {
            assert!(!deficit_should_serve(served0, true, true));
            served0 = deficit_next(served0, 0);
        }
        assert_eq!(served0, 8);
        assert!(deficit_should_serve(served0, true, true));
        served0 = deficit_next(served0, 1);
        assert_eq!(served0, 0);
        assert!(!deficit_should_serve(served0, true, true));
    }

    #[test]
    fn vruntime_order_sorts_by_service() {
        assert!(vruntime_before(0, 1));
        assert!(vruntime_before(100, 200));
        assert!(!vruntime_before(200, 100));
        assert!(!vruntime_before(5, 5));
        assert_eq!(vruntime_advance(100, 50), 150);
        assert_eq!(vruntime_advance(u64::MAX, 1), u64::MAX);
        assert_eq!(vruntime_advance(u64::MAX - 1, 5), u64::MAX);
    }

    #[test]
    fn vruntime_new_joins_at_floor() {
        let floor = 1_000_000;
        let joined = floor;
        assert_eq!(joined, floor);
        let later = vruntime_advance(joined, 500_000);
        assert!(vruntime_before(joined, later));
        let floor2 = floor_advance(floor, joined);
        assert_eq!(floor2, floor);
        let floor3 = floor_advance(floor, later);
        assert_eq!(floor3, later);
    }

    #[test]
    fn vruntime_property_advance_never_wraps() {
        for base in [0, 1, 1_000_000, u64::MAX - 1, u64::MAX] {
            for delta in [0, 1, 500_000, u64::MAX] {
                let out = vruntime_advance(base, delta);
                assert!(out >= base || out == u64::MAX);
                if base != u64::MAX {
                    assert!(out >= base);
                }
            }
        }
    }

    #[test]
    fn floor_only_moves_forward() {
        assert_eq!(floor_advance(100, 50), 100);
        assert_eq!(floor_advance(100, 100), 100);
        assert_eq!(floor_advance(100, 150), 150);
        assert_eq!(floor_advance(0, 0), 0);
    }

    #[test]
    fn preempt_gap_gates_busy_kicks() {
        assert!(preempt_gap_ok(2_000_000, 0));
        assert!(preempt_gap_ok(1_000_000, 0));
        assert!(!preempt_gap_ok(999_999, 0));
        assert!(!preempt_gap_ok(1_500_000, 1_000_000));
        assert!(preempt_gap_ok(2_000_000, 1_000_000));
        assert!(preempt_gap_ok(0, 5_000_000));
    }

    #[test]
    fn fifo_tail_preserves_arrival_order() {
        let mut lane: VecDeque<u64> = VecDeque::new();
        let arrivals = [5_000_000, 100, 1_000_000, 50];
        for &id in &arrivals {
            lane.push_back(id);
        }
        let mut served = Vec::new();
        while let Some(id) = lane.pop_front() {
            served.push(id);
        }
        assert_eq!(served, arrivals);
    }

    #[test]
    fn fifo_property_holds_across_trials() {
        for trial in 0..32 {
            let mut lane: VecDeque<u64> = VecDeque::new();
            let mut arrivals = Vec::new();
            for i in 0..8 {
                let id = trial * 100 + i;
                arrivals.push(id);
                lane.push_back(id);
            }
            for &want in &arrivals {
                assert_eq!(lane.pop_front(), Some(want));
            }
            assert!(lane.is_empty());
        }
    }

    #[test]
    fn fifo_head_wakeup_jumps_ahead() {
        let mut lane: VecDeque<u64> = VecDeque::new();
        lane.push_back(1);
        lane.push_back(2);
        lane.push_front(3);
        assert_eq!(lane.pop_front(), Some(3));
        assert_eq!(lane.pop_front(), Some(1));
        assert_eq!(lane.pop_front(), Some(2));
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
    fn counts_balance_across_tier_moves() {
        let mut c = TierCounts::new();
        c.join(0);
        c.join(0);
        c.join(1);
        assert_eq!(c.sum(), 3);
        c.shift(0, 1);
        assert_eq!(c.nr, [1, 2]);
        assert_eq!(c.sum(), 3);
        c.leave(1);
        assert_eq!(c.sum(), 2);
        c.leave(0);
        c.leave(1);
        assert_eq!(c.sum(), 0);
    }

    #[test]
    fn counts_saturate_at_bounds() {
        let mut c = TierCounts::new();
        c.nr = [u64::MAX, u64::MAX];
        c.join(0);
        assert_eq!(c.nr[0], u64::MAX);
        c.nr = [0, 0];
        c.leave(0);
        assert_eq!(c.nr[0], 0);
    }

    #[test]
    fn default_counts_match_empty() {
        assert_eq!(TierCounts::default(), TierCounts::new());
    }

    #[test]
    fn cleared_running_view_reads_idle() {
        let mut view = RunningView {
            est: 100,
            pid: 7,
            tier: 1,
        };
        assert!(!view.is_idle());
        view.clear();
        assert_eq!(view, RunningView::idle());
        assert!(view.is_idle());
    }

    #[test]
    fn dispatch_burn_join_keeps_balance() {
        let mut counts = TierCounts::new();
        let mut tier = 0;
        counts.join(tier);
        assert_eq!(counts.sum(), 1);
        let grant = quantum_tier(tier);
        let delta = grant;
        assert!(burned(grant, delta));
        let next = next_on_burn(tier, true, true);
        assert_eq!(next, 1);
        counts.shift(tier, next);
        tier = next;
        assert_eq!(counts.nr, [0, 1]);
        assert_eq!(counts.sum(), 1);
        let v = vruntime_advance(0, delta);
        assert!(v > 0);
        assert!(tier_ok(tier));
    }

    #[test]
    fn block_release_keeps_balance() {
        let mut counts = TierCounts::new();
        counts.join(0);
        assert_eq!(counts.sum(), 1);
        counts.leave(0);
        assert_eq!(counts.sum(), 0);
        counts.leave(0);
        assert_eq!(counts.sum(), 0);
    }
}
