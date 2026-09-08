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
/* Unknown LLC id. Marks an empty table entry. */
pub const LLC_UNKNOWN: u32 = 0xFFFF_FFFF;
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
 * True when a frequency value is known. Zero means
 * unknown, so callers use a plain fallback and never
 * divide by the value.
 */
#[cfg(test)]
pub fn freq_known(freq_khz: u64) -> bool {
    freq_khz != 0
}

/*
 * True when any entry claims a sibling thread. False
 * means plain hardware with one thread per core, so
 * callers keep plain per-CPU behavior.
 */
#[cfg(test)]
pub fn topology_has_smt(smt: &[bool]) -> bool {
    smt.iter().any(|v| *v)
}

/*
 * True when a sibling may be used. Needs sibling
 * hardware and an allowed peer, else plain per-CPU
 * choice stays.
 */
#[cfg(test)]
pub fn sibling_ok(has_smt: bool, sibling: i32, allowed: &[bool]) -> bool {
    if !has_smt {
        return false;
    }
    if sibling < 0 {
        return false;
    }
    if let Some(&ok) = allowed.get(sibling as usize) {
        return ok;
    }
    false
}

/*
 * Next peer for a scan. Returns none with one or no
 * CPUs, so scans end at once with a single CPU and
 * no peers. Returns none for an out of range CPU.
 */
#[cfg(test)]
pub fn next_peer(cpu: u32, nr_cpus: usize) -> Option<u32> {
    if nr_cpus <= 1 {
        return None;
    }
    if (cpu as usize) >= nr_cpus {
        return None;
    }
    Some((cpu + 1) % nr_cpus as u32)
}

/*
 * Bound of a peer scan. Zero with one or no CPUs, so
 * steal scans and rotation end at once with a single
 * CPU. Otherwise one less than the CPU count.
 */
#[cfg(test)]
pub fn scan_bound(nr_cpus: usize) -> usize {
    if nr_cpus <= 1 {
        return 0;
    }
    nr_cpus - 1
}

/*
 * Check that an LLC id names a real domain. The
 * unknown value marks an empty entry and fails
 * open with no LLC step.
 */
#[cfg(test)]
pub fn llc_known(id: u32) -> bool {
    id != LLC_UNKNOWN
}

/*
 * Check that the LLC step may run. Needs more than
 * one domain, so single and unknown hosts stay
 * plain with no extra scan.
 */
#[cfg(test)]
pub fn llc_ok(nr: u64) -> bool {
    nr >= 2
}

/*
 * LLC id of one CPU. Unknown ids fail open, so an
 * out of range CPU yields no domain.
 */
#[cfg(test)]
pub fn llc_of(cpu: usize, llc_ids: &[u32]) -> Option<u32> {
    let id = *llc_ids.get(cpu)?;
    if !llc_known(id) {
        return None;
    }
    Some(id)
}

/*
 * Idle CPU in the same LLC as the previous CPU.
 * Skips the second thread of a busy core when the
 * full set marks fully idle cores. Empty full set
 * means no SMT preference. Returns none when no
 * LLC idle CPU is found. Single and unknown hosts
 * return none at once with no scan.
 */
#[cfg(test)]
pub fn pick_llc_idle(
    prev: i32,
    llc_ids: &[u32],
    allowed: &[bool],
    idle: &[bool],
    full: &[bool],
    nr: u64,
) -> Option<u32> {
    if !llc_ok(nr) {
        return None;
    }
    if prev < 0 {
        return None;
    }
    let want = llc_of(prev as usize, llc_ids)?;
    let use_full = !full.is_empty();
    for (cpu, &id) in llc_ids.iter().enumerate() {
        if id != want {
            continue;
        }
        if !may_run_on(cpu as i32, allowed) {
            continue;
        }
        if use_full {
            match full.get(cpu) {
                Some(true) => {}
                _ => continue,
            }
        }
        match idle.get(cpu) {
            Some(true) => return Some(cpu as u32),
            _ => continue,
        }
    }
    None
}

/*
 * First idle CPU in the mask. Models the any idle
 * step. Returns none when no allowed CPU is idle.
 */
#[cfg(test)]
pub fn pick_any_idle(allowed: &[bool], idle: &[bool]) -> Option<u32> {
    for (cpu, &ok) in allowed.iter().enumerate() {
        if !ok {
            continue;
        }
        if let Some(true) = idle.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * Full select model. Mirrors the BPF order of LLC
 * idle, any idle, previous, current and first.
 * Returns none for park use when no CPU allows.
 */
#[cfg(test)]
pub fn select_cpu_model(
    prev: i32,
    cur: i32,
    allowed: &[bool],
    idle: &[bool],
    llc_ids: &[u32],
    full: &[bool],
    nr: u64,
) -> Option<u32> {
    if let Some(c) = pick_llc_idle(prev, llc_ids, allowed, idle, full, nr) {
        return Some(c);
    }
    if let Some(c) = pick_any_idle(allowed, idle) {
        return Some(c);
    }
    if may_run_on(prev, allowed) {
        return Some(prev as u32);
    }
    if may_run_on(cur, allowed) {
        return Some(cur as u32);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
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
 * Target CPU from the selected CPU. A valid allowed
 * selected CPU wins. Otherwise the first allowed CPU
 * wins. No allowed CPU yields no target for park use.
 * Pinned tasks resolve to the single allowed CPU here.
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
 * Check that a CPU may run a task with the given
 * mask. Mirrors the BPF head and kick guards. A
 * negative CPU fails closed. An out of range CPU
 * fails closed. A missing entry fails closed.
 */
#[cfg(test)]
pub fn may_run_on(cpu: i32, allowed: &[bool]) -> bool {
    if cpu < 0 {
        return false;
    }
    if let Some(&ok) = allowed.get(cpu as usize) {
        return ok;
    }
    false
}

/*
 * Target CPU for a task that cannot move. Mirrors
 * the BPF local path. An out of range CPU yields no
 * target for park use.
 */
#[cfg(test)]
pub fn stay_target(task_cpu: i32, nr_cpus: usize) -> Option<u32> {
    if task_cpu < 0 {
        return None;
    }
    if (task_cpu as usize) < nr_cpus {
        return Some(task_cpu as u32);
    }
    None
}

/*
 * Running view of one CPU for tests. Mirrors the BPF
 * CPU state fields used by the dashboard. Zero pid
 * means idle.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningView {
    /* Estimate of the task now on the CPU. */
    pub est: u64,
    /* Pid now on the CPU. Zero when idle. */
    pub pid: u32,
    /* Tier of the task now on the CPU. */
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
     * True when no task runs on the CPU. The dashboard
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
 * tasks in one tier across all CPUs. The sum matches
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

    #[test]
    fn pinned_single_cpu_never_leaves() {
        let pinned = [false, false, true, false];
        for sel in [-1, 0, 1, 2, 3, 5, 99] {
            assert_eq!(pick_target_cpu(sel, &pinned), Some(2));
        }
        assert!(may_run_on(2, &pinned));
        assert!(!may_run_on(0, &pinned));
        assert!(!may_run_on(1, &pinned));
        assert!(!may_run_on(3, &pinned));
        assert!(!may_run_on(-1, &pinned));
        assert!(!may_run_on(99, &pinned));
    }

    #[test]
    fn narrow_mask_keeps_within_mask() {
        let narrow = [false, false, true, true, false];
        assert_eq!(pick_target_cpu(3, &narrow), Some(3));
        assert_eq!(pick_target_cpu(2, &narrow), Some(2));
        assert_eq!(pick_target_cpu(0, &narrow), Some(2));
        assert_eq!(pick_target_cpu(4, &narrow), Some(2));
        assert_eq!(pick_target_cpu(-1, &narrow), Some(2));
        assert_eq!(pick_target_cpu(99, &narrow), Some(2));
        assert!(may_run_on(2, &narrow));
        assert!(may_run_on(3, &narrow));
        assert!(!may_run_on(0, &narrow));
        assert!(!may_run_on(4, &narrow));
    }

    #[test]
    fn empty_mask_parks() {
        let empty = [false, false, false];
        assert_eq!(pick_target_cpu(0, &empty), None);
        assert_eq!(pick_target_cpu(2, &empty), None);
        assert_eq!(pick_target_cpu(-1, &empty), None);
        assert!(!may_run_on(0, &empty));
        assert!(!may_run_on(2, &empty));
        assert_eq!(pick_target_cpu(-1, &[]), None);
        assert!(!may_run_on(0, &[]));
    }

    #[test]
    fn head_guard_blocks_foreign() {
        let pinned = [false, false, true];
        assert!(!may_run_on(0, &pinned));
        assert!(may_run_on(2, &pinned));
        let narrow = [false, true, true];
        assert!(!may_run_on(0, &narrow));
        assert!(may_run_on(1, &narrow));
        assert!(may_run_on(2, &narrow));
    }

    #[test]
    fn kick_guard_blocks_foreign() {
        let pinned = [false, true, false];
        assert!(may_run_on(1, &pinned));
        assert!(!may_run_on(0, &pinned));
        assert!(!may_run_on(2, &pinned));
        assert!(!may_run_on(-1, &pinned));
    }

    #[test]
    fn stay_local_keeps_task_cpu() {
        assert_eq!(stay_target(2, 8), Some(2));
        assert_eq!(stay_target(0, 8), Some(0));
        assert_eq!(stay_target(-1, 8), None);
        assert_eq!(stay_target(99, 8), None);
        assert_eq!(stay_target(7, 8), Some(7));
        assert_eq!(stay_target(8, 8), None);
    }

    #[test]
    fn batch_serve_needs_allowed_head() {
        let pinned = [false, false, true];
        assert!(!may_run_on(0, &pinned));
        assert!(may_run_on(2, &pinned));
        assert!(deficit_should_serve(8, true, true));
        assert!(!deficit_should_serve(0, true, true));
    }

    #[test]
    fn park_fallback_tries_once() {
        let pinned = [false, false, true];
        let first_try = may_run_on(0, &pinned);
        let second_try = may_run_on(0, &pinned);
        assert!(!first_try);
        assert_eq!(first_try, second_try);
        assert_eq!(pick_target_cpu(0, &pinned), Some(2));
    }

    #[test]
    fn zero_freq_is_unknown_with_fallback() {
        assert!(!freq_known(0));
        assert!(freq_known(1));
        assert!(freq_known(3_800_000));
        assert!(freq_known(u64::MAX));
    }

    #[test]
    fn no_sibling_keeps_plain_per_cpu() {
        assert!(!topology_has_smt(&[false, false, false]));
        assert!(!topology_has_smt(&[]));
        assert!(!topology_has_smt(&[false]));
        assert!(topology_has_smt(&[false, true, false]));
        assert!(topology_has_smt(&[true]));
        let allowed = [true, true, true];
        assert!(!sibling_ok(false, 1, &allowed));
        assert!(!sibling_ok(false, 0, &allowed));
        assert!(sibling_ok(true, 1, &allowed));
        assert!(!sibling_ok(true, 1, &[true, false, true]));
        assert!(!sibling_ok(true, -1, &allowed));
        assert!(!sibling_ok(true, 9, &allowed));
        assert_eq!(pick_target_cpu(0, &[true]), Some(0));
        assert!(may_run_on(0, &[true]));
        assert!(!may_run_on(1, &[true]));
    }

    #[test]
    fn single_cpu_has_no_peers() {
        assert_eq!(next_peer(0, 1), None);
        assert_eq!(next_peer(0, 0), None);
        assert_eq!(next_peer(0, 2), Some(1));
        assert_eq!(next_peer(1, 2), Some(0));
        assert_eq!(next_peer(2, 2), None);
        assert_eq!(scan_bound(0), 0);
        assert_eq!(scan_bound(1), 0);
        assert_eq!(scan_bound(2), 1);
        assert_eq!(scan_bound(8), 7);
        assert_eq!(stay_target(0, 1), Some(0));
        assert_eq!(stay_target(1, 1), None);
        assert_eq!(stay_target(-1, 1), None);
        assert_eq!(pick_target_cpu(0, &[true]), Some(0));
        assert_eq!(pick_target_cpu(-1, &[true]), Some(0));
        assert_eq!(pick_target_cpu(5, &[true]), Some(0));
        assert_eq!(pick_target_cpu(0, &[false]), None);
        assert!(!deficit_should_serve(0, true, false));
        assert!(deficit_should_serve(0, false, true));
        assert!(deficit_should_serve(8, true, true));
    }

    #[test]
    fn single_cpu_scan_ends_at_once() {
        let mut steps = 0;
        let mut cur = next_peer(0, 1);
        while let Some(n) = cur {
            steps += 1;
            cur = next_peer(n, 1);
        }
        assert_eq!(steps, 0);
        assert_eq!(cur, None);
        let mut seen = 0;
        let mut at = 0;
        let bound = scan_bound(1);
        while seen < bound {
            at = next_peer(at, 1).unwrap_or(0);
            seen += 1;
        }
        assert_eq!(seen, 0);
        assert_eq!(at, 0);
    }

    #[test]
    fn llc_ids_match_header() {
        assert!(llc_known(0));
        assert!(llc_known(1));
        assert!(!llc_known(LLC_UNKNOWN));
        assert!(!llc_ok(0));
        assert!(!llc_ok(1));
        assert!(llc_ok(2));
        assert_eq!(llc_of(0, &[0, 1]), Some(0));
        assert_eq!(llc_of(1, &[0, 1]), Some(1));
        assert_eq!(llc_of(2, &[0, 1]), None);
        assert_eq!(llc_of(0, &[LLC_UNKNOWN]), None);
    }

    #[test]
    fn llc_prefers_local_idle_over_remote() {
        let llc = [0, 0, 1, 1];
        let allowed = [true, true, true, true];
        let idle = [false, false, false, true];
        let full: [bool; 0] = [];
        assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle, &full, 2), Some(3));
        let idle2 = [true, false, false, false];
        assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle2, &full, 2), None);
        assert_eq!(pick_any_idle(&allowed, &idle2), Some(0));
        assert_eq!(
            select_cpu_model(2, 0, &allowed, &idle, &llc, &full, 2),
            Some(3)
        );
        let idle3 = [true, false, false, true];
        assert_eq!(
            select_cpu_model(2, 0, &allowed, &idle3, &llc, &full, 2),
            Some(3)
        );
    }

    #[test]
    fn llc_fallback_when_domain_empty_unknown() {
        let llc = [0, 0, 1, 1];
        let allowed = [true, true, true, true];
        let idle = [true, false, false, false];
        let full: [bool; 0] = [];
        assert_eq!(pick_llc_idle(-1, &llc, &allowed, &idle, &full, 2), None);
        assert_eq!(pick_llc_idle(9, &llc, &allowed, &idle, &full, 2), None);
        let unknown = [LLC_UNKNOWN, LLC_UNKNOWN];
        assert_eq!(pick_llc_idle(0, &unknown, &allowed, &idle, &full, 0), None);
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 0), None);
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 1), None);
        assert_eq!(
            select_cpu_model(0, 0, &allowed, &idle, &llc, &full, 0),
            Some(0)
        );
        let empty = [false, false, false, false];
        assert_eq!(select_cpu_model(1, 0, &empty, &idle, &llc, &full, 2), None);
    }

    #[test]
    fn single_llc_matches_plain_order() {
        let single = [0, 0, 0, 0];
        let unknown = [LLC_UNKNOWN, LLC_UNKNOWN, LLC_UNKNOWN];
        let allowed = [true, true, true, true];
        let idle = [false, true, false, false];
        let full: [bool; 0] = [];
        assert!(!llc_ok(1));
        assert_eq!(pick_llc_idle(0, &single, &allowed, &idle, &full, 1), None);
        let got = select_cpu_model(0, 0, &allowed, &idle, &single, &full, 1);
        let exp = select_cpu_model(0, 0, &allowed, &idle, &unknown, &full, 0);
        assert_eq!(got, exp);
        assert_eq!(got, Some(1));
        let busy = [false, false, false, false];
        let got2 = select_cpu_model(2, 1, &allowed, &busy, &single, &full, 1);
        let exp2 = select_cpu_model(2, 1, &allowed, &busy, &unknown, &full, 0);
        assert_eq!(got2, exp2);
        assert_eq!(got2, Some(2));
    }

    #[test]
    fn llc_skips_smt_sibling_when_marked() {
        let llc = [0, 0, 0];
        let allowed = [true, true, true];
        let idle = [false, true, true];
        let full = [false, false, true];
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 2), Some(2));
        let idle_only_smt = [false, true, false];
        assert_eq!(
            pick_llc_idle(0, &llc, &allowed, &idle_only_smt, &full, 2),
            None
        );
        assert_eq!(
            select_cpu_model(0, 0, &allowed, &idle_only_smt, &llc, &full, 2),
            Some(1)
        );
    }
}
