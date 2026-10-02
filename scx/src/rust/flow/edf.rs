// SPDX-License-Identifier: GPL-2.0
//! Deadline and admission math kept for header checks.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the release, period, deadline, admission models.
//! The core orders through the quantized tree in veb with admission
//! plus order owned in the core. This file keeps the scalar math as
//! oracle for tests plus header checks with identical share plus
//! bound math. Shares scale with the repeat slice so admitted use
//! stays honest.

/// Default period in nanos at sixteen milliseconds. Holds eight slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Admission bound in per mille at nine hundred fifty. Holds use under
/// ninety five percent of one CPU.
pub const ADMIT_PERMILLE: u64 = 950;
/// Base capacity in units at one thousand twenty four. Symmetric hosts
/// offer the same units on every CPU.
pub const CAP_BASE: u32 = 1024;
/// Lead margin in nanos for one directed preempt. A quarter of the
/// base slice, so near ties never bounce while urgent gaps preempt.
#[cfg(test)]
pub const PREEMPT_MARGIN_NS: u64 = 500_000;
/// Tail in nanos that waits out a nearly done owner. A quarter of
/// the base slice, so a finishing owner never takes a kick.
#[cfg(test)]
pub const PREEMPT_TAIL_NS: u64 = 500_000;

/// Period for one task from hint micros else default.
/// Empty hints use the default period. Large hints saturate.
pub fn task_period(hint_us: u32) -> u64 {
    if hint_us == 0 {
        return PERIOD_NS;
    }
    (hint_us as u64).saturating_mul(1000)
}

/// Absolute deadline from release plus relative period.
/// Large sums saturate at the top.
pub fn deadline_at(release: u64, period: u64) -> u64 {
    release.saturating_add(period)
}

/// Per mille share of one slice in one period.
/// Empty periods yield zero share. A two millisecond slice in a sixteen
/// millisecond period takes one hundred twenty five per mille.
pub fn slice_permille(period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    super::slice::QUANTUM_NS * 1000 / period
}

/// Per mille share of one repeat slice in one period.
/// Empty periods yield zero share. Two milliseconds in sixteen take
/// one hundred twenty five, four take two hundred fifty, eight take
/// five hundred, matching the core repeat steps with no extra threshold.
pub fn slice_permille_for(period: u64, exhaust: u32) -> u64 {
    if exhaust == 0 {
        return slice_permille(period);
    }
    if period == 0 {
        return 0;
    }
    super::slice::quantum_for(exhaust) * 1000 / period
}

/// True when one CPU admits one more per mille share.
/// The admitted sum plus the fresh share stays within the bound.
pub fn admit_ok(admitted: u64, share: u64) -> bool {
    admitted.saturating_add(share) <= ADMIT_PERMILLE
}

/// True when one task missed its deadline at the given time.
/// Empty releases skip. Empty deadlines skip. Times within the deadline pass.
pub fn missed(release: u64, deadline: u64, now: u64) -> bool {
    if release == 0 {
        return false;
    }
    if deadline == 0 {
        return false;
    }
    if now <= deadline {
        return false;
    }
    true
}

/// True when one arrival preempts one occupant under margin plus tail.
/// Empty arrivals never preempt. A far arrival never preempts a
/// rowless occupant, so two rowless tasks never churn. A rowless
/// occupant counts as longer, so an admitted arrival still preempts
/// a reject run. A nearly done occupant finishes instead, and the
/// arrival must lead by the margin, so near ties never bounce.
/// Mirrors the core paired check with the core as authority.
#[cfg(test)]
pub fn preempt_want(arrival: u64, occupant: u64, remain: u64, margin: u64) -> bool {
    if arrival == 0 {
        return false;
    }
    if arrival == u64::MAX && occupant == 0 {
        return false;
    }
    if occupant == 0 {
        return true;
    }
    if remain < PREEMPT_TAIL_NS {
        return false;
    }
    (arrival.saturating_add(margin).wrapping_sub(occupant) as i64) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_defaults_and_hints() {
        assert_eq!(task_period(0), 16_000_000);
        assert_eq!(task_period(8000), 8_000_000);
        assert_eq!(deadline_at(1_000, 16_000_000), 16_001_000);
        assert_eq!(deadline_at(u64::MAX, 16_000_000), u64::MAX);
    }

    #[test]
    fn admission_holds_bound() {
        assert_eq!(slice_permille(16_000_000), 125);
        assert_eq!(slice_permille(0), 0);
        assert_eq!(slice_permille_for(16_000_000, 0), 125);
        assert_eq!(slice_permille_for(16_000_000, 1), 250);
        assert_eq!(slice_permille_for(16_000_000, 2), 500);
        assert_eq!(slice_permille_for(0, 2), 0);
        assert!(admit_ok(825, 125));
        assert!(!admit_ok(826, 125));
        assert!(!admit_ok(u64::MAX, 125));
    }

    #[test]
    fn miss_checks() {
        assert!(!missed(0, 100, 200));
        assert!(!missed(10, 0, 200));
        assert!(!missed(10, 100, 100));
        assert!(missed(10, 100, 101));
    }

    #[test]
    fn preempt_needs_margin_and_long_tail() {
        // Urgent gaps preempt while near ties hold.
        assert!(preempt_want(
            1_000_000,
            10_000_000,
            u64::MAX,
            PREEMPT_MARGIN_NS
        ));
        assert!(!preempt_want(
            9_900_000,
            10_000_000,
            u64::MAX,
            PREEMPT_MARGIN_NS
        ));
        assert!(!preempt_want(
            10_000_000,
            10_000_000,
            u64::MAX,
            PREEMPT_MARGIN_NS
        ));
        assert!(!preempt_want(
            11_000_000,
            10_000_000,
            u64::MAX,
            PREEMPT_MARGIN_NS
        ));
        // A nearly done owner finishes instead of taking a kick.
        assert!(!preempt_want(
            1_000_000,
            10_000_000,
            100_000,
            PREEMPT_MARGIN_NS
        ));
        assert!(preempt_want(
            1_000_000,
            10_000_000,
            PREEMPT_TAIL_NS,
            PREEMPT_MARGIN_NS
        ));
        // Rowless pairs keep the old guards.
        assert!(!preempt_want(0, 10_000_000, u64::MAX, PREEMPT_MARGIN_NS));
        assert!(!preempt_want(u64::MAX, 0, u64::MAX, PREEMPT_MARGIN_NS));
        assert!(preempt_want(1_000_000, 0, u64::MAX, PREEMPT_MARGIN_NS));
        assert_eq!(PREEMPT_MARGIN_NS, 500_000);
        assert_eq!(PREEMPT_TAIL_NS, 500_000);
    }
}
