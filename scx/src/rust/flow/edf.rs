// SPDX-License-Identifier: GPL-2.0
//! Deadline and admission math kept for header checks.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the release, period, deadline, admission models.
//! The daemon orders through the quantized tree in veb. This file
//! keeps the scalar math used by admission and by header checks.

/// Default period in nanos at sixteen milliseconds. Holds eight slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Admission bound in per mille at nine hundred fifty. Holds use under
/// ninety five percent of one CPU.
pub const ADMIT_PERMILLE: u64 = 950;
/// Base capacity in units at one thousand twenty four. Symmetric hosts
/// offer the same units on every CPU.
pub const CAP_BASE: u32 = 1024;

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
pub fn slice_permillle(period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    super::slice::QUANTUM_NS * 1000 / period
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
        assert_eq!(slice_permillle(16_000_000), 125);
        assert_eq!(slice_permillle(0), 0);
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
}
