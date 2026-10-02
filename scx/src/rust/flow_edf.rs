// SPDX-License-Identifier: GPL-2.0
//! Deadline plus admission helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the release plus period plus deadline plus admission plus miss
//! plus predictor models shared by BPF and userspace tests. The BPF
//! deadline lives in intf.h with the admission rows in
//! main/deadline.bpf.c, and this file mirrors the math with no map use.
//! Admission stays hint based always while the predictor shapes only
//! the deadline, so steady work keeps a small share.

/// Default period in nanos at 16ms. Holds eight slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Admission bound in per mille at 950. Holds use under ninety five percent.
pub const ADMIT_PERMILLE: u64 = 950;
/// Base capacity in units at 1024. Every symmetric CPU offers the same units.
pub const CAP_BASE: u32 = 1024;
/// Least predictor value in nanos at 1. Clamps short bursts with no wrap.
pub const PRED_MIN_NS: u64 = 1;
/// Largest predictor value in nanos at 1s. Clamps long bursts with no wrap.
pub const PRED_MAX_NS: u64 = 1_000_000_000;

/// Period for one task from hint micros else default.
/// A zero hint means no hint, so the default period applies. The hint
/// converts from micros to nanos with saturation, so a huge hint
/// clamps instead of wrapping to a short period.
#[cfg(test)]
pub fn task_period(hint_us: u32) -> u64 {
    if hint_us == 0 {
        return PERIOD_NS;
    }
    (hint_us as u64).saturating_mul(1000)
}

/// Absolute deadline from release plus relative period.
/// The add saturates, so a huge release clamps instead of wrapping
/// to the front.
#[cfg(test)]
pub fn deadline_at(release: u64, period: u64) -> u64 {
    release.saturating_add(period)
}

/// Per mille share of one slice in one period with saturation.
/// A zero period means no bound, so the share stays zero. A 2ms slice
/// in a 16ms period takes 125 per mille.
#[cfg(test)]
pub fn slice_permillle(period: u64) -> u64 {
    if period == 0 {
        return 0;
    }
    crate::flow_slice::QUANTUM_NS * 1000 / period
}

/// Admission share of one task from the hint period always.
/// A zero hint means no hint, so the default period applies. The
/// predictor never shapes this share, so steady work keeps a small
/// share while short bursts earn only tight deadlines.
#[cfg(test)]
pub fn admit_share(hint_us: u32) -> u64 {
    slice_permillle(task_period(hint_us))
}

/// True when one CPU can admit one more per mille share.
/// The admitted sum plus the new share must stay under the bound, so
/// admitted work keeps idle time for late wakeups. A wrapped sum fails
/// closed, so an overflow never admits.
#[cfg(test)]
pub fn admit_ok(admitted: u64, share: u64) -> bool {
    match admitted.checked_add(share) {
        None => false,
        Some(sum) => sum <= ADMIT_PERMILLE,
    }
}

/// True when one task missed its deadline at the given time.
/// A zero deadline means no order yet, so the check skips. A zero
/// release means no release yet, so the check skips too.
#[cfg(test)]
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

/// Clamped predictor value in 1ns to 1s with no wrap.
/// Values below the floor rise to 1ns and values past the top fall
/// to 1s, so a huge burst never wraps to a short deadline.
#[cfg(test)]
pub fn pred_clamp(v: u64) -> u64 {
    v.clamp(PRED_MIN_NS, PRED_MAX_NS)
}

/// Updated burst average with shift 3 and saturation.
/// A zero average means no history, so the first sample sets the
/// average at once. Later samples move one eighth toward the new
/// delta with shifts only.
#[cfg(test)]
pub fn pred_avg(avg: u64, delta: u64) -> u64 {
    let d = pred_clamp(if delta == 0 { PRED_MIN_NS } else { delta });
    if avg == 0 {
        return d;
    }
    if d > avg {
        avg.saturating_add((d - avg) >> 3)
            .clamp(PRED_MIN_NS, PRED_MAX_NS)
    } else {
        let diff = (avg - d) >> 3;
        if diff > avg {
            return PRED_MIN_NS;
        }
        pred_clamp(avg - diff)
    }
}

/// Updated burst deviation with shift 2 and saturation.
/// Tracks the absolute error with one quarter steps, so stable bursts
/// keep a small margin while ragged bursts widen with no jump. A zero
/// deviation takes the max of error and average quarter as the floor
/// with shifts plus clamp kept.
#[cfg(test)]
pub fn pred_dev(dev: u64, avg: u64, delta: u64) -> u64 {
    let d = pred_clamp(if delta == 0 { PRED_MIN_NS } else { delta });
    let a = if avg == 0 { d } else { avg };
    let err_raw = d.abs_diff(a);
    let err = pred_clamp(if err_raw == 0 { PRED_MIN_NS } else { err_raw });
    if dev == 0 {
        let floor = avg >> 2;
        if floor > err {
            return pred_clamp(floor);
        }
        return err;
    }
    if err > dev {
        pred_clamp(dev.saturating_add((err - dev) >> 2))
    } else {
        let diff = (dev - err) >> 2;
        if diff > dev {
            return PRED_MIN_NS;
        }
        pred_clamp(dev - diff)
    }
}

/// Predicted period from average plus deviation with fallback.
/// A zero average means no history, so the default period applies.
#[cfg(test)]
pub fn pred_period(avg: u64, dev: u64) -> u64 {
    if avg == 0 {
        return PERIOD_NS;
    }
    pred_clamp(avg.saturating_add(dev))
}

/// Predicted deadline from release plus predictor else hint period.
/// A zero average means no history, so the hint period applies with
/// the default when the hint is zero.
#[cfg(test)]
pub fn pred_deadline(release: u64, avg: u64, dev: u64, hint_us: u32) -> u64 {
    let period = if avg == 0 {
        task_period(hint_us)
    } else {
        pred_period(avg, dev)
    };
    release.saturating_add(period)
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
        assert!(!admit_ok(u64::MAX - 10, 20));
    }

    #[test]
    fn admission_stays_hint_based() {
        assert_eq!(admit_share(0), 125);
        assert_eq!(admit_share(8000), 250);
        assert_eq!(admit_share(4000), 500);
        // A short predictor period must not inflate the share: a 2.5ms
        // predicted window would take 800 per mille, while the hint
        // share stays small for the same task.
        assert_eq!(slice_permillle(2_500_000), 800);
        assert_eq!(admit_share(0), 125);
    }

    #[test]
    fn miss_checks() {
        assert!(!missed(0, 100, 200));
        assert!(!missed(10, 0, 200));
        assert!(!missed(10, 100, 100));
        assert!(missed(10, 100, 101));
    }

    #[test]
    fn pred_clamps_range() {
        assert_eq!(pred_clamp(0), 1);
        assert_eq!(pred_clamp(1), 1);
        assert_eq!(pred_clamp(1_000_000_000), 1_000_000_000);
        assert_eq!(pred_clamp(u64::MAX), 1_000_000_000);
    }

    #[test]
    fn pred_avg_first_sets_then_shifts() {
        assert_eq!(pred_avg(0, 2_000_000), 2_000_000);
        assert_eq!(pred_avg(0, 0), 1);
        let up = pred_avg(8_000_000, 16_000_000);
        assert_eq!(up, 9_000_000);
        let down = pred_avg(16_000_000, 8_000_000);
        assert_eq!(down, 15_000_000);
        assert_eq!(pred_avg(u64::MAX, u64::MAX), PRED_MAX_NS);
    }

    #[test]
    fn pred_dev_tracks_error() {
        assert_eq!(pred_dev(0, 0, 2_000_000), 1);
        assert_eq!(pred_dev(0, 2_000_000, 2_000_000), 500_000);
        assert_eq!(pred_dev(0, 4_000_000, 4_000_000), 1_000_000);
        assert_eq!(pred_dev(0, 1_000_000, 2_000_000), 1_000_000);
        let wide = pred_dev(1, 2_000_000, 4_000_000);
        assert!(wide > 1);
        assert_eq!(pred_dev(100, 1_000, 1_000), 76);
    }

    #[test]
    fn pred_period_falls_back_then_clamps() {
        assert_eq!(pred_period(0, 0), 16_000_000);
        assert_eq!(pred_period(2_000_000, 500_000), 2_500_000);
        assert_eq!(pred_period(u64::MAX, u64::MAX), PRED_MAX_NS);
    }

    #[test]
    fn pred_deadline_uses_hint_then_predictor() {
        assert_eq!(pred_deadline(1_000, 0, 0, 0), 16_001_000);
        assert_eq!(pred_deadline(1_000, 0, 0, 8000), 8_001_000);
        assert_eq!(pred_deadline(1_000, 2_000_000, 500_000, 0), 2_501_000);
        assert_eq!(pred_deadline(u64::MAX, 2_000_000, 0, 0), u64::MAX);
    }
}
