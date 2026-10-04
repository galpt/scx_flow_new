// SPDX-License-Identifier: GPL-2.0
//! Deadline plus fairness helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the period plus deadline plus miss plus predictor plus vruntime
//! models shared by BPF and userspace tests. The BPF deadline plus
//! fairness live in intf.h with the deadline checks in edf.bpf.c,
//! and this file mirrors the math with no map use. Every task joins a
//! tier queue with no admission bound, so the predictor shapes the EDF
//! deadline while vruntime shapes the fair time. Fair order via kernel
//! priority queue: the vtime key holds the earlier of deadline plus
//! virtual deadline, so urgent tasks still win with lag bounds.

/// Default period in nanos at 16ms. Holds sixteen slices.
pub const PERIOD_NS: u64 = 16_000_000;
/// Base capacity in units at 1024. Every symmetric CPU offers the same units.
pub const CAP_BASE: u32 = 1024;
/// Least predictor value in nanos at 1. Clamps short bursts with no wrap.
pub const PRED_MIN_NS: u64 = 1;
/// Largest predictor value in nanos at 1s. Clamps long bursts with no wrap.
pub const PRED_MAX_NS: u64 = 1_000_000_000;
/// Allowed lag bound in nanos at 2ms. Bounds sleeper boost with no storm.
#[cfg(test)]
pub const VLAG_MAX_NS: i32 = 2_000_000;

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

/// Absolute deadline from now plus relative period.
/// The add saturates, so a huge now clamps instead of wrapping
/// to the front.
#[cfg(test)]
pub fn deadline_at(now: u64, period: u64) -> u64 {
    now.saturating_add(period)
}

/// Fallback deadline from now plus the hint period with saturation.
/// Tasks with no state join a tier queue at once with this deadline.
#[cfg(test)]
pub fn fallback_deadline(now: u64, hint_us: u32) -> u64 {
    deadline_at(now, task_period(hint_us))
}

/// True when one task missed its deadline at the given time.
/// A zero deadline means no order yet, so the check skips. A time equal
/// to the deadline passes, so only a strictly later time counts. Order
/// uses the wrap safe signed diff like BPF flow_missed, so the check
/// holds across the u64 wrap with no branch.
#[cfg(test)]
pub fn missed(deadline: u64, now: u64) -> bool {
    if deadline == 0 {
        return false;
    }
    if now == deadline {
        return false;
    }
    (now.wrapping_sub(deadline) as i64) > 0
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
/// Tracks the absolute error against the new average with one quarter
/// steps, so stable bursts keep a small margin while ragged bursts widen
/// with no jump. Callers pass the new average from pred_avg. A zero
/// deviation takes the max of error and new average quarter as the floor
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

/// Train average plus deviation from one sample with the new average.
/// Mirrors BPF stopping plus leftover order, so the deviation tracks the
/// fresh mean with no lagging bound.
#[cfg(test)]
pub fn pred_train(avg: u64, dev: u64, delta: u64) -> (u64, u64) {
    let n_avg = pred_avg(avg, delta);
    let n_dev = pred_dev(dev, n_avg, delta);
    (n_avg, n_dev)
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

/// Predicted deadline from now plus predictor else hint period.
/// A zero average means no history, so the hint period applies with
/// the default when the hint is zero.
#[cfg(test)]
pub fn pred_deadline(now: u64, avg: u64, dev: u64, hint_us: u32) -> u64 {
    let period = if avg == 0 {
        task_period(hint_us)
    } else {
        pred_period(avg, dev)
    };
    now.saturating_add(period)
}

/// Clamp one weight into the scheduler range.
/// Zero or oversize weights fail closed to the nearer bound.
#[cfg(test)]
pub fn weight_clamp(w: u32) -> u32 {
    w.clamp(
        crate::flow::slice::WEIGHT_MIN,
        crate::flow::slice::WEIGHT_MAX,
    )
}

/// Scaled service for one delta at one weight with one divide.
/// The neutral weight of 128 keeps the delta unchanged, lighter tasks
/// grow while heavier tasks shrink with saturation and a floor of one.
/// Mirrors BPF flow_scaled_delta plus weight calc_delta_fair.
#[cfg(test)]
pub fn scaled_delta(delta: u64, weight: u32) -> u64 {
    let w = weight_clamp(weight);
    if delta == 0 {
        return 0;
    }
    let w = if w == 0 {
        crate::flow::slice::WEIGHT_MIN
    } else {
        w
    };
    if delta > u64::MAX / crate::flow::slice::WEIGHT_BASE as u64 {
        return u64::MAX;
    }
    let out = delta * crate::flow::slice::WEIGHT_BASE as u64 / w as u64;
    if out == 0 {
        return 1;
    }
    out
}

/// Advanced vruntime after one delta at one weight with saturation.
#[cfg(test)]
pub fn vruntime_advance(vruntime: u64, delta: u64, weight: u32) -> u64 {
    vruntime.saturating_add(scaled_delta(delta, weight))
}

/// True when the first time is before the second with wrap safety.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Clamped lag within plus or minus 2ms.
#[cfg(test)]
pub fn lag_clamp(lag: i32) -> i32 {
    lag.clamp(-VLAG_MAX_NS, VLAG_MAX_NS)
}

/// True when one vruntime is eligible against the CPU minimum.
/// Eligible means the vruntime falls no more than the allowed lag past
/// the minimum, so lagging tasks wait while leading tasks pace.
#[cfg(test)]
pub fn eligible(vruntime: u64, min_vruntime: u64, vlag: i32) -> bool {
    let lag = lag_clamp(vlag).max(0) as u64;
    let limit = min_vruntime.saturating_add(lag);
    if limit == u64::MAX {
        return true;
    }
    if vruntime == limit {
        return true;
    }
    time_before(vruntime, limit)
}

/// Virtual deadline from eligible plus request over weight.
#[cfg(test)]
pub fn virt_deadline(ve: u64, request: u64, weight: u32) -> u64 {
    ve.saturating_add(scaled_delta(request, weight))
}

/// Fair queue key as the earlier of deadline plus virtual deadline.
#[cfg(test)]
pub fn fair_vtime(deadline: u64, vd: u64) -> u64 {
    if deadline == 0 {
        return vd;
    }
    if vd == 0 {
        return deadline;
    }
    if time_before(vd, deadline) {
        return vd;
    }
    deadline
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
        assert_eq!(fallback_deadline(1_000, 0), 16_001_000);
        assert_eq!(fallback_deadline(1_000, 8000), 8_001_000);
    }

    #[test]
    fn miss_checks_without_stored_release() {
        assert!(!missed(0, 200));
        assert!(!missed(100, 100));
        assert!(missed(100, 101));
        assert!(missed(u64::MAX - 1, 5));
        assert!(!missed(u64::MAX - 1, u64::MAX - 2));
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
    fn pred_train_uses_new_avg() {
        let (n_avg, n_dev) = pred_train(8_000_000, 1_000_000, 16_000_000);
        assert_eq!(n_avg, pred_avg(8_000_000, 16_000_000));
        assert_eq!(n_dev, pred_dev(1_000_000, n_avg, 16_000_000));
        // Pinned recompute uses the predictor plus hint like open tasks.
        assert_eq!(pred_deadline(1_000, 0, 0, 8000), 8_001_000);
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

    #[test]
    fn scaler_keeps_neutral_shifts_bands() {
        assert_eq!(scaled_delta(1_000_000, 128), 1_000_000);
        assert_eq!(scaled_delta(1_000_000, 16), 8_000_000);
        assert_eq!(scaled_delta(1_000_000, 32), 4_000_000);
        assert_eq!(scaled_delta(1_000_000, 64), 2_000_000);
        assert_eq!(scaled_delta(1_000_000, 256), 500_000);
        assert_eq!(scaled_delta(1_000_000, 1024), 125_000);
        assert_eq!(scaled_delta(u64::MAX, 1), u64::MAX);
        assert_eq!(vruntime_advance(1_000, 1_000_000, 128), 1_001_000);
    }

    #[test]
    fn lag_clamps_and_gates_eligibility() {
        assert_eq!(lag_clamp(5_000_000), 2_000_000);
        assert_eq!(lag_clamp(-5_000_000), -2_000_000);
        assert!(eligible(1_000, 1_000, 0));
        assert!(eligible(500, 1_000, 0));
        assert!(!eligible(1_001, 1_000, 0));
        assert!(eligible(3_000_000, 1_000_000, 2_000_000));
        assert!(!eligible(3_000_001, 1_000_000, 2_000_000));
    }

    #[test]
    fn virtual_deadline_paces_fair_time() {
        let vd = virt_deadline(1_000_000, 1_000_000, 128);
        assert_eq!(vd, 2_000_000);
        assert_eq!(fair_vtime(10_000_000, vd), vd);
        assert_eq!(fair_vtime(1_000_000, vd), 1_000_000);
        assert_eq!(fair_vtime(0, vd), vd);
    }
}
