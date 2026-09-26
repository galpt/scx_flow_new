// SPDX-License-Identifier: GPL-2.0
//! Virtual time helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the wrap safe virtual time helpers shared by tests and docs.

/// Bound of moved tasks in one pass.
pub const DISPATCH_BATCH: u32 = 32;
/// Latency target in nanos at 5ms for the lag cap.
#[cfg(test)]
pub const LAG_BASE_NS: u64 = 5_000_000;
/// Base weight with a neutral share.
#[cfg(test)]
pub const LAG_WEIGHT_BASE: u64 = 100;

/// True when the first time is before the second with wrap safety.
/// The signed diff keeps order across the u64 wrap with no extra branch.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Advance virtual time by scaled runtime.
/// The sum wraps with the clock, so long runs stay ordered with no check.
#[cfg(test)]
pub fn vruntime_add(v: u64, delta: u64) -> u64 {
    v.wrapping_add(delta)
}

/// Max of two virtual times with wrap safety.
/// The later time wins, so the minimum never moves backward.
#[cfg(test)]
pub fn min_max(old: u64, next: u64) -> u64 {
    if time_before(old, next) { next } else { old }
}

/// Lag cap for one weight at 5ms times base over weight.
/// Light tasks may lag further behind the minimum than heavy ones.
#[cfg(test)]
pub fn lag_cap(weight: u32) -> u64 {
    let w = crate::flow_slice::clamp_weight(weight) as u64;
    LAG_BASE_NS * LAG_WEIGHT_BASE / w
}

/// Clamped entry virtual time against the CPU minimum.
/// Fresh tasks anchor at minimum minus lag cap with wrap safety.
#[cfg(test)]
pub fn clamp_entry(task_v: u64, min_v: u64, cap: u64) -> u64 {
    let floor = min_v.wrapping_sub(cap);
    if time_before(task_v, floor) {
        floor
    } else {
        task_v
    }
}

/// Synthetic vruntime penalty for one stolen task when enabled.
/// The 500us add is weight scaled, so heavy tasks pay less time.
#[cfg(test)]
pub fn steal_penalty(weight: u32) -> u64 {
    let w = crate::flow_slice::clamp_weight(weight) as u64;
    500_000 * LAG_WEIGHT_BASE / w
}

/// Guarded idle minimum.
/// Keeps the old minimum when the waking value is zero.
#[cfg(test)]
pub fn min_guarded(old: u64, waking_v: u64) -> u64 {
    if waking_v == 0 { old } else { waking_v }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_holds_high_water() {
        assert_eq!(min_max(10, 20), 20);
        assert_eq!(min_max(20, 10), 20);
    }

    #[test]
    fn lag_cap_scales_with_weight() {
        assert_eq!(lag_cap(100), 5_000_000);
        assert_eq!(lag_cap(1000), 500_000);
        assert_eq!(lag_cap(1), 500_000_000);
    }

    #[test]
    fn fresh_task_anchors_at_floor() {
        assert_eq!(clamp_entry(0, 10_000_000, 5_000_000), 5_000_000);
        assert_eq!(clamp_entry(9_000_000, 10_000_000, 5_000_000), 9_000_000);
    }

    #[test]
    fn steal_penalty_scales_with_weight() {
        assert_eq!(steal_penalty(100), 500_000);
        assert_eq!(steal_penalty(1000), 50_000);
    }

    #[test]
    fn vruntime_sums_with_wrap() {
        assert_eq!(vruntime_add(10, 20), 30);
        assert_eq!(vruntime_add(u64::MAX, 1), 0);
    }

    #[test]
    fn guarded_minimum_keeps_zero_wake() {
        assert_eq!(min_guarded(7, 0), 7);
        assert_eq!(min_guarded(7, 9), 9);
    }
}
