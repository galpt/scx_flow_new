// SPDX-License-Identifier: GPL-2.0
//! Dynamic slice helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free slice bounds shared by BPF and userspace.

/// Least slice in nanos at 250us.
pub const QMIN_NS: u64 = 250_000;
/// Largest slice in nanos at 15ms.
pub const QMAX_NS: u64 = 15_000_000;
/// Latency target in nanos at 5ms.
pub const LTARGET_NS: u64 = 5_000_000;
/// Micro quantum in nanos at 500us.
pub const MICRO_QUANTUM_NS: u64 = 500_000;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 100;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 10_000;

/// Clamp one weight into 1 to 10000.
/// Zero or oversize weights fail closed to the nearer bound.
#[cfg(test)]
pub fn clamp_weight(w: u32) -> u32 {
    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
}

/// Dynamic slice from weight and queue pressure with no knob.
/// L is the larger of the 5ms target and N times the 250us minimum.
/// Fair is L times weight over N times base, clamped to the bounds.
/// Callers pass the admitting lane depth plus one, so the fast lane
/// sizes from fast pressure and the deadline lane from its own depth
/// with one probe and one divide per enqueue.
#[cfg(test)]
pub fn dyn_slice(weight: u32, queued: u64) -> u64 {
    let w = clamp_weight(weight) as u64;
    let mut n = queued.max(1);
    if n > 1024 {
        n = 1024;
    }
    let mut l = LTARGET_NS;
    if n * QMIN_NS > l {
        l = n * QMIN_NS;
    }
    let fair = l * w / (n * WEIGHT_BASE as u64);
    fair.clamp(QMIN_NS, QMAX_NS)
}

/// Scaled charge of one run segment for the ledger.
/// Heavy weights accrue less virtual time per nanosecond.
#[cfg(test)]
pub fn scaled_delta(delta: u64, weight: u32) -> u64 {
    delta * WEIGHT_BASE as u64 / clamp_weight(weight) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_weight_holds_target_alone() {
        assert_eq!(dyn_slice(100, 1), 5_000_000);
    }

    #[test]
    fn light_weight_clamps_to_minimum() {
        assert_eq!(dyn_slice(1, 1), QMIN_NS);
    }

    #[test]
    fn heavy_weight_clamps_to_maximum() {
        assert_eq!(dyn_slice(10_000, 1), QMAX_NS);
    }

    #[test]
    fn pressure_grows_latency_bound() {
        assert_eq!(dyn_slice(400, 4), 5_000_000);
        assert_eq!(dyn_slice(100, 40), QMIN_NS);
    }

    #[test]
    fn heavy_pressure_clamps_fair_share() {
        assert_eq!(dyn_slice(100, 200), QMIN_NS);
    }

    #[test]
    fn zero_weight_and_queue_fail_closed() {
        assert_eq!(dyn_slice(0, 0), QMIN_NS);
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 10_000);
    }

    #[test]
    fn scaled_charge_favors_heavy_weights() {
        assert_eq!(scaled_delta(1_000_000, 100), 1_000_000);
        assert_eq!(scaled_delta(1_000_000, 1000), 100_000);
        assert_eq!(scaled_delta(1_000_000, 1), 100_000_000);
    }
}
