// SPDX-License-Identifier: GPL-2.0
//! Fixed quantum helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free quantum and weight bounds shared by BPF and userspace.

/// Fixed slice in nanos at 1ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 1_000_000;
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

/// Deadline step for one weight as quantum times base over weight.
/// Base weight waits one quantum, heavy weights wait less, and light
/// weights wait more, so shares stay proportional through order.
#[cfg(test)]
pub fn deadline_step(weight: u32) -> u64 {
    QUANTUM_NS * WEIGHT_BASE as u64 / clamp_weight(weight) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_millisecond() {
        assert_eq!(QUANTUM_NS, 1_000_000);
    }

    #[test]
    fn base_weight_waits_one_quantum() {
        assert_eq!(deadline_step(100), 1_000_000);
    }

    #[test]
    fn heavy_weight_waits_less() {
        assert_eq!(deadline_step(10_000), 10_000);
        assert_eq!(deadline_step(1000), 100_000);
    }

    #[test]
    fn light_weight_waits_more() {
        assert_eq!(deadline_step(1), 100_000_000);
        assert_eq!(deadline_step(50), 2_000_000);
    }

    #[test]
    fn zero_weight_and_oversize_fail_closed() {
        assert_eq!(deadline_step(0), deadline_step(1));
        assert_eq!(deadline_step(99_999), deadline_step(10_000));
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 10_000);
    }
}
