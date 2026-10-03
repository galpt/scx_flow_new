// SPDX-License-Identifier: GPL-2.0
//! Fixed slice plus weight helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free slice plus weight bounds plus the no divide
//! scaler shared by BPF and userspace. Order keys on the fair time of
//! deadline plus virtual deadline, so no nice table is needed here.

/// Fixed slice in nanos at 1ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 1_000_000;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;

/// Clamp one weight into range with fail closed to the nearer bound.
#[cfg(test)]
pub fn weight_clamp(w: u32) -> u32 {
    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
}

/// Scaled service for one delta at one weight with banded shifts.
/// Mirrors BPF flow_scaled_delta with no divide and saturation.
#[cfg(test)]
pub fn scaled_delta(delta: u64, weight: u32) -> u64 {
    crate::flow::edf::scaled_delta(delta, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_millisecond() {
        assert_eq!(QUANTUM_NS, 1_000_000);
    }

    #[test]
    fn weights_clamp_to_range() {
        assert_eq!(weight_clamp(0), WEIGHT_MIN);
        assert_eq!(weight_clamp(128), 128);
        assert_eq!(weight_clamp(99_999), WEIGHT_MAX);
    }

    #[test]
    fn scaler_uses_bands_without_divide() {
        assert_eq!(scaled_delta(1_000_000, 128), 1_000_000);
        assert_eq!(scaled_delta(1_000_000, 16), 8_000_000);
        assert_eq!(scaled_delta(1_000_000, 32), 4_000_000);
        assert_eq!(scaled_delta(1_000_000, 1024), 125_000);
    }
}
