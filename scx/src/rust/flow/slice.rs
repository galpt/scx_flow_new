// SPDX-License-Identifier: GPL-2.0
//! Slice helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the base slice plus the repeat steps shared by the daemon.
//! Fresh tasks use the base slice. Repeat exhaust steps to four then
//! eight milliseconds capped there. Weights clamp to the near bound.

/// Base slice in nanos at two milliseconds. Fresh tasks use this slice.
pub const QUANTUM_NS: u64 = 2_000_000;
/// Repeat slice in nanos at four milliseconds for one exhaust.
pub const QUANTUM_MID_NS: u64 = 4_000_000;
/// Capped slice in nanos at eight milliseconds for repeat exhaust.
pub const QUANTUM_MAX_NS: u64 = 8_000_000;
/// Largest repeat step kept capped at two.
pub const QUANTUM_MAX_STEP: u32 = 2;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;

/// Clamp one weight into the admitted range.
/// Edge values fall to the near bound.
pub fn clamp_weight(w: u32) -> u32 {
    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
}

/// Slice in nanos for one repeat count capped at eight milliseconds.
/// Zero takes two milliseconds, one takes four, two and above take eight.
pub fn quantum_for(exhaust: u32) -> u64 {
    if exhaust == 0 {
        QUANTUM_NS
    } else if exhaust == 1 {
        QUANTUM_MID_NS
    } else {
        QUANTUM_MAX_NS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_two_milliseconds() {
        assert_eq!(QUANTUM_NS, 2_000_000);
        assert_eq!(QUANTUM_MID_NS, 4_000_000);
        assert_eq!(QUANTUM_MAX_NS, 8_000_000);
        assert_eq!(quantum_for(0), 2_000_000);
        assert_eq!(quantum_for(1), 4_000_000);
        assert_eq!(quantum_for(2), 8_000_000);
        assert_eq!(quantum_for(9), 8_000_000);
    }

    #[test]
    fn edge_weights_fall_to_near_bound() {
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 16_384);
    }
}
