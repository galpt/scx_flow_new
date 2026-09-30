// SPDX-License-Identifier: GPL-2.0
//! Fixed slice helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the fixed slice and the weight bounds shared by the daemon.
//! Every insert uses the fixed slice. Weights clamp to the near bound.

/// Fixed slice in nanos at two milliseconds. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 2_000_000;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_two_milliseconds() {
        assert_eq!(QUANTUM_NS, 2_000_000);
    }

    #[test]
    fn edge_weights_fall_to_near_bound() {
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 16_384);
    }
}
