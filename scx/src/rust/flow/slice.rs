// SPDX-License-Identifier: GPL-2.0
//! Fixed slice helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free slice and weight bounds shared by BPF and
//! userspace. Order keys on the absolute deadline with no runtime
//! tiebreak, so no nice table is needed here.

/// Fixed slice in nanos at 1ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 1_000_000;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_millisecond() {
        assert_eq!(QUANTUM_NS, 1_000_000);
    }
}
