// SPDX-License-Identifier: GPL-2.0
//! Fixed slice helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free slice and weight bounds plus the nice table
//! shared by BPF and userspace.

/// Fixed slice in nanos at 2ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 2_000_000;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;

/// Weight table for 40 nice levels from minus 20 to 19.
/// Index is nice plus 20 with center 1024 at nice 0.
/// Ends are 2048 at minus 20 and 256 at 19,
/// so total spread K is 8 with boost 2x and penalty 4x.
/// Made as 1024 times 2 to minus nice over 20 below 1,
/// else 1024 times 4 to minus nice over 19, rounded.
/// The maker is docs only, the table is rodata.
#[cfg(test)]
pub const WEIGHT_TABLE: [u16; 40] = [
    2048, 1978, 1911, 1846, 1783, 1722, 1663, 1607, 1552, 1499, 1448, 1399, 1351, 1305, 1261, 1218,
    1176, 1136, 1097, 1060, 1024, 952, 885, 823, 765, 711, 661, 614, 571, 531, 494, 459, 427, 397,
    369, 343, 319, 296, 275, 256,
];

/// Clamp one weight into 1 to 16384.
/// Zero or oversize weights fail closed to the nearer bound.
#[cfg(test)]
pub fn clamp_weight(w: u32) -> u32 {
    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
}

/// Weight of one nice level from the table.
/// Out of range maps to 1024 with no trap.
/// Nice 0 skips the table with no load.
#[cfg(test)]
pub fn weight_of(nice: i32) -> u32 {
    if nice == 0 {
        return 1024;
    }
    if nice < -20 || nice > 19 {
        return 1024;
    }
    WEIGHT_TABLE[(nice + 20) as usize] as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_two_milliseconds() {
        assert_eq!(QUANTUM_NS, 2_000_000);
    }

    #[test]
    fn zero_weight_and_oversize_fail_closed() {
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 16_384);
    }

    #[test]
    fn weight_table_matches_header() {
        assert_eq!(WEIGHT_TABLE.len(), 40);
        assert_eq!(WEIGHT_TABLE[0], 2048);
        assert_eq!(WEIGHT_TABLE[20], 1024);
        assert_eq!(WEIGHT_TABLE[39], 256);
        assert_eq!(weight_of(0), 1024);
        assert_eq!(weight_of(-20), 2048);
        assert_eq!(weight_of(19), 256);
        assert_eq!(weight_of(-21), 1024);
        assert_eq!(weight_of(20), 1024);
        assert_eq!(weight_of(-19), 1978);
        assert_eq!(weight_of(1), 952);
    }
}
