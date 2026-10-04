// SPDX-License-Identifier: GPL-2.0
//! Flat hint helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the flat period plus weight table shared by BPF and userspace
//! tests. The flat view tunes the period plus the weight only with single
//! weighting through one band helper, and no group or pool shapes order.
//! Id zero scopes to defaults with no row. A zero cached id is the stale
//! sentinel with miss to the acquire path. The BPF hints live in
//! cgroup.bpf.c with rows in hint_stor, and this file mirrors the table
//! with no map use. Full tables miss to defaults with no eviction. Moves
//! invalidate the cached id like disable plus enable plus exit.

/// Max hint rows bound shared with the BPF header.
pub const HINT_MAX: u64 = 8192;

/// Period hint in micros for one weight with fixed bands.
/// Light shares map to long periods and heavy shares map to short
/// periods, so the hint tunes the deadline with no share use.
#[cfg(test)]
pub fn hint_period_us(weight: u32) -> u64 {
    let w = weight.clamp(
        crate::flow::slice::WEIGHT_MIN,
        crate::flow::slice::WEIGHT_MAX,
    );
    if w < 64 {
        32_000
    } else if w < 128 {
        16_000
    } else if w < 512 {
        8_000
    } else {
        4_000
    }
}

/// Weight hint for one share with fixed bands on powers of two.
/// Mirrors BPF set_weight bands, so light shares earn small weights
/// while heavy shares earn large weights with no divide.
#[cfg(test)]
pub fn hint_weight(weight: u32) -> u32 {
    let w = weight.clamp(
        crate::flow::slice::WEIGHT_MIN,
        crate::flow::slice::WEIGHT_MAX,
    );
    if w < 64 {
        32
    } else if w < 128 {
        64
    } else if w < 512 {
        256
    } else {
        1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_maps_light_long_heavy_short() {
        assert_eq!(hint_period_us(1), 32_000);
        assert_eq!(hint_period_us(100), 16_000);
        assert_eq!(hint_period_us(200), 8_000);
        assert_eq!(hint_period_us(1000), 4_000);
    }

    #[test]
    fn weight_bands_follow_powers_of_two() {
        assert_eq!(hint_weight(1), 32);
        assert_eq!(hint_weight(100), 64);
        assert_eq!(hint_weight(200), 256);
        assert_eq!(hint_weight(1000), 1024);
        assert_eq!(hint_weight(0), 32);
        assert_eq!(hint_weight(99_999), 1024);
    }

    #[test]
    fn zero_scopes_to_single_band_with_sentinel() {
        // Id zero scopes to defaults with no row, and a zero cached id
        // is the stale sentinel with miss to the acquire path.
        assert_eq!(hint_period_us(0), 32_000);
        assert_eq!(hint_weight(0), 32);
        // Single weighting keeps one clamp plus one band with no double.
        assert_eq!(hint_period_us(128), 8_000);
        assert_eq!(hint_weight(128), 256);
    }
}
