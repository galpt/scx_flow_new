// SPDX-License-Identifier: GPL-2.0
//! Weight plus nice plus fair delta mirrors for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF weight.bpf.c with the nice table plus the fair delta
//! scaler plus the effective share. The nice table maps nice minus 20
//! to 19 into weights centred at 128 with kernel ratios scaled by
//! eight. The fair delta scales inversely with weight through one
//! divide with saturation and a floor of one.

/// Base weight with a neutral share.
#[cfg(test)]
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
#[cfg(test)]
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
#[cfg(test)]
pub const WEIGHT_MAX: u32 = 16_384;

/// Nice weight table for nice minus 20 to 19 with nice zero at 128.
#[cfg(test)]
pub const NICE_WEIGHT: [u32; 40] = [
    11095, 8969, 7060, 5784, 4536, 3644, 2906, 2338, 1868, 1489, 1193, 952, 762, 613, 488, 390,
    312, 248, 198, 159, 128, 102, 81, 65, 52, 41, 34, 26, 21, 17, 13, 10, 8, 7, 5, 4, 3, 2, 2, 1,
];

/// Weight for one nice value clamped into minus 20 to 19.
#[cfg(test)]
pub fn nice_to_weight(nice: i32) -> u32 {
    let n = nice.clamp(-20, 19);
    NICE_WEIGHT[(n + 20) as usize]
}

/// Fair scaled service for one delta at one weight with one divide.
#[cfg(test)]
pub fn calc_delta_fair(delta: u64, weight: u32) -> u64 {
    crate::flow::edf::scaled_delta(delta, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_table_centres_at_128() {
        assert_eq!(NICE_WEIGHT.len(), 40);
        assert_eq!(nice_to_weight(0), 128);
        assert_eq!(NICE_WEIGHT[20], 128);
        assert_eq!(nice_to_weight(-20), 11095);
        assert_eq!(nice_to_weight(19), 1);
        assert_eq!(nice_to_weight(-99), 11095);
        assert_eq!(nice_to_weight(99), 1);
    }

    #[test]
    fn calc_matches_neutral_and_scales() {
        assert_eq!(calc_delta_fair(0, 128), 0);
        assert_eq!(calc_delta_fair(1_000_000, 128), 1_000_000);
        assert_eq!(calc_delta_fair(1_000_000, 16), 8_000_000);
        assert_eq!(calc_delta_fair(1_000_000, 1024), 125_000);
        assert_eq!(calc_delta_fair(1, 16_384), 1);
        assert_eq!(calc_delta_fair(u64::MAX, 1), u64::MAX);
    }
}
