// SPDX-License-Identifier: GPL-2.0
//! Virtual runtime helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the weight bounds plus the runtime advance shared by BPF and userspace.
//! Order carries weight through advancing runtime with no fixed service step.

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

/// Advanced runtime after one execution segment.
/// Scales raw time by base over effective weight with saturating add,
/// so heavy shares advance slowly and light shares advance fast.
/// Splits the divide to keep every intermediate small with no wrap.
#[cfg(test)]
pub fn vruntime_advance(vruntime: u64, delta: u64, eff: u32) -> u64 {
    let w = clamp_weight(eff) as u64;
    let adv = delta / w * WEIGHT_BASE as u64 + delta % w * WEIGHT_BASE as u64 / w;
    vruntime.saturating_add(adv)
}

/// Key deadline from runtime with the floor clamp.
/// The later of runtime and floor wins, so a long sleep never earns
/// credit and a back to back arrival queues past its own runtime.
#[cfg(test)]
pub fn deadline_clamp(vruntime: u64, floor: u64) -> u64 {
    crate::flow_edf::time_max(vruntime, floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_weight_advances_raw_time() {
        assert_eq!(vruntime_advance(0, 1_000_000, 100), 1_000_000);
        assert_eq!(vruntime_advance(5_000_000, 1_000_000, 100), 6_000_000);
    }

    #[test]
    fn heavy_weight_advances_slowly() {
        assert_eq!(vruntime_advance(0, 1_000_000, 10_000), 10_000);
        assert_eq!(vruntime_advance(0, 1_000_000, 1000), 100_000);
    }

    #[test]
    fn light_weight_advances_fast() {
        assert_eq!(vruntime_advance(0, 1_000_000, 1), 100_000_000);
        assert_eq!(vruntime_advance(0, 1_000_000, 50), 2_000_000);
    }

    #[test]
    fn zero_weight_and_oversize_fail_closed() {
        assert_eq!(
            vruntime_advance(0, 1_000_000, 0),
            vruntime_advance(0, 1_000_000, 1)
        );
        assert_eq!(
            vruntime_advance(0, 1_000_000, 99_999),
            vruntime_advance(0, 1_000_000, 10_000)
        );
        assert_eq!(clamp_weight(0), 1);
        assert_eq!(clamp_weight(99_999), 10_000);
    }

    #[test]
    fn advance_saturates_past_max() {
        assert_eq!(vruntime_advance(u64::MAX, 1_000_000, 100), u64::MAX);
        assert_eq!(vruntime_advance(u64::MAX - 5, 1_000_000, 1), u64::MAX);
    }

    #[test]
    fn segments_accumulate_monotonic() {
        let mut v = 0u64;
        v = vruntime_advance(v, 500_000, 100);
        v = vruntime_advance(v, 500_000, 200);
        assert_eq!(v, 500_000 + 250_000);
        v = vruntime_advance(v, 0, 100);
        assert_eq!(v, 750_000);
    }

    #[test]
    fn clamp_drops_sleeper_credit() {
        assert_eq!(deadline_clamp(1_000, 10_000_000), 10_000_000);
        assert_eq!(deadline_clamp(11_000_000, 10_000_000), 11_000_000);
        assert_eq!(deadline_clamp(10_000_000, 10_000_000), 10_000_000);
    }
}
