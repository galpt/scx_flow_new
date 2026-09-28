// SPDX-License-Identifier: GPL-2.0
//! Served runtime helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the virtual runtime advance plus the floor clamp plus the
//! open key helpers shared by tests. The BPF runtime lives in
//! intf.h with the floor in main/floor.bpf.c, and this file mirrors
//! the math with no map use.

/// Clamp one share into 1 to 10000.
/// Zero or oversize shares fail closed to the nearer bound.
#[cfg(test)]
pub fn clamp_share(w: u32) -> u32 {
    w.clamp(crate::flow_slice::WEIGHT_MIN, crate::flow_slice::WEIGHT_MAX)
}

/// Advanced runtime after one execution segment.
/// Scales raw time by base over the effective share with a split
/// divide, so heavy shares advance slowly and light shares advance
/// fast. The split keeps every intermediate small for real segments,
/// a segment past the scale bound saturates at once, and both adds
/// saturate too, so huge inputs clamp instead of wrapping.
#[cfg(test)]
pub fn runtime_advance(vruntime: u64, delta: u64, eff: u32) -> u64 {
    let w = clamp_share(eff) as u64;
    let base = crate::flow_slice::WEIGHT_BASE as u64;
    let q = delta / w;
    if q > u64::MAX / base {
        return u64::MAX;
    }
    let adv = (q * base).saturating_add(delta % w * base / w);
    vruntime.saturating_add(adv)
}

/// Later of two saturated times with a plain compare.
/// Saturated values never wrap, so the plain order keeps the
/// largest value with no signed diff use. Real times far below
/// the bound order the same either way.
#[cfg(test)]
pub fn later(a: u64, b: u64) -> u64 {
    a.max(b)
}

/// Later of two floor times with a plain compare.
/// Saturated floors never wrap, so the plain order keeps the
/// largest value with no signed diff use.
#[cfg(test)]
pub fn floor_max(cur: u64, val: u64) -> u64 {
    later(cur, val)
}

/// Slack for one open insert as the step capped at 2ms.
/// Base weight keeps one quantum, heavy weights keep less, and light
/// weights stop at twice the quantum, so a light task never leaps
/// past the starvation floor in one arrival.
#[cfg(test)]
pub fn deadline_slack(weight: u32) -> u64 {
    crate::flow_slice::deadline_step(weight).min(crate::flow_edf::STARVE_NS)
}

/// Key deadline from a base past the floor with slack.
/// The later of base and floor wins, so a long sleep never earns
/// credit past served work, and the add saturates, so a huge floor
/// clamps instead of wrapping to the front.
#[cfg(test)]
pub fn deadline_key(base: u64, floor: u64, slack: u64) -> u64 {
    later(base, floor).saturating_add(slack)
}

/// Share for one runtime charge with cold plus zero folding to base.
/// A cold cache uses base share, and a zero share folds to base too,
/// so the advance never divides by zero.
#[cfg(test)]
pub fn charge_share(cached: bool, eweight: u32) -> u32 {
    let s = if cached {
        eweight
    } else {
        crate::flow_slice::WEIGHT_BASE
    };
    if s == 0 {
        crate::flow_slice::WEIGHT_BASE
    } else {
        s
    }
}

/// Open insert key from runtime plus last plus now plus floor.
/// Takes the later of runtime, last deadline, and now, then keys
/// past the floor with the share slack. Only the open path keys
/// here, parks keep no key use.
#[cfg(test)]
pub fn insert_key(vruntime: u64, last: u64, now: u64, floor: u64, eff: u32) -> u64 {
    let base = later(later(vruntime, now), last);
    deadline_key(base, floor, deadline_slack(eff))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consts_match_header() {
        assert_eq!(
            crate::flow_slice::WEIGHT_BASE,
            crate::bpf_intf::flow_consts_FLOW_WEIGHT_BASE as u32
        );
        assert_eq!(
            crate::flow_slice::WEIGHT_MIN,
            crate::bpf_intf::flow_consts_FLOW_WEIGHT_MIN as u32
        );
        assert_eq!(
            crate::flow_slice::WEIGHT_MAX,
            crate::bpf_intf::flow_consts_FLOW_WEIGHT_MAX as u32
        );
        assert_eq!(
            crate::flow_edf::STARVE_NS,
            crate::bpf_intf::flow_consts_FLOW_STARVE_NS as u64
        );
        assert_eq!(
            crate::flow_select::MAX_CPUS,
            crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as u32
        );
        assert_eq!(crate::flow_select::MAX_CPUS, 1024);
    }

    #[test]
    fn base_weight_advances_raw_time() {
        assert_eq!(runtime_advance(0, 1_000_000, 100), 1_000_000);
        assert_eq!(runtime_advance(5_000_000, 1_000_000, 100), 6_000_000);
    }

    #[test]
    fn heavy_weight_advances_slowly() {
        assert_eq!(runtime_advance(0, 1_000_000, 10_000), 10_000);
        assert_eq!(runtime_advance(0, 1_000_000, 1000), 100_000);
    }

    #[test]
    fn light_weight_advances_fast() {
        assert_eq!(runtime_advance(0, 1_000_000, 1), 100_000_000);
        assert_eq!(runtime_advance(0, 1_000_000, 50), 2_000_000);
    }

    #[test]
    fn zero_weight_and_oversize_fail_closed() {
        assert_eq!(
            runtime_advance(0, 1_000_000, 0),
            runtime_advance(0, 1_000_000, 1)
        );
        assert_eq!(
            runtime_advance(0, 1_000_000, 99_999),
            runtime_advance(0, 1_000_000, 10_000)
        );
        assert_eq!(clamp_share(0), 1);
        assert_eq!(clamp_share(99_999), 10_000);
    }

    #[test]
    fn advance_saturates_past_max() {
        assert_eq!(runtime_advance(u64::MAX, 1_000_000, 100), u64::MAX);
        assert_eq!(runtime_advance(u64::MAX - 5, 1_000_000, 1), u64::MAX);
        assert_eq!(runtime_advance(u64::MAX, 0, 100), u64::MAX);
    }

    #[test]
    fn segments_accumulate_monotonic() {
        let mut v = 0u64;
        v = runtime_advance(v, 500_000, 100);
        v = runtime_advance(v, 500_000, 200);
        assert_eq!(v, 500_000 + 250_000);
        v = runtime_advance(v, 0, 100);
        assert_eq!(v, 750_000);
    }

    #[test]
    fn advance_matches_exact_ratio() {
        for delta in [
            0u64,
            1,
            999_999,
            1_000_000,
            1_000_001,
            u64::MAX / 3,
            u64::MAX,
        ] {
            for eff in [0u32, 1, 3, 100, 9999, 10_000, 99_999] {
                let w = clamp_share(eff) as u128;
                let exact = delta as u128 * 100 / w;
                let want = exact.min(u64::MAX as u128) as u64;
                assert_eq!(runtime_advance(0, delta, eff), want);
                assert_eq!(
                    runtime_advance(7_000_000, delta, eff),
                    7_000_000u64.saturating_add(want)
                );
            }
        }
    }

    #[test]
    fn later_keeps_largest_without_wrap() {
        assert_eq!(later(10, 20), 20);
        assert_eq!(later(20, 10), 20);
        assert_eq!(later(10, 10), 10);
        assert_eq!(later(u64::MAX, 1), u64::MAX);
        assert_eq!(later(1, u64::MAX), u64::MAX);
        assert_eq!(later(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(later(0, 0), 0);
    }

    #[test]
    fn floor_keeps_later_time() {
        assert_eq!(floor_max(10, 20), 20);
        assert_eq!(floor_max(20, 10), 20);
        assert_eq!(floor_max(10, 10), 10);
        assert_eq!(floor_max(0, 0), 0);
        assert_eq!(floor_max(0, 7_000_000), 7_000_000);
    }

    #[test]
    fn floor_boundary_never_regresses() {
        assert_eq!(floor_max(u64::MAX, 1), u64::MAX);
        assert_eq!(floor_max(1, u64::MAX), u64::MAX);
        assert_eq!(floor_max(u64::MAX - 3, 5), u64::MAX - 3);
        assert_eq!(floor_max(5, u64::MAX - 3), u64::MAX - 3);
        assert_eq!(floor_max(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn slack_caps_light_weights_at_starve() {
        assert_eq!(deadline_slack(100), 1_000_000);
        assert_eq!(deadline_slack(1000), 100_000);
        assert_eq!(deadline_slack(10_000), 10_000);
        assert_eq!(deadline_slack(50), 2_000_000);
        assert_eq!(deadline_slack(1), crate::flow_edf::STARVE_NS);
        assert_eq!(deadline_slack(0), crate::flow_edf::STARVE_NS);
        assert!(deadline_slack(1) <= crate::flow_edf::STARVE_NS);
    }

    #[test]
    fn key_takes_later_plus_slack() {
        assert_eq!(deadline_key(10_000_000, 9_000_000, 1_000_000), 11_000_000);
        assert_eq!(deadline_key(9_000_000, 10_000_000, 1_000_000), 11_000_000);
        assert_eq!(deadline_key(10_000_000, 10_000_000, 1_000_000), 11_000_000);
        assert_eq!(deadline_key(1_000, 2_000, 0), 2_000);
    }

    #[test]
    fn key_saturates_past_max() {
        assert_eq!(deadline_key(u64::MAX, u64::MAX, 1_000_000), u64::MAX);
        assert_eq!(deadline_key(u64::MAX - 5, 0, 1_000_000), u64::MAX);
        assert_eq!(deadline_key(0, u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn key_boundary_clamps_without_wrap() {
        assert_eq!(deadline_key(u64::MAX, 5, 10), u64::MAX);
        assert_eq!(deadline_key(5, u64::MAX, 10), u64::MAX);
        assert_eq!(deadline_key(u64::MAX, u64::MAX, 0), u64::MAX);
        assert_eq!(deadline_key(0, 0, 0), 0);
    }

    #[test]
    fn share_folds_cold_and_zero_to_base() {
        assert_eq!(charge_share(true, 200), 200);
        assert_eq!(charge_share(true, 1), 1);
        assert_eq!(charge_share(false, 200), crate::flow_slice::WEIGHT_BASE);
        assert_eq!(charge_share(false, 0), crate::flow_slice::WEIGHT_BASE);
        assert_eq!(charge_share(true, 0), crate::flow_slice::WEIGHT_BASE);
    }

    #[test]
    fn insert_key_anchors_sleepers_past_now() {
        assert_eq!(insert_key(1_000, 1_000, 10_000_000, 0, 100), 11_000_000);
        assert_eq!(
            insert_key(1_000, 1_000, 10_000_000, 12_000_000, 100),
            13_000_000
        );
    }

    #[test]
    fn insert_key_queues_back_to_back_behind_last() {
        assert_eq!(
            insert_key(10_000_000, 12_000_000, 9_000_000, 0, 100),
            13_000_000
        );
        assert_eq!(
            insert_key(10_000_000, 12_000_000, 9_000_000, 0, 1000),
            12_100_000
        );
    }

    #[test]
    fn insert_key_never_trails_floor() {
        assert_eq!(insert_key(1_000, 1_000, 2_000, 50_000_000, 100), 51_000_000);
        assert_eq!(
            insert_key(60_000_000, 60_000_000, 9_000_000, 50_000_000, 100),
            61_000_000
        );
    }
}
