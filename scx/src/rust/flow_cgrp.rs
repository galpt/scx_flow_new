// SPDX-License-Identifier: GPL-2.0
//! Hierarchy share and pool helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the hierarchy share walk plus the pool helpers shared by tests.
//! The BPF share lives in main.bpf.c with the pool in cgroup.bpf.c,
//! and this file mirrors the walk predicates with no map use.

/// Bound of hierarchy rows. Mirrors the BPF header.
pub const CGRP_MAX: usize = 2048;
/// Bound of ancestors visited by one share or pool walk.
pub const CGRP_DEPTH_MAX: usize = 8;
/// Default share on miss with neutral weight.
pub const CGRP_WEIGHT_DFL: u32 = 100;
/// Least period in microseconds at 1ms. Short periods fail closed here.
pub const BW_PERIOD_MIN_US: u64 = 1000;
/// Single timer interval in nanos at 10ms. Wakes parks with no scan.
/// Test only by design. The BPF header owns the live value, and Rust
/// never arms the timer, so this const only checks the header in tests.
#[cfg(test)]
pub const BW_TIMER_NS: u64 = 10_000_000;
/// Unlimited quota value mapped to zero for no cap use.
/// Test only by design. The BPF header owns the live value, and Rust
/// never reads kernel quotas, so this const only checks the norm in tests.
#[cfg(test)]
pub const RUNTIME_INF: u64 = u64::MAX;
/// Throttle bit in the hierarchy flags. Set means the gated pass
/// skips with a miss. Mirrors the BPF header.
#[cfg(test)]
pub const CGRP_THROTTLED: u32 = 1;
/// Parked chain ring slots at 64. Each slot holds one park chain of
/// 8 ancestor ids with the leaf first. Mirrors the BPF header.
#[cfg(test)]
pub const PARK_HINT_NR: u64 = 64;

/// Clamp one share into 1 to 10000.
/// Zero or oversize shares fail closed to the nearer bound.
#[cfg(test)]
pub fn clamp_share(w: u32) -> u32 {
    w.clamp(crate::flow_slice::WEIGHT_MIN, crate::flow_slice::WEIGHT_MAX)
}

/// Effective weight from task weight and hierarchy share.
/// Both inputs clamp to range, and the product scales by base 100.
/// A missing hierarchy entry uses base, so the task weight stands.
#[cfg(test)]
pub fn eff_weight(task_w: u32, hier_w: u32) -> u32 {
    let t = clamp_share(task_w) as u64;
    let h = clamp_share(hier_w) as u64;
    let eff = t * h / crate::flow_slice::WEIGHT_BASE as u64;
    eff.clamp(
        crate::flow_slice::WEIGHT_MIN as u64,
        crate::flow_slice::WEIGHT_MAX as u64,
    ) as u32
}

/// Hierarchy share over ancestors with miss default 100.
/// Compounds each weight by base 100, so a light parent lowers
/// the share. Caps at range with no trap. Takes the nearest 8
/// entries from the leaf, so a deeper chain truncates the far
/// root levels with the leaf order kept. Order matters only for
/// truncation, the product itself commutes.
#[cfg(test)]
pub fn hier_weight(weights: &[u32]) -> u32 {
    let mut hier = CGRP_WEIGHT_DFL as u64;
    for &w in weights.iter().take(CGRP_DEPTH_MAX) {
        let v = clamp_share(w) as u64;
        hier = hier * v / crate::flow_slice::WEIGHT_BASE as u64;
        hier = hier.clamp(
            crate::flow_slice::WEIGHT_MIN as u64,
            crate::flow_slice::WEIGHT_MAX as u64,
        );
    }
    hier as u32
}

/// Floored period in microseconds with a 1ms floor.
/// Short periods fail closed to the floor with no trap.
#[cfg(test)]
pub fn bw_period_floor(period_us: u64) -> u64 {
    period_us.max(BW_PERIOD_MIN_US)
}

/// Normalized quota with unlimited mapped to zero.
/// Zero means no cap, so zero means no check.
#[cfg(test)]
pub fn bw_quota_norm(quota_us: u64) -> u64 {
    if quota_us == RUNTIME_INF {
        return 0;
    }
    quota_us
}

/// True when one pool has no cap and never throttles.
/// Zero quota means unlimited with no pool use.
#[cfg(test)]
pub fn bw_unlimited(quota_us: u64) -> bool {
    quota_us == 0
}

/// Pool cap in nanos from quota plus burst with burst cap.
/// Unlimited pools hold zero with no cap use, limited pools cap
/// at quota plus burst converted to nanos.
#[cfg(test)]
pub fn bw_max_ns(quota_us: u64, burst_us: u64) -> u64 {
    if bw_unlimited(quota_us) {
        return 0;
    }
    quota_us.saturating_add(burst_us).saturating_mul(1000)
}

/// Cached share entry for one task.
/// Cgid holds the last hierarchy id, eweight holds the share,
/// cached marks a valid entry, and generation holds the low bits
/// of the global generation for validation. The low bits wrap past
/// 64k bumps, so a wrap needs 64k bumps with no move to falsely hit.
/// Moves clear the cache and share changes bump the generation, so
/// the window stays huge with no false hit in practice.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCache {
    /// Last hierarchy id.
    pub cgid: u64,
    /// Hierarchy share with base 100.
    pub eweight: u32,
    /// True when the entry may be used.
    pub cached: bool,
    /// Low bits of the global generation.
    pub generation: u16,
}

/// True when one cached share may be used at once.
/// Needs a set flag with matching id and generation, so a move
/// or a share change misses past with a fresh walk. Moves clear the
/// cache at once, so a stale id never validates past a move. The
/// generation compares only the low bits, so 64k bumps wrap with a
/// huge window and no false hit in practice.
#[cfg(test)]
pub fn cache_valid(cache: &TaskCache, cur_id: u64, cur_generation: u64) -> bool {
    cache.cached && cache.cgid == cur_id && cache.generation == cur_generation as u16
}

/// Cleared cache for one hierarchy move with deadline carry.
/// Drops the valid flag and records the new id, so the next enqueue
/// walks the new ancestors with no stale share.
#[cfg(test)]
pub fn cache_on_move(nid: u64) -> TaskCache {
    TaskCache {
        cgid: nid,
        eweight: CGRP_WEIGHT_DFL,
        cached: false,
        generation: 0,
    }
}

/// Atomic run claim for one leftover segment.
/// Models the BPF exchange and compare and swap pair: the first
/// claimant takes the nonzero start and clears to zero, later
/// claimants see zero with no double charge. Returns the claimed
/// start, or zero when another path already charged.
#[cfg(test)]
pub fn run_claim(run_at: &mut u64) -> u64 {
    let start = *run_at;
    if start == 0 {
        return 0;
    }
    *run_at = 0;
    start
}

/// True when one leaf flag parks the task in the gated pass.
/// Needs the throttle bit set, so full walks plus consume hold parks
/// and full passes plus the timer chain refill release them.
#[cfg(test)]
pub fn flag_throttled(flags: u32) -> bool {
    flags & CGRP_THROTTLED != 0
}

/// Set the throttle bit on one flags word.
/// Models the BPF single compare and swap try with no tear.
#[cfg(test)]
pub fn flag_set(flags: u32) -> u32 {
    flags | CGRP_THROTTLED
}

/// Clear the throttle bit on one flags word.
/// Models the BPF single compare and swap try with no tear.
#[cfg(test)]
pub fn flag_clear(flags: u32) -> u32 {
    flags & !CGRP_THROTTLED
}

/// Pool state for one hierarchy entry.
/// Quota holds zero for unlimited, pool holds the rest in nanos,
/// and updated holds the last refill time in nanos.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolState {
    /// Quota in microseconds, zero for unlimited.
    pub quota_us: u64,
    /// Burst in microseconds for the cap.
    pub burst_us: u64,
    /// Period in microseconds floored at 1ms.
    pub period_us: u64,
    /// Rest in nanos, zero when drained.
    pub pool_ns: u64,
    /// Last refill time in nanos.
    pub updated_at: u64,
}

/// Lazy refill of one pool with burst cap.
/// Unlimited pools stay zero with no time use. Elapsed time
/// refills by quota over period with saturating math, capped at
/// quota plus burst. The stamp advances only when the refill adds,
/// so tiny elapsed keeps its fraction for the next pass.
#[cfg(test)]
pub fn pool_refill(pool: &mut PoolState, now: u64) {
    if bw_unlimited(pool.quota_us) {
        return;
    }
    if now < pool.updated_at {
        return;
    }
    let elapsed = now - pool.updated_at;
    if elapsed == 0 {
        return;
    }
    if pool.period_us == 0 {
        return;
    }
    let add = elapsed.saturating_mul(pool.quota_us) / pool.period_us;
    if add == 0 {
        return;
    }
    pool.updated_at = now;
    let max = bw_max_ns(pool.quota_us, pool.burst_us);
    if max == 0 {
        return;
    }
    if pool.pool_ns >= max {
        return;
    }
    pool.pool_ns = (pool.pool_ns.saturating_add(add)).min(max);
}

/// True when one pool walk is throttled with lazy refill.
/// Any drained pool binds, so the tightest ancestor parks.
/// Unlimited entries pass with no pool use.
#[cfg(test)]
pub fn pools_throttled(pools: &mut [PoolState], now: u64) -> bool {
    for p in pools.iter_mut().take(CGRP_DEPTH_MAX) {
        if bw_unlimited(p.quota_us) {
            continue;
        }
        pool_refill(p, now);
        if p.pool_ns == 0 {
            return true;
        }
    }
    false
}

/// Charge one runtime delta to pools with floor at zero.
/// Limited pools drain saturating to zero with no wrap.
#[cfg(test)]
pub fn pools_consume(pools: &mut [PoolState], delta: u64) {
    if delta == 0 {
        return;
    }
    for p in pools.iter_mut().take(CGRP_DEPTH_MAX) {
        if bw_unlimited(p.quota_us) {
            continue;
        }
        p.pool_ns = p.pool_ns.saturating_sub(delta);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consts_match_header() {
        assert_eq!(CGRP_MAX, 2048);
        assert_eq!(CGRP_DEPTH_MAX, 8);
        assert_eq!(CGRP_WEIGHT_DFL, 100);
        assert_eq!(BW_PERIOD_MIN_US, 1000);
        assert_eq!(BW_TIMER_NS, 10_000_000);
        assert_eq!(RUNTIME_INF, u64::MAX);
        assert_eq!(
            CGRP_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_CGRP_MAX as u64
        );
        assert_eq!(
            CGRP_DEPTH_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_CGRP_DEPTH_MAX as u64
        );
        assert_eq!(
            BW_TIMER_NS,
            crate::bpf_intf::flow_consts_FLOW_BW_TIMER_NS as u64
        );
        assert_eq!(
            BW_PERIOD_MIN_US,
            crate::bpf_intf::flow_consts_FLOW_BW_PERIOD_MIN_US as u64
        );
    }

    #[test]
    fn eff_folds_task_with_hierarchy() {
        assert_eq!(eff_weight(100, 100), 100);
        assert_eq!(eff_weight(200, 100), 200);
        assert_eq!(eff_weight(100, 200), 200);
        assert_eq!(eff_weight(100, 50), 50);
        assert_eq!(eff_weight(0, 0), 1);
        assert_eq!(eff_weight(99_999, 99_999), 10_000);
    }

    #[test]
    fn hier_compounds_with_miss_default() {
        assert_eq!(hier_weight(&[]), 100);
        assert_eq!(hier_weight(&[100]), 100);
        assert_eq!(hier_weight(&[200]), 200);
        assert_eq!(hier_weight(&[100, 200]), 200);
        assert_eq!(hier_weight(&[50, 50]), 25);
        let deep = vec![200u32; 16];
        assert_eq!(hier_weight(&deep), hier_weight(&[200u32; 8]));
    }

    #[test]
    fn hier_keeps_nearest_eight_in_order() {
        let leaf_first = vec![50u32, 100, 100, 100, 100, 100, 100, 100, 100];
        let root_light = vec![100u32, 100, 100, 100, 100, 100, 100, 100, 50];
        assert_eq!(hier_weight(&leaf_first), 50);
        assert_eq!(hier_weight(&root_light), 100);
        assert_ne!(hier_weight(&leaf_first), hier_weight(&root_light));
        let nine = vec![200u32; 9];
        assert_eq!(hier_weight(&nine), hier_weight(&[200u32; 8]));
    }

    #[test]
    fn bw_max_saturates_huge_inputs() {
        assert_eq!(bw_max_ns(u64::MAX - 1, 10), u64::MAX);
        assert_eq!(bw_max_ns(u64::MAX / 1000 + 10, 0), u64::MAX);
        assert_eq!(bw_max_ns(1000, 500), 1_500_000);
    }

    #[test]
    fn refill_keeps_fraction_for_next_pass() {
        let mut p = PoolState {
            quota_us: 1000,
            burst_us: 0,
            period_us: 1_000_000,
            pool_ns: 0,
            updated_at: 0,
        };
        pool_refill(&mut p, 100);
        assert_eq!(p.pool_ns, 0);
        assert_eq!(p.updated_at, 0);
        pool_refill(&mut p, 1000);
        assert_eq!(p.pool_ns, 1);
        assert_eq!(p.updated_at, 1000);
    }

    #[test]
    fn gen_wrap_needs_huge_window_without_move() {
        let c = TaskCache {
            cgid: 7,
            eweight: 100,
            cached: true,
            generation: 0,
        };
        assert!(cache_valid(&c, 7, 65536));
        assert!(!cache_valid(&c, 7, 65537));
        assert!(!cache_valid(&c, 8, 65536));
    }

    #[test]
    fn bw_helpers_hold_floor_and_inf() {
        assert_eq!(bw_period_floor(500), 1000);
        assert_eq!(bw_period_floor(5000), 5000);
        assert_eq!(bw_quota_norm(RUNTIME_INF), 0);
        assert_eq!(bw_quota_norm(1000), 1000);
        assert!(bw_unlimited(0));
        assert!(!bw_unlimited(1000));
        assert_eq!(bw_max_ns(0, 0), 0);
        assert_eq!(bw_max_ns(1000, 500), 1_500_000);
    }

    #[test]
    fn cache_needs_id_and_gen() {
        let c = TaskCache {
            cgid: 7,
            eweight: 100,
            cached: true,
            generation: 3,
        };
        assert!(cache_valid(&c, 7, 3));
        assert!(!cache_valid(&c, 8, 3));
        assert!(!cache_valid(&c, 7, 4));
        let cold = TaskCache {
            cgid: 7,
            eweight: 100,
            cached: false,
            generation: 3,
        };
        assert!(!cache_valid(&cold, 7, 3));
    }

    #[test]
    fn pools_bind_tightest_with_refill() {
        let mut pools = vec![
            PoolState {
                quota_us: 1000,
                burst_us: 0,
                period_us: 1000,
                pool_ns: 1_000_000,
                updated_at: 0,
            },
            PoolState {
                quota_us: 0,
                burst_us: 0,
                period_us: 1000,
                pool_ns: 0,
                updated_at: 0,
            },
        ];
        assert!(!pools_throttled(&mut pools, 0));
        pools[0].pool_ns = 0;
        pools[0].updated_at = 0;
        assert!(pools_throttled(&mut pools, 0));
        pools[0].pool_ns = 0;
        pools[0].updated_at = 0;
        assert!(!pools_throttled(&mut pools, 500));
        pools_consume(&mut pools, 500_000);
        assert_eq!(pools[0].pool_ns, 0);
    }

    #[test]
    fn refill_caps_at_burst() {
        let mut p = PoolState {
            quota_us: 1000,
            burst_us: 500,
            period_us: 1000,
            pool_ns: 0,
            updated_at: 0,
        };
        pool_refill(&mut p, 10_000_000);
        assert_eq!(p.pool_ns, 1_500_000);
        pool_refill(&mut p, 20_000_000);
        assert_eq!(p.pool_ns, 1_500_000);
        let mut u = PoolState {
            quota_us: 0,
            burst_us: 0,
            period_us: 1000,
            pool_ns: 0,
            updated_at: 0,
        };
        pool_refill(&mut u, 10_000_000);
        assert_eq!(u.pool_ns, 0);
    }

    #[test]
    fn run_claim_charges_once() {
        let mut run = 5_000u64;
        assert_eq!(run_claim(&mut run), 5_000);
        assert_eq!(run, 0);
        assert_eq!(run_claim(&mut run), 0);
        let mut zero = 0u64;
        assert_eq!(run_claim(&mut zero), 0);
    }

    #[test]
    fn move_clears_cache_for_fresh_walk() {
        let c = cache_on_move(9);
        assert!(!c.cached);
        assert_eq!(c.cgid, 9);
        assert!(!cache_valid(&c, 9, 0));
        let live = TaskCache {
            cgid: 7,
            eweight: 100,
            cached: true,
            generation: 3,
        };
        assert!(cache_valid(&live, 7, 3));
        let moved = cache_on_move(8);
        assert!(!cache_valid(&moved, 7, 3));
    }

    #[test]
    fn throttle_flag_parks_gated_pass() {
        assert_eq!(CGRP_THROTTLED, 1);
        assert_eq!(
            CGRP_THROTTLED as u64,
            crate::bpf_intf::flow_consts_FLOW_CGRP_THROTTLED as u64
        );
        assert_eq!(
            PARK_HINT_NR,
            crate::bpf_intf::flow_consts_FLOW_PARK_HINT_NR as u64
        );
        assert_eq!(PARK_HINT_NR, 64);
        assert!(flag_throttled(flag_set(0)));
        assert!(!flag_throttled(flag_clear(flag_set(0))));
        assert!(!flag_throttled(0));
        assert!(!flag_throttled(flag_clear(0)));
        assert_eq!(flag_set(flag_set(0)), CGRP_THROTTLED);
    }
}
