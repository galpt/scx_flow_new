/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * EDF unit tests for the flow scheduler.
 * The tests mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */
use crate::flow_edf::*;
use crate::flow_mean::*;
use crate::flow_select::*;
use std::collections::VecDeque;

#[test]
fn est_clamp_caps_at_one_second() {
    assert_eq!(clamp_est(0), EST_MIN_NS);
    assert_eq!(clamp_est(1), EST_MIN_NS);
    assert_eq!(clamp_est(EST_MAX_NS), EST_MAX_NS);
    assert_eq!(clamp_est(EST_MAX_NS + 1), EST_MAX_NS);
    assert_eq!(clamp_est(u64::MAX), EST_MAX_NS);
}

#[test]
fn est_is_last_burst_with_no_smoothing() {
    let first = clamp_est(1_000_000);
    let second = clamp_est(8_000_000);
    assert_eq!(second, 8_000_000);
    assert_ne!(first, second);
}

#[test]
fn tq_seed_floor_ceiling_match_spec() {
    assert_eq!(TQ_SEED_NS, 8_000_000);
    assert_eq!(TQ_MIN_NS, 500_000);
    assert_eq!(TQ_MAX_NS, 32_000_000);
    assert_eq!(mean_tq(0, 0), TQ_SEED_NS);
    assert_eq!(clamp_tq(0), TQ_MIN_NS);
    assert_eq!(clamp_tq(100), TQ_MIN_NS);
    assert_eq!(clamp_tq(500_000), 500_000);
    assert_eq!(clamp_tq(8_000_000), 8_000_000);
    assert_eq!(clamp_tq(32_000_000), 32_000_000);
    assert_eq!(clamp_tq(40_000_000), 32_000_000);
    assert_eq!(clamp_tq(u64::MAX), 32_000_000);
}

#[test]
fn mean_uses_sum_over_nr() {
    assert_eq!(mean_tq(8_000_000, 1), 8_000_000);
    assert_eq!(mean_tq(16_000_000, 2), 8_000_000);
    assert_eq!(mean_tq(1_000_000, 2), 500_000);
    assert_eq!(mean_tq(100, 2), 500_000);
    assert_eq!(mean_tq(100_000_000, 2), 32_000_000);
    assert_eq!(mean_tq(0, 1), 500_000);
}

#[test]
fn mean_property_stays_in_range() {
    for sum in [0, 1, 500_000, 8_000_000, 64_000_000] {
        for nr in [0, 1, 2, 8] {
            let tq = mean_tq(sum, nr);
            if nr == 0 {
                assert_eq!(tq, TQ_SEED_NS);
            } else {
                assert!(tq >= TQ_MIN_NS);
                assert!(tq <= TQ_MAX_NS);
            }
        }
    }
}

#[test]
fn fresh_join_leaves_mean_unchanged() {
    let mut m = CpuMean::empty();
    assert_eq!(m.tq(), TQ_SEED_NS);
    let e0 = m.join_fresh();
    assert_eq!(e0, TQ_SEED_NS);
    assert_eq!(m.tq(), TQ_SEED_NS);
    let e1 = m.join_fresh();
    assert_eq!(e1, TQ_SEED_NS);
    assert_eq!(m.tq(), TQ_SEED_NS);
    m.leave(e0);
    assert_eq!(m.tq(), TQ_SEED_NS);
    m.leave(e1);
    assert_eq!(m.tq(), TQ_SEED_NS);
    assert_eq!(m.nr, 0);
}

#[test]
fn mean_tracks_join_leave_replace() {
    let mut m = CpuMean::empty();
    let a = m.join(2_000_000);
    assert_eq!(a, 2_000_000);
    assert_eq!(m.tq(), 2_000_000);
    m.join(4_000_000);
    assert_eq!(m.tq(), 3_000_000);
    m.replace(2_000_000, 8_000_000);
    assert_eq!(m.tq(), 6_000_000);
    m.leave(8_000_000);
    assert_eq!(m.tq(), 4_000_000);
    m.leave(4_000_000);
    assert_eq!(m.tq(), TQ_SEED_NS);
}

#[test]
fn mean_saturates_at_bounds() {
    let mut m = CpuMean::empty();
    m.sum = u64::MAX;
    m.nr = 1;
    assert_eq!(m.tq(), TQ_MAX_NS);
    m.sum = 0;
    m.nr = 1;
    assert_eq!(m.tq(), TQ_MIN_NS);
    let mut n = CpuMean::empty();
    n.sum = u64::MAX - 1;
    n.nr = 0;
    n.join(1_000_000);
    assert_eq!(n.sum, u64::MAX);
    assert_eq!(n.nr, 1);
    n.leave(1_000_000);
    assert_eq!(n.sum, u64::MAX - 1_000_000);
    assert_eq!(n.nr, 0);
    let mut q = CpuMean::empty();
    q.sum = 100;
    q.nr = 1;
    q.leave(1_000_000);
    assert_eq!(q.sum, 0);
    assert_eq!(q.nr, 0);
}

#[test]
fn acct_cap_bounds_match_spec() {
    /* Small values pass through with no change. */
    assert_eq!(clamp_acct(1), 1);
    assert_eq!(clamp_acct(500_000), 500_000);
    assert_eq!(clamp_acct(8_000_000), 8_000_000);
    assert_eq!(clamp_acct(32_000_000), 32_000_000);
    /* Large values cap at the accounting bound. */
    assert_eq!(clamp_acct(32_000_001), ACCT_MAX_NS);
    assert_eq!(clamp_acct(100_000_000), ACCT_MAX_NS);
    assert_eq!(clamp_acct(1_000_000_000), ACCT_MAX_NS);
    assert_eq!(clamp_acct(u64::MAX), ACCT_MAX_NS);
    /* The deadline keeps the full range. */
    assert_eq!(clamp_est(1_000_000_000), EST_MAX_NS);
    assert_eq!(ACCT_MAX_NS, 32_000_000);
}

#[test]
fn acct_misfire_small_values_stay_exact() {
    /* Values below the cap never misfire. */
    for v in [1, 1000, 500_000, 8_000_000, 32_000_000] {
        assert_eq!(clamp_acct(v), clamp_est(v));
    }
    /* A fresh mean with small joins stays exact. */
    let mut m = CpuMean::empty();
    let e = m.join(2_000_000);
    assert_eq!(e, 2_000_000);
    assert_eq!(m.sum, 2_000_000);
    m.leave(2_000_000);
    assert_eq!(m.sum, 0);
    assert_eq!(m.nr, 0);
}

#[test]
fn acct_outlier_keeps_mean_bounded() {
    /* One outlier adds only the cap to the sum. */
    let mut m = CpuMean::empty();
    let e = m.join(1_000_000_000);
    assert_eq!(e, 1_000_000_000);
    assert_eq!(m.sum, ACCT_MAX_NS);
    assert_eq!(m.tq(), ACCT_MAX_NS);
    /* Deadline still sees the full value. */
    let mut q = Vec::new();
    let dl = deadline(0, e);
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: dl,
            seq: 0,
            id: 1,
        },
    );
    assert_eq!(q[0].deadline, 1_000_000_000);
    /* Leaving the outlier restores the seed. */
    m.leave(1_000_000_000);
    assert_eq!(m.sum, 0);
    assert_eq!(m.tq(), TQ_SEED_NS);
}

#[test]
fn acct_property_holds_across_trials() {
    /* Capped sums keep means in range with outliers. */
    for trial in 0..16u64 {
        let mut m = CpuMean::empty();
        let big = 100_000_000 + trial * 1_000_000;
        let small = 1_000_000 + trial * 1000;
        m.join(big);
        assert_eq!(m.sum, ACCT_MAX_NS);
        m.join(small);
        let want = (ACCT_MAX_NS + clamp_est(small)) / 2;
        let want = want.clamp(TQ_MIN_NS, TQ_MAX_NS);
        assert_eq!(m.tq(), want);
        m.replace(big, small);
        assert_eq!(m.sum, clamp_est(small) * 2);
        m.leave(small);
        m.leave(small);
        assert_eq!(m.sum, 0);
        assert_eq!(m.tq(), TQ_SEED_NS);
    }
}

#[test]
fn edf_weight_matches_fixed() {
    /* Fixed weight keeps the value unchanged. */
    assert_eq!(WEIGHT, 1024);
    assert_eq!(scale_by_weight(1_000_000, 1024), 1_000_000);
    assert_eq!(scale_by_weight(8_000_000, 1024), 8_000_000);
    /* Zero weight falls back to the estimate. */
    assert_eq!(scale_by_weight(1_000_000, 0), 1_000_000);
    /* Future weights scale with no overflow. */
    assert_eq!(scale_by_weight(1_000_000, 512), 2_000_000);
    assert_eq!(scale_by_weight(2_000_000, 2048), 1_000_000);
}

#[test]
fn edf_clamp_bounds_match_slice() {
    /* Lagging values move forward to the floor. */
    assert_eq!(clamp_vruntime(0, 100_000_000, 8_000_000), 92_000_000);
    assert!(was_clamped(0, 100_000_000, 8_000_000));
    /* Values at the floor stay with no count. */
    assert_eq!(
        clamp_vruntime(92_000_000, 100_000_000, 8_000_000),
        92_000_000
    );
    assert!(!was_clamped(92_000_000, 100_000_000, 8_000_000));
    /* Fresh values near the frontier stay. */
    assert_eq!(
        clamp_vruntime(99_000_000, 100_000_000, 8_000_000),
        99_000_000
    );
    assert!(!was_clamped(99_000_000, 100_000_000, 8_000_000));
    /* Ahead values stay with no clamp. */
    assert_eq!(
        clamp_vruntime(110_000_000, 100_000_000, 8_000_000),
        110_000_000
    );
    assert!(!was_clamped(110_000_000, 100_000_000, 8_000_000));
}

#[test]
fn edf_deadline_wraps_safe() {
    /* Deadline adds with wrap and keeps order. */
    assert_eq!(deadline(100, 50), 150);
    assert_eq!(deadline(u64::MAX - 10, 20), 9);
    assert!(time_before(u64::MAX - 10, 9));
    assert!(!time_before(9, u64::MAX - 10));
    /* Equal times are never before. */
    assert!(!time_before(100, 100));
    assert!(!time_before(u64::MAX, u64::MAX));
    /* Vruntimes advance with wrap. */
    assert_eq!(vruntime_add(100, 50), 150);
    assert_eq!(vruntime_add(u64::MAX, 1), 0);
}

#[test]
fn s1_bounded_lag_holds_across_trials() {
    /* S1 bounded lag keeps sleepers near frontier. */
    for trial in 0..32u64 {
        let slice = TQ_SEED_NS;
        let frontier = 100_000_000 + trial * 1_000_000;
        let lags = [0, 1, slice - 1, slice, slice + 1, 50_000_000];
        for lag in lags {
            let v = frontier.wrapping_sub(lag);
            let clamped = clamp_vruntime(v, frontier, slice);
            if time_before(v, frontier) {
                let held = frontier.wrapping_sub(clamped);
                assert!(held <= slice);
            } else {
                assert_eq!(clamped, v);
            }
            let (c2, dl, flag) = edf_insert(v, frontier, slice, 1_000_000, 1024);
            assert_eq!(c2, clamped);
            assert_eq!(flag, was_clamped(v, frontier, slice));
            assert_eq!(dl, deadline(c2, scale_by_weight(1_000_000, 1024)));
        }
    }
}

#[test]
fn s2_sleeper_cap_one_slice_holds() {
    /* S2 sleeper cap bounds advantage to one slice. */
    for trial in 0..16u64 {
        let slice = TQ_SEED_NS;
        let frontier = 200_000_000 + trial * 1_000_000;
        let est = 1_000_000 + trial * 100_000;
        let (clamped, dl, flag) = edf_insert(0, frontier, slice, est, 1024);
        assert_eq!(clamped, frontier.wrapping_sub(slice));
        assert!(flag);
        assert_eq!(dl, clamped.wrapping_add(clamp_est(est)));
        if clamp_est(est) <= slice {
            assert!(!time_before(frontier, dl));
            let early = frontier.wrapping_sub(dl);
            assert!(early <= slice);
        }
        /* A fresh value near frontier earns no cap. */
        let near = frontier.wrapping_sub(1_000_000);
        let (_, _, flag2) = edf_insert(near, frontier, slice, est, 1024);
        assert!(!flag2);
    }
}

#[test]
fn s3_frontier_monotonic_with_wrap_holds() {
    /* S3 frontier never moves backward while queued. */
    for trial in 0..16u64 {
        let old = 1_000_000 + trial * 1_000_000;
        let next = old.wrapping_add(500_000);
        assert_eq!(frontier_max(old, next), next);
        assert_eq!(frontier_max(next, old), next);
        assert_eq!(frontier_step(old, next, true, 0), next);
        assert_eq!(frontier_step(old, next, true, 2), next);
        assert_eq!(frontier_step(old, next, false, 1), next);
        /* Idle blocks reset to the waking value. */
        assert_eq!(frontier_step(old, next, false, 0), next);
        assert_eq!(frontier_idle(next), next);
    }
    /* Wrap keeps order across the u64 top. */
    let old = u64::MAX - 100;
    let next = 50u64;
    assert!(time_before(old, next));
    assert_eq!(frontier_max(old, next), next);
    assert_eq!(frontier_max(next, old), next);
    assert_eq!(frontier_step(old, next, true, 1), next);
    assert_eq!(frontier_step(old, next, false, 0), next);
    /* Lagging value near the top clamps forward. */
    let lag = u64::MAX - 20_000_000;
    let top = u64::MAX - 1_000_000;
    assert_eq!(
        clamp_vruntime(lag, top, 8_000_000),
        top.wrapping_sub(8_000_000)
    );
    /* Fresh zero near the top stays with no clamp. */
    assert_eq!(clamp_vruntime(0, top, 8_000_000), 0);
    /* Small frontier with wrap floor keeps zero. */
    assert_eq!(clamp_vruntime(0, 5_000_000, 8_000_000), 0);
}

#[test]
fn edf_insert_counts_clamp_and_order() {
    /* Clamped inserts count once with ordered keys. */
    let slice = TQ_SEED_NS;
    let frontier = 100_000_000;
    let (c1, dl1, f1) = edf_insert(0, frontier, slice, 2_000_000, 1024);
    assert!(f1);
    assert_eq!(c1, frontier.wrapping_sub(slice));
    assert_eq!(dl1, c1.wrapping_add(2_000_000));
    /* Plain inserts count zero with later keys. */
    let (c2, dl2, f2) = edf_insert(frontier, frontier, slice, 1_000_000, 1024);
    assert!(!f2);
    assert_eq!(c2, frontier);
    assert!(time_before(dl2, dl1) || dl2 == dl1 || time_before(dl1, dl2));
    let mut q = Vec::new();
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: dl1,
            seq: 0,
            id: 1,
        },
    );
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: dl2,
            seq: 1,
            id: 2,
        },
    );
    assert_eq!(q.len(), 2);
    assert!(!q[1].before(&q[0]));
}

#[test]
fn edf_frontier_step_idle_bounded() {
    /* Idle resets bound to waking time with no zero. */
    let waking = 50_000_000;
    assert_eq!(frontier_step(100_000_000, waking, false, 0), waking);
    assert_ne!(frontier_step(100_000_000, waking, false, 0), 0);
    /* Queued work never moves backward. */
    assert_eq!(frontier_step(100_000_000, waking, false, 1), 100_000_000);
    assert_eq!(frontier_step(100_000_000, waking, true, 0), 100_000_000);
    /* Forward steps always win while busy. */
    assert_eq!(frontier_step(10, 20, true, 5), 20);
    assert_eq!(frontier_step(10, 20, false, 3), 20);
}

#[test]
fn edf_insert_and_step_matches_composition() {
    /* Combined helper matches separate calls. */
    for trial in 0..16u64 {
        let frontier = 100_000_000 + trial * 1_000_000;
        let slice = TQ_SEED_NS;
        let est = 1_000_000 + trial * 100_000;
        let v = frontier.wrapping_sub(trial * 500_000);
        for (runnable, queued) in [(true, 0), (false, 0), (false, 1), (true, 2)] {
            let (c1, dl1, flag1) = edf_insert(v, frontier, slice, est, 1024);
            let scaled = scale_by_weight(clamp_est(est), 1024);
            let next_v = vruntime_add(c1, scaled);
            let want_frontier = frontier_step(frontier, next_v, runnable, queued);
            let (c2, dl2, got_frontier, flag2) =
                edf_insert_and_step(v, frontier, slice, est, 1024, runnable, queued);
            assert_eq!(c2, c1);
            assert_eq!(dl2, dl1);
            assert_eq!(flag2, flag1);
            assert_eq!(got_frontier, want_frontier);
            /* Deadline is clamped time plus scaled estimate. */
            assert_eq!(dl2, deadline(c2, scaled));
        }
    }
    /* Idle path resets to waking time with progress. */
    let (c, dl, next, flag) =
        edf_insert_and_step(0, 100_000_000, TQ_SEED_NS, 1_000_000, 1024, false, 0);
    assert!(flag);
    assert_eq!(c, 100_000_000 - TQ_SEED_NS);
    assert_eq!(dl, c.wrapping_add(1_000_000));
    assert_eq!(next, c.wrapping_add(1_000_000));
}

#[test]
fn sticky_prior_bounds_match_idle_prior() {
    /* Idle priors reuse at once with a count. */
    assert_eq!(STEAL_MIN_DEPTH, 2);
    let allowed = [true, true, true, true];
    let idle = [false, true, false, false];
    assert!(sticky_prior_ok(1, &allowed, &idle));
    assert!(!sticky_prior_ok(0, &allowed, &idle));
    assert!(!sticky_prior_ok(2, &allowed, &idle));
    /* Busy priors never preempt. */
    let busy = [false, false, false, false];
    assert!(!sticky_prior_ok(1, &allowed, &busy));
    /* Foreign priors never reuse. */
    let narrow = [false, false, true, false];
    assert!(!sticky_prior_ok(1, &narrow, &idle));
    assert!(sticky_prior_ok(2, &narrow, &[false, false, true]));
    assert!(!sticky_prior_ok(-1, &allowed, &idle));
}

#[test]
fn sticky_misfire_cases_stay_plain() {
    /* Empty masks never reuse. */
    let empty = [false, false];
    let idle = [true, true];
    assert!(!sticky_prior_ok(0, &empty, &idle));
    assert!(!sticky_prior_ok(-1, &empty, &idle));
    /* Missing idle entries never reuse. */
    let allowed = [true, true];
    let none: [bool; 0] = [];
    assert!(!sticky_prior_ok(0, &allowed, &none));
    /* Thin donors never lose work. */
    assert!(!donor_ok(0));
    assert!(!donor_ok(1));
    assert!(donor_ok(2));
    assert!(donor_ok(8));
}

#[test]
fn sticky_donor_gate_keeps_last_task() {
    /* Donors with one task keep it for the owner. */
    assert!(!donor_ok(0));
    assert!(!donor_ok(1));
    /* Donors with two or more may share one. */
    for depth in [2, 3, 8, 32] {
        assert!(donor_ok(depth));
    }
    /* Sticky select prefers idle prior first. */
    let allowed = [true, true, true, true];
    let idle = [false, true, false, false];
    let llc = [0, 0, 1, 1];
    let full: [bool; 0] = [];
    let (got, reused) = select_sticky_model(1, 0, &allowed, &idle, &llc, &full, 2, 0, 0, true);
    assert_eq!(got, Some(1));
    assert!(reused);
    let idle2 = [false, false, false, true];
    let (got2, reused2) = select_sticky_model(1, 0, &allowed, &idle2, &llc, &full, 2, 0, 0, true);
    assert_eq!(got2, Some(3));
    assert!(!reused2);
}

#[test]
fn sticky_property_holds_across_trials() {
    /* Only idle allowed priors reuse. */
    for trial in 0..16u64 {
        let idx = (trial % 4) as usize;
        let mut allowed = [true, true, true, true];
        let mut idle = [false, false, false, false];
        idle[idx] = trial % 2 == 0;
        if trial % 5 == 0 {
            allowed[idx] = false;
        }
        let prev = idx as i32;
        let want = allowed[idx] && idle[idx];
        assert_eq!(sticky_prior_ok(prev, &allowed, &idle), want);
        let (got, reused) =
            select_sticky_model(prev, 0, &allowed, &idle, &[0, 0, 1, 1], &[], 2, 0, 0, true);
        assert_eq!(reused, want);
        if want {
            assert_eq!(got, Some(idx as u32));
        }
        /* Donor depths below two never steal. */
        let depth = trial % 4;
        assert_eq!(donor_ok(depth), depth >= 2);
    }
}

#[test]
fn cuts_kick_bounds_match_empty_only() {
    /* First arrivals wake idle targets. */
    assert!(may_kick(0));
    assert!(may_kick(1));
    /* Queued work stays quiet with no kick. */
    assert!(!may_kick(2));
    assert!(!may_kick(8));
    assert!(!may_kick(u64::MAX));
}

#[test]
fn cuts_replace_bounds_match_equal_skip() {
    /* Equal bursts skip the mean write. */
    assert!(!should_replace(2_000_000, 2_000_000));
    assert!(!should_replace(8_000_000, 8_000_000));
    assert!(!should_replace(0, 1));
    /* Distinct bursts run the mean write. */
    assert!(should_replace(2_000_000, 8_000_000));
    assert!(should_replace(8_000_000, 2_000_000));
    /* Clamp keeps equal skip honest. */
    let mut m = CpuMean::empty();
    m.join(2_000_000);
    let sum = m.sum;
    m.replace(2_000_000, 2_000_000);
    assert_eq!(m.sum, sum);
    m.replace(2_000_000, 4_000_000);
    assert_ne!(m.sum, sum);
}

#[test]
fn cuts_misfire_cases_stay_quiet() {
    /* Busy queues never kick. */
    assert!(!may_kick(2));
    assert!(!may_kick(32));
    /* Equal estimates never replace. */
    let mut m = CpuMean::empty();
    m.join(4_000_000);
    let sum = m.sum;
    let nr = m.nr;
    m.replace(4_000_000, 4_000_000);
    assert_eq!(m.sum, sum);
    assert_eq!(m.nr, nr);
    /* Distinct estimates always replace. */
    m.replace(4_000_000, 5_000_000);
    assert_ne!(m.sum, sum);
}

#[test]
fn cuts_property_holds_across_trials() {
    /* Only empty queues kick, only distinct replace. */
    for trial in 0..16u64 {
        let len = trial % 4;
        assert_eq!(may_kick(len), len <= 1);
        let a = 1_000_000 + trial * 1000;
        let b = 1_000_000 + (trial + 1) * 1000;
        assert!(!should_replace(a, a));
        assert!(should_replace(a, b));
        let mut m = CpuMean::empty();
        m.join(a);
        let sum = m.sum;
        m.replace(a, a);
        assert_eq!(m.sum, sum);
        m.replace(a, b);
        assert_ne!(m.sum, sum);
    }
}

#[test]
fn dsq_ids_match_spec() {
    assert_eq!(DSQ_BASE, 0x4000);
    assert_eq!(DSQ_PARK, 0x5000);
    assert_ne!(DSQ_BASE, DSQ_PARK);
    assert_eq!(dsq_for_cpu(0, 8), Some(0x4000));
    assert_eq!(dsq_for_cpu(7, 8), Some(0x4007));
    assert_eq!(dsq_for_cpu(8, 8), None);
    assert_eq!(dsq_for_cpu(1023, 1024), Some(0x43ff));
    assert_eq!(dsq_for_cpu(1024, 2048), None);
}

#[test]
fn ordered_insert_sorts_by_deadline() {
    let mut q = Vec::new();
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: 8_000_000,
            seq: 0,
            id: 1,
        },
    );
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: 1_000_000,
            seq: 1,
            id: 2,
        },
    );
    ordered_insert(
        &mut q,
        OrderedEntry {
            deadline: 4_000_000,
            seq: 2,
            id: 3,
        },
    );
    assert_eq!(q[0].id, 2);
    assert_eq!(q[1].id, 3);
    assert_eq!(q[2].id, 1);
}

#[test]
fn ordered_insert_keeps_arrival_order_on_ties() {
    let mut q = Vec::new();
    for i in 0..4 {
        ordered_insert(
            &mut q,
            OrderedEntry {
                deadline: 2_000_000,
                seq: i,
                id: i,
            },
        );
    }
    assert_eq!(q[0].id, 0);
    assert_eq!(q[1].id, 1);
    assert_eq!(q[2].id, 2);
    assert_eq!(q[3].id, 3);
}

#[test]
fn ordered_property_holds_across_trials() {
    for trial in 0..16u64 {
        let mut q = Vec::new();
        for i in 0..8u64 {
            let deadline = (trial * 7 + i * 13) % 5 + 1;
            ordered_insert(
                &mut q,
                OrderedEntry {
                    deadline,
                    seq: i,
                    id: i,
                },
            );
        }
        for w in q.windows(2) {
            assert!(!w[1].before(&w[0]));
        }
    }
}

#[test]
fn cpuperf_uses_est_against_tq_only() {
    assert_eq!(cpuperf_for_est(500_000, 8_000_000), CPUPERF_SHORT);
    assert_eq!(cpuperf_for_est(8_000_000, 8_000_000), CPUPERF_SHORT);
    assert_eq!(cpuperf_for_est(8_000_001, 8_000_000), CPUPERF_LONG);
    assert_eq!(cpuperf_for_est(32_000_000, 500_000), CPUPERF_LONG);
    assert_eq!(cpuperf_for_est(1, 500_000), CPUPERF_SHORT);
}

#[test]
fn idle_restore_needs_blocked_and_empty() {
    assert!(should_restore_hint(false, 0, 0));
    assert!(!should_restore_hint(true, 0, 0));
    assert!(!should_restore_hint(false, 1, 0));
    assert!(!should_restore_hint(false, 0, 1));
    assert!(!should_restore_hint(true, 1, 1));
}

#[test]
fn target_prefers_selected_when_allowed() {
    assert_eq!(pick_target_cpu(2, &[true, true, true]), Some(2));
    assert_eq!(pick_target_cpu(0, &[true, false]), Some(0));
    assert_eq!(pick_target_cpu(1, &[false, true]), Some(1));
}

#[test]
fn target_falls_back_to_first_when_invalid() {
    assert_eq!(pick_target_cpu(-1, &[false, true, true]), Some(1));
    assert_eq!(pick_target_cpu(5, &[true, false]), Some(0));
    assert_eq!(pick_target_cpu(1, &[true, false]), Some(0));
    assert_eq!(pick_target_cpu(-1, &[]), None);
}

#[test]
fn target_none_when_no_allowed() {
    assert_eq!(pick_target_cpu(0, &[false, false]), None);
    assert_eq!(pick_target_cpu(-1, &[false]), None);
}

#[test]
fn target_pinned_resolves_to_single() {
    assert_eq!(pick_target_cpu(2, &[false, false, true]), Some(2));
    assert_eq!(pick_target_cpu(0, &[false, false, true]), Some(2));
    assert_eq!(pick_target_cpu(-1, &[false, true, false]), Some(1));
}

#[test]
fn head_guard_blocks_foreign() {
    let pinned = [false, false, true];
    assert!(!may_run_on(0, &pinned));
    assert!(may_run_on(2, &pinned));
    let narrow = [false, true, true];
    assert!(!may_run_on(0, &narrow));
    assert!(may_run_on(1, &narrow));
    assert!(may_run_on(2, &narrow));
}

#[test]
fn kick_guard_blocks_foreign() {
    let pinned = [false, true, false];
    assert!(may_run_on(1, &pinned));
    assert!(!may_run_on(0, &pinned));
    assert!(!may_run_on(2, &pinned));
    assert!(!may_run_on(-1, &pinned));
}

#[test]
fn stay_local_keeps_task_cpu() {
    let all = [true; 8];
    assert_eq!(stay_target(2, 8, &all), Some(2));
    assert_eq!(stay_target(0, 8, &all), Some(0));
    assert_eq!(stay_target(-1, 8, &all), None);
    assert_eq!(stay_target(99, 8, &all), None);
    assert_eq!(stay_target(7, 8, &all), Some(7));
    assert_eq!(stay_target(8, 8, &all), None);
}

#[test]
fn stay_disallowed_here_parks() {
    /* In range but outside the mask parks. */
    let narrow = [false, false, true];
    assert_eq!(stay_target(0, 3, &narrow), None);
    assert_eq!(stay_target(1, 3, &narrow), None);
    assert_eq!(stay_target(2, 3, &narrow), Some(2));
    /* Live range with an empty mask parks. */
    let empty = [false, false, false];
    assert_eq!(stay_target(0, 3, &empty), None);
    /* A missing entry fails closed. */
    assert_eq!(stay_target(0, 3, &[]), None);
    /* Out of range parks even when allowed. */
    assert_eq!(stay_target(3, 3, &[true, true, true]), None);
}

#[test]
fn empty_mask_parks() {
    let empty = [false, false, false];
    assert_eq!(pick_target_cpu(0, &empty), None);
    assert_eq!(pick_target_cpu(2, &empty), None);
    assert_eq!(pick_target_cpu(-1, &empty), None);
    assert!(!may_run_on(0, &empty));
    assert!(!may_run_on(2, &empty));
    assert_eq!(pick_target_cpu(-1, &[]), None);
    assert!(!may_run_on(0, &[]));
}

#[test]
fn zero_freq_is_unknown_with_fallback() {
    assert!(!freq_known(0));
    assert!(freq_known(1));
    assert!(freq_known(3_800_000));
    assert!(freq_known(u64::MAX));
}

#[test]
fn no_sibling_keeps_plain_per_cpu() {
    assert!(!topology_has_smt(&[false, false, false]));
    assert!(!topology_has_smt(&[]));
    assert!(!topology_has_smt(&[false]));
    assert!(topology_has_smt(&[false, true, false]));
    assert!(topology_has_smt(&[true]));
    let allowed = [true, true, true];
    assert!(!sibling_ok(false, 1, &allowed));
    assert!(!sibling_ok(false, 0, &allowed));
    assert!(sibling_ok(true, 1, &allowed));
    assert!(!sibling_ok(true, 1, &[true, false, true]));
    assert!(!sibling_ok(true, -1, &allowed));
    assert!(!sibling_ok(true, 9, &allowed));
    assert_eq!(pick_target_cpu(0, &[true]), Some(0));
    assert!(may_run_on(0, &[true]));
    assert!(!may_run_on(1, &[true]));
}

#[test]
fn single_cpu_has_no_peers() {
    assert_eq!(next_peer(0, 1), None);
    assert_eq!(next_peer(0, 0), None);
    assert_eq!(next_peer(0, 2), Some(1));
    assert_eq!(next_peer(1, 2), Some(0));
    assert_eq!(next_peer(2, 2), None);
    assert_eq!(scan_bound(0), 0);
    assert_eq!(scan_bound(1), 0);
    assert_eq!(scan_bound(2), 1);
    assert_eq!(scan_bound(8), 7);
    assert_eq!(scan_bound(64), STEAL_BOUND);
    assert_eq!(stay_target(0, 1, &[true]), Some(0));
    assert_eq!(stay_target(0, 1, &[false]), None);
    assert_eq!(stay_target(1, 1, &[true]), None);
    assert_eq!(stay_target(-1, 1, &[true]), None);
    assert_eq!(pick_target_cpu(0, &[true]), Some(0));
    assert_eq!(pick_target_cpu(-1, &[true]), Some(0));
    assert_eq!(pick_target_cpu(5, &[true]), Some(0));
    assert_eq!(pick_target_cpu(0, &[false]), None);
}

#[test]
fn single_cpu_scan_ends_at_once() {
    let mut steps = 0;
    let mut cur = next_peer(0, 1);
    while let Some(n) = cur {
        steps += 1;
        cur = next_peer(n, 1);
    }
    assert_eq!(steps, 0);
    assert_eq!(cur, None);
    let mut seen = 0;
    let mut at = 0;
    let bound = scan_bound(1);
    while seen < bound {
        at = next_peer(at, 1).unwrap_or(0);
        seen += 1;
    }
    assert_eq!(seen, 0);
    assert_eq!(at, 0);
}

#[test]
fn steal_cursor_rotates_across_peers() {
    assert_eq!(steal_next(0, 4), 1);
    assert_eq!(steal_next(3, 4), 0);
    assert_eq!(steal_next(0, 1), 0);
    assert_eq!(steal_next(5, 0), 0);
    let mut cur = 0;
    for want in [1, 2, 3, 0, 1] {
        cur = steal_next(cur, 4);
        assert_eq!(cur, want);
    }
}

#[test]
fn steal_bound_caps_large_hosts() {
    assert_eq!(scan_bound(2), 1);
    assert_eq!(scan_bound(9), 8);
    assert_eq!(scan_bound(16), 8);
    assert_eq!(scan_bound(1024), 8);
}

#[test]
fn llc_ids_match_header() {
    assert!(llc_known(0));
    assert!(llc_known(1));
    assert!(!llc_known(LLC_UNKNOWN));
    assert!(!llc_ok(0));
    assert!(!llc_ok(1));
    assert!(llc_ok(2));
    assert_eq!(llc_of(0, &[0, 1]), Some(0));
    assert_eq!(llc_of(1, &[0, 1]), Some(1));
    assert_eq!(llc_of(2, &[0, 1]), None);
    assert_eq!(llc_of(0, &[LLC_UNKNOWN]), None);
}

#[test]
fn llc_prefers_local_idle_over_remote() {
    let llc = [0, 0, 1, 1];
    let allowed = [true, true, true, true];
    let idle = [false, false, false, true];
    let full: [bool; 0] = [];
    assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle, &full, 2), Some(3));
    let idle2 = [true, false, false, false];
    assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle2, &full, 2), None);
    assert_eq!(pick_any_idle(&allowed, &idle2), Some(0));
    assert_eq!(
        select_cpu_model(2, 0, &allowed, &idle, &llc, &full, 2),
        Some(3)
    );
    let idle3 = [true, false, false, true];
    assert_eq!(
        select_cpu_model(2, 0, &allowed, &idle3, &llc, &full, 2),
        Some(3)
    );
}

#[test]
fn llc_fallback_when_domain_empty_unknown() {
    let llc = [0, 0, 1, 1];
    let allowed = [true, true, true, true];
    let idle = [true, false, false, false];
    let full: [bool; 0] = [];
    assert_eq!(pick_llc_idle(-1, &llc, &allowed, &idle, &full, 2), None);
    assert_eq!(pick_llc_idle(9, &llc, &allowed, &idle, &full, 2), None);
    let unknown = [LLC_UNKNOWN, LLC_UNKNOWN];
    assert_eq!(pick_llc_idle(0, &unknown, &allowed, &idle, &full, 0), None);
    assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 0), None);
    assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 1), None);
    assert_eq!(
        select_cpu_model(0, 0, &allowed, &idle, &llc, &full, 0),
        Some(0)
    );
    let empty = [false, false, false, false];
    assert_eq!(select_cpu_model(1, 0, &empty, &idle, &llc, &full, 2), None);
}

#[test]
fn single_llc_matches_plain_order() {
    let single = [0, 0, 0, 0];
    let unknown = [LLC_UNKNOWN, LLC_UNKNOWN, LLC_UNKNOWN];
    let allowed = [true, true, true, true];
    let idle = [false, true, false, false];
    let full: [bool; 0] = [];
    assert!(!llc_ok(1));
    assert_eq!(pick_llc_idle(0, &single, &allowed, &idle, &full, 1), None);
    let got = select_cpu_model(0, 0, &allowed, &idle, &single, &full, 1);
    let exp = select_cpu_model(0, 0, &allowed, &idle, &unknown, &full, 0);
    assert_eq!(got, exp);
    assert_eq!(got, Some(1));
    let busy = [false, false, false, false];
    let got2 = select_cpu_model(2, 1, &allowed, &busy, &single, &full, 1);
    let exp2 = select_cpu_model(2, 1, &allowed, &busy, &unknown, &full, 0);
    assert_eq!(got2, exp2);
    assert_eq!(got2, Some(2));
}

#[test]
fn llc_skips_smt_sibling_when_marked() {
    let llc = [0, 0, 0];
    let allowed = [true, true, true];
    let idle = [false, true, true];
    let full = [false, false, true];
    assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 2), Some(2));
    let idle_only_smt = [false, true, false];
    assert_eq!(
        pick_llc_idle(0, &llc, &allowed, &idle_only_smt, &full, 2),
        None
    );
    assert_eq!(
        select_cpu_model(0, 0, &allowed, &idle_only_smt, &llc, &full, 2),
        Some(1)
    );
}

#[test]
fn dispatch_skips_dead_head() {
    /* Dead head models a NULL pid lookup. */
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    /* Good tasks allow the asking CPU. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::from([dead.clone(), good.clone(), good.clone(), good.clone()]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert_eq!(moved, 3);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0], dead);
}

#[test]
fn dispatch_skips_failed_move_with_progress() {
    /* Failed head models a denied queue move. */
    let failed = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: true,
    };
    /* Good tasks allow the asking CPU. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::from([failed.clone(), good.clone(), good.clone()]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(moved > 0);
    assert_eq!(moved, 2);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0], failed);
}

#[test]
fn dispatch_batch_drains_within_passes() {
    let good = PendingTask {
        allowed: vec![true; 16],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::new();
    for _ in 0..64 {
        queue.push_back(good.clone());
    }
    let first = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert_eq!(first, 32);
    assert_eq!(queue.len(), 32);
    let second = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert_eq!(second, 32);
    assert!(queue.is_empty());
}

#[test]
fn dispatch_park_moves_exiting_head() {
    /* Exiting tasks move to run to exit. */
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    /* Foreign head allows only the other CPU. */
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Good tasks allow the asking CPU. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::from([exiting.clone(), foreign.clone(), good.clone(), good.clone()]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(moved > 0);
    assert_eq!(moved, 3);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0], foreign);
}

#[test]
fn progress_guarantee_moves_past_all_bad_heads() {
    /* Dead, foreign, and failed heads stay at once. */
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    /* Exiting tasks move to run to exit. */
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let failed = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: true,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::from([
        dead.clone(),
        exiting.clone(),
        foreign.clone(),
        failed.clone(),
        good.clone(),
    ]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(moved > 0);
    assert_eq!(moved, 2);
    assert_eq!(queue.len(), 3);
    assert_eq!(queue[0], dead);
    assert_eq!(queue[1], foreign);
    assert_eq!(queue[2], failed);
}

#[test]
fn progress_guarantee_property_holds() {
    /* Any movable and exiting task behind bad heads must move. */
    for trial in 0..32 {
        let mut queue = VecDeque::new();
        let bad = trial % 4;
        for i in 0..8 {
            let task = if i < 3 {
                match (bad + i) % 4 {
                    0 => PendingTask {
                        allowed: vec![true, true],
                        exiting: false,
                        live: false,
                        fail: false,
                    },
                    1 => PendingTask {
                        allowed: vec![true, true],
                        exiting: true,
                        live: true,
                        fail: false,
                    },
                    2 => PendingTask {
                        allowed: vec![false, true],
                        exiting: false,
                        live: true,
                        fail: false,
                    },
                    _ => PendingTask {
                        allowed: vec![true, true],
                        exiting: false,
                        live: true,
                        fail: true,
                    },
                }
            } else {
                PendingTask {
                    allowed: vec![true, true],
                    exiting: false,
                    live: true,
                    fail: false,
                }
            };
            queue.push_back(task);
        }
        let moved = drain_model(&mut queue, 0, 8);
        assert!(moved > 0);
        if bad == 2 {
            assert_eq!(moved, 5);
            assert_eq!(queue.len(), 3);
        } else {
            assert_eq!(moved, 6);
            assert_eq!(queue.len(), 2);
        }
    }
}

#[test]
fn progress_guarantee_zero_means_no_movable_work() {
    /* No movable work yields zero without failure. */
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    let foreign = PendingTask {
        allowed: vec![false, false],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::from([dead.clone(), foreign.clone()]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert_eq!(moved, 0);
    assert_eq!(queue.len(), 2);
    /* Adding one movable task restores progress. */
    queue.push_back(PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    });
    let moved2 = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(moved2 > 0);
    assert_eq!(moved2, 1);
}

#[test]
fn incident_idle_cpu_progress_with_bad_heads() {
    /* Foreign tasks pin to the busy CPU. */
    let mut mask = vec![false; 16];
    mask[15] = true;
    let foreign = PendingTask {
        allowed: mask,
        exiting: false,
        live: true,
        fail: false,
    };
    /* Exiting tasks move to run to exit. */
    let exiting = PendingTask {
        allowed: vec![true; 16],
        exiting: true,
        live: true,
        fail: false,
    };
    /* Dead tasks model a NULL pid lookup. */
    let dead = PendingTask {
        allowed: vec![true; 16],
        exiting: false,
        live: false,
        fail: false,
    };
    /* Failed tasks model a denied queue move. */
    let failed = PendingTask {
        allowed: vec![true; 16],
        exiting: false,
        live: true,
        fail: true,
    };
    /* Good tasks allow the idle CPU. */
    let good = PendingTask {
        allowed: vec![true; 16],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut queue = VecDeque::new();
    queue.push_back(exiting.clone());
    queue.push_back(foreign.clone());
    queue.push_back(dead.clone());
    queue.push_back(failed.clone());
    for _ in 0..40 {
        queue.push_back(good.clone());
    }
    assert_eq!(queue.len(), 44);
    /* First pass moves a full batch past bad heads. */
    let first = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(first > 0);
    assert_eq!(first, 32);
    assert_eq!(queue.len(), 12);
    assert_eq!(queue[0], foreign);
    assert_eq!(queue[1], dead);
    assert_eq!(queue[2], failed);
    /* Second pass drains the rest past bad heads. */
    let second = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(second > 0);
    assert_eq!(second, 9);
    assert_eq!(queue.len(), 3);
    /* Unmovable heads stay but never block new work. */
    queue.push_back(good.clone());
    queue.push_back(good.clone());
    let third = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert!(third > 0);
    assert_eq!(third, 2);
    assert_eq!(queue.len(), 3);
    assert_eq!(queue[0], foreign);
    assert_eq!(queue[1], dead);
    assert_eq!(queue[2], failed);
}

#[test]
fn incident_steal_keeps_progress_with_bad_heads() {
    /* Good tasks allow the thief. */
    let good = PendingTask {
        allowed: vec![true, true, true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Bad head allows only the far CPU. */
    let bad = PendingTask {
        allowed: vec![false, false, false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([bad.clone(), good.clone()]),
        VecDeque::from([good.clone()]),
    ];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert!(moved > 0);
    assert_eq!(moved, 2);
    assert_eq!(peers[1].len(), 1);
    assert_eq!(peers[1][0], bad);
    assert_eq!(peers[2].len(), 0);
}

#[test]
fn steal_only_when_idle_and_bounded() {
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([good.clone(), good.clone()]),
    ];
    let (busy, _) = steal_model(&mut peers.clone(), 0, 0, 8, false);
    assert_eq!(busy, 0);
    let (idle, next) = steal_model(&mut peers, 0, 0, 8, true);
    assert!(idle > 0);
    assert_eq!(idle, 1);
    assert_eq!(next, 1);
    let mut wide: Vec<VecDeque<PendingTask>> = vec![VecDeque::new(); 16];
    for q in wide.iter_mut().skip(1) {
        q.push_back(good.clone());
    }
    let (capped, _) = steal_model(&mut wide, 0, 0, 32, true);
    assert!(capped > 0);
    assert!(capped <= 8);
}

#[test]
fn steal_checks_mask_and_skips_bad_heads() {
    /* Foreign tasks allow no CPU here. */
    let foreign = PendingTask {
        allowed: vec![false, false],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Exiting tasks move to run to exit. */
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    /* Good tasks allow the thief. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([foreign.clone(), exiting.clone(), good.clone()]),
        VecDeque::from([good.clone()]),
    ];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert!(moved > 0);
    assert_eq!(moved, 2);
    assert_eq!(peers[1].len(), 2);
    assert_eq!(peers[1][0], foreign);
    assert_eq!(peers[1][1], good);
    assert_eq!(peers[2].len(), 0);
}

#[test]
fn peer_drain_explicit_mask_skips_foreign_head() {
    /* Foreign head stays while good work waits. */
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Good head allows the thief. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    assert!(!peer_head_ok(0, Some(&foreign)));
    assert!(peer_head_ok(0, Some(&good)));
    assert!(peer_head_ok(1, Some(&foreign)));
    assert!(!peer_head_ok(0, None));
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([foreign.clone(), good.clone()]),
        VecDeque::from([good.clone()]),
    ];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert_eq!(moved, 2);
    assert_eq!(peers[1].len(), 1);
    assert_eq!(peers[1][0], foreign);
    assert_eq!(peers[2].len(), 0);
}

#[test]
fn peer_rescues_movable_behind_bad_head() {
    /* Dead head stays while good behind moves. */
    let dead = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: false,
        fail: false,
    };
    /* Foreign head stays for its owner. */
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Failed head stays with progress. */
    let failed = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: true,
    };
    /* Good tasks allow the thief. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([dead.clone(), foreign.clone(), failed.clone(), good.clone()]),
        VecDeque::new(),
    ];
    let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert!(moved > 0);
    assert_eq!(moved, 1);
    assert_eq!(peers[1].len(), 3);
    assert_eq!(peers[1][0], dead);
    assert_eq!(peers[1][1], foreign);
    assert_eq!(peers[1][2], failed);
}

#[test]
fn exiting_task_eventually_runs() {
    /* Exiting tasks move to run to exit. */
    let exiting = PendingTask {
        allowed: vec![true, true],
        exiting: true,
        live: true,
        fail: false,
    };
    /* Good tasks allow the asking CPU. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    /* Owner moves its own exiting head. */
    let mut queue = VecDeque::from([exiting.clone(), good.clone()]);
    let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
    assert_eq!(moved, 2);
    assert!(queue.is_empty());
    /* A thief moves an exiting head when allowed. */
    assert!(peer_head_ok(0, Some(&exiting)));
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([exiting.clone()]),
        VecDeque::new(),
    ];
    let (stolen, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert_eq!(stolen, 1);
    assert!(peers[1].is_empty());
    /* A foreign exiting head stays for its owner. */
    let far = PendingTask {
        allowed: vec![false, true],
        exiting: true,
        live: true,
        fail: false,
    };
    assert!(!peer_head_ok(0, Some(&far)));
    assert!(peer_head_ok(1, Some(&far)));
}

#[test]
fn idle_steals_past_unmovable_leftovers() {
    /* An idle CPU steals past unmovable leftovers. */
    assert!(may_steal(2, 0, 0));
    assert!(may_steal(0, 1, 0));
    assert!(may_steal(5, 3, 0));
    assert!(may_steal(0, 0, 0));
    /* A busy CPU with local work stays home. */
    assert!(!may_steal(1, 0, 1));
    assert!(!may_steal(0, 1, 1));
    assert!(!may_steal(2, 3, 2));
    /* A busy CPU with empty queues may steal. */
    assert!(may_steal(0, 0, 1));
    assert!(may_steal(0, 0, 5));
    /* Own queue with only foreign work stays idle. */
    let foreign = PendingTask {
        allowed: vec![false, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut own = VecDeque::from([foreign.clone(), foreign.clone()]);
    let moved = drain_model(&mut own, 0, DISPATCH_BATCH);
    assert_eq!(moved, 0);
    assert_eq!(own.len(), 2);
    assert!(may_steal(own.len() as u64, 0, moved));
    let mut peers: Vec<VecDeque<PendingTask>> = vec![
        VecDeque::new(),
        VecDeque::from([good.clone()]),
        VecDeque::from([good.clone()]),
    ];
    let (stolen, _) = steal_model(&mut peers, 0, 0, 8, true);
    assert!(stolen > 0);
}

#[test]
fn cleared_running_view_reads_idle() {
    let mut view = RunningView { est: 100, pid: 7 };
    assert!(!view.is_idle());
    view.clear();
    assert_eq!(view, RunningView::idle());
    assert!(view.is_idle());
}

#[test]
fn depths_balance_across_join_leave() {
    let mut d = CpuDepths::new(4);
    d.join(0);
    d.join(0);
    d.join(1);
    assert_eq!(d.sum(), 3);
    d.leave(0);
    assert_eq!(d.sum(), 2);
    d.leave(0);
    d.leave(1);
    assert_eq!(d.sum(), 0);
    d.leave(0);
    assert_eq!(d.sum(), 0);
}

#[test]
fn depths_saturate_at_bounds() {
    let mut d = CpuDepths::new(1);
    d.nr[0] = u64::MAX;
    d.join(0);
    assert_eq!(d.nr[0], u64::MAX);
    d.nr[0] = 0;
    d.leave(0);
    assert_eq!(d.nr[0], 0);
}

#[test]
fn pinned_single_cpu_never_leaves() {
    let pinned = [false, false, true, false];
    for sel in [-1, 0, 1, 2, 3, 5, 99] {
        assert_eq!(pick_target_cpu(sel, &pinned), Some(2));
    }
    assert!(may_run_on(2, &pinned));
    assert!(!may_run_on(0, &pinned));
    assert!(!may_run_on(1, &pinned));
    assert!(!may_run_on(3, &pinned));
    assert!(!may_run_on(-1, &pinned));
    assert!(!may_run_on(99, &pinned));
}

#[test]
fn narrow_mask_keeps_within_mask() {
    let narrow = [false, false, true, true, false];
    assert_eq!(pick_target_cpu(3, &narrow), Some(3));
    assert_eq!(pick_target_cpu(2, &narrow), Some(2));
    assert_eq!(pick_target_cpu(0, &narrow), Some(2));
    assert_eq!(pick_target_cpu(4, &narrow), Some(2));
    assert_eq!(pick_target_cpu(-1, &narrow), Some(2));
    assert_eq!(pick_target_cpu(99, &narrow), Some(2));
    assert!(may_run_on(2, &narrow));
    assert!(may_run_on(3, &narrow));
    assert!(!may_run_on(0, &narrow));
    assert!(!may_run_on(4, &narrow));
}

#[test]
fn batch_window_is_tiny_past_floor() {
    let eps = BATCH_EPS_NS;
    let floor = crate::flow_mean::TQ_MIN_NS;
    assert_eq!(eps, 96_000);
    assert!(eps >= 64_000);
    assert!(eps <= 128_000);
    assert!(eps < floor);
    assert!(batch_within(1_000_000, 1_000_000));
    assert!(batch_within(1_000_000, 1_000_000 + 96_000));
    assert!(!batch_within(1_000_000, 1_000_000 + 96_001));
    assert!(batch_within(1_000_000 + 50_000, 1_000_000));
    assert!(!batch_within(0, 500_000));
}

#[test]
fn grace_is_tiny_past_least_period() {
    let grace = GRACE_NS;
    let least = 120_000_000;
    assert_eq!(grace, 50_000);
    assert!(grace < least);
    assert!(grace_ok(1_000_000, 1_000_000));
    assert!(grace_ok(1_000_000 + 50_000, 1_000_000));
    assert!(!grace_ok(1_000_000 + 50_001, 1_000_000));
    assert!(grace_ok(1_000_000, 1_000_050_000));
    assert!(!grace_ok(2_000_000, 1_000_000));
}

#[test]
fn shed_keeps_one_batch_then_parks() {
    let batch = DISPATCH_BATCH as u64;
    assert_eq!(batch, 32);
    assert!(!should_shed(0));
    assert!(!should_shed(batch - 1));
    assert!(should_shed(batch));
    assert!(should_shed(batch * 2));
}

#[test]
fn shed_cap_bound_matches_twice_batch() {
    /* The cap holds twice one batch with no knob. */
    assert_eq!(SHED_PARK_MAX, 64);
    assert_eq!(SHED_PARK_MAX, DISPATCH_BATCH as u64 * 2);
    assert_eq!(DISPATCH_BATCH as u64, 32);
    /* Below the cap still sheds when the target is full. */
    assert!(should_shed_cap(32, 0));
    assert!(should_shed_cap(32, 63));
    /* At the cap the shed stops with no drop. */
    assert!(!should_shed_cap(32, 64));
    assert!(!should_shed_cap(64, 64));
}

#[test]
fn shed_cap_fallback_keeps_target() {
    /* A full park falls through to the target with no drop. */
    /* The plain shed still wants park, but the cap stops it. */
    assert!(should_shed(32));
    assert!(!should_shed_cap(32, 64));
    assert!(!should_shed_cap(64, 64));
    assert!(!should_shed_cap(64, 100));
    /* An overfull park also falls through with no kill. */
    assert!(!should_shed_cap(32, 65));
    assert!(!should_shed_cap(u64::MAX, u64::MAX));
}

#[test]
fn shed_cap_unsaturated_keeps_target() {
    /* An unsaturated target never sheds even with empty park. */
    assert!(!should_shed_cap(0, 0));
    assert!(!should_shed_cap(31, 0));
    assert!(!should_shed_cap(0, 63));
    /* A saturated target sheds only while park stays below the cap. */
    assert!(should_shed_cap(32, 0));
    assert!(should_shed_cap(64, 0));
    assert!(!should_shed_cap(31, 63));
}

#[test]
fn batch_sticky_keeps_near_deadlines() {
    let allowed = [true, true, true, true];
    assert!(sticky_batch_ok(1, &allowed, 1_000_000, 1_000_000));
    assert!(sticky_batch_ok(1, &allowed, 1_000_000, 1_096_000));
    assert!(!sticky_batch_ok(1, &allowed, 1_000_000, 1_096_001));
    assert!(!sticky_batch_ok(1, &allowed, 0, 1_000_000));
    assert!(!sticky_batch_ok(-1, &allowed, 1_000_000, 1_000_000));
    assert!(!sticky_batch_ok(
        1,
        &[false, false, false, false],
        1_000_000,
        1_000_000
    ));
}

#[test]
fn idle_guard_keeps_old_on_zero() {
    assert_eq!(frontier_idle_guarded(100_000_000, 0), 100_000_000);
    assert_eq!(frontier_idle_guarded(100_000_000, 50_000_000), 50_000_000);
    assert_eq!(frontier_idle_guarded(0, 0), 0);
    assert_eq!(frontier_idle_guarded(0, 1_000_000), 1_000_000);
}

#[test]
fn park_waits_behind_saturated_own() {
    /* No reserve remains, so own keeps full budget. */
    assert_eq!(own_budget_for_dispatch(32, 0, true), 32);
    assert_eq!(own_budget_for_dispatch(32, 1, true), 32);
    assert_eq!(own_budget_for_dispatch(32, 5, true), 32);
    assert_eq!(own_budget_for_dispatch(32, 1, false), 32);
    assert_eq!(own_budget_for_dispatch(0, 1, true), 0);
    assert_eq!(own_budget_for_dispatch(1, 1, true), 1);
    /* Saturated own leaves park waiting in 4.2.0 order. */
    /* The CI 1M verifier limit forces this baseline, so the */
    /* park starve bound is dropped. Shed backpressure is */
    /* future work. */
    let good = PendingTask {
        allowed: vec![true, true],
        exiting: false,
        live: true,
        fail: false,
    };
    let mut own = VecDeque::new();
    let mut park = VecDeque::new();
    for _ in 0..64 {
        own.push_back(good.clone());
    }
    for _ in 0..4 {
        park.push_back(good.clone());
    }
    let (moved_own, moved_park) = dispatch_own_park_model(&mut own, &mut park, 0, 32, true);
    assert_eq!(moved_own, 32);
    assert_eq!(moved_park, 0);
    assert_eq!(moved_own + moved_park, 32);
    assert_eq!(own.len(), 32);
    assert_eq!(park.len(), 4);
    /* Second pass still waits while own stays saturated. */
    let (moved_own2, moved_park2) = dispatch_own_park_model(&mut own, &mut park, 0, 32, true);
    assert_eq!(moved_own2, 32);
    assert_eq!(moved_park2, 0);
    /* Unsaturated own drains park on the remainder. */
    let mut own_small = VecDeque::new();
    let mut park_small = VecDeque::new();
    for _ in 0..10 {
        own_small.push_back(good.clone());
    }
    for _ in 0..4 {
        park_small.push_back(good.clone());
    }
    let (small_own, small_park) =
        dispatch_own_park_model(&mut own_small, &mut park_small, 0, 32, true);
    assert_eq!(small_own, 10);
    assert_eq!(small_park, 4);
    assert!(own_small.is_empty());
    assert!(park_small.is_empty());
    /* A tight remainder caps park at the budget left. */
    let mut own_tight = VecDeque::new();
    let mut park_tight = VecDeque::new();
    for _ in 0..30 {
        own_tight.push_back(good.clone());
    }
    for _ in 0..4 {
        park_tight.push_back(good.clone());
    }
    let (tight_own, tight_park) =
        dispatch_own_park_model(&mut own_tight, &mut park_tight, 0, 32, true);
    assert_eq!(tight_own, 30);
    assert_eq!(tight_park, 2);
    assert_eq!(park_tight.len(), 2);
    /* Empty park keeps full own budget with no loss. */
    let mut own2 = VecDeque::new();
    let mut park2 = VecDeque::new();
    for _ in 0..64 {
        own2.push_back(good.clone());
    }
    let (a, b) = dispatch_own_park_model(&mut own2, &mut park2, 0, 32, true);
    assert_eq!(a, 32);
    assert_eq!(b, 0);
    /* Gate off keeps the same baseline order with park wait. */
    let mut own3 = VecDeque::new();
    let mut park3 = VecDeque::new();
    for _ in 0..64 {
        own3.push_back(good.clone());
    }
    for _ in 0..4 {
        park3.push_back(good.clone());
    }
    let (c, d) = dispatch_own_park_model(&mut own3, &mut park3, 0, 32, false);
    assert_eq!(c, 32);
    assert_eq!(d, 0);
}

#[test]
fn grace_step_matches_stopping_path() {
    /* Runnable stops keep the max with no idle reset. */
    assert_eq!(frontier_idle_grace_step(100, 50, 0, 0, true, 0, 0), 100);
    assert_eq!(frontier_idle_grace_step(10, 20, 0, 0, true, 0, 0), 20);
    /* Queued work keeps the max with no idle reset. */
    assert_eq!(frontier_idle_grace_step(100, 50, 0, 0, false, 1, 0), 100);
    assert_eq!(frontier_idle_grace_step(100, 50, 0, 0, false, 0, 1), 100);
    /* Zero waking keeps old with no stale zero use. */
    assert_eq!(frontier_idle_grace_step(100, 0, 0, 0, false, 0, 0), 100);
    /* Within grace resets to waking time. */
    assert_eq!(
        frontier_idle_grace_step(100, 50, 1_000_000, 1_000_000, false, 0, 0),
        50
    );
    assert_eq!(
        frontier_idle_grace_step(100, 50, 1_000_000, 1_000_000 + 50_000, false, 0, 0),
        50
    );
    /* Past grace keeps the max for prompt account. */
    assert_eq!(
        frontier_idle_grace_step(100, 50, 1_000_000, 1_000_000 + 50_001, false, 0, 0),
        100
    );
    /* Fresh deadline zero skips grace and resets. */
    assert_eq!(
        frontier_idle_grace_step(100, 50, 0, 9_000_000, false, 0, 0),
        50
    );
}

#[test]
fn mask_range_and_live_fail_closed() {
    /* Negative CPUs fail closed. */
    assert!(!may_run_on(-1, &[true, true]));
    assert!(!cpu_live(-1, 2));
    assert!(!may_run_on_live(-1, &[true, true], 2));
    /* CPU past 1024 fails closed as test only bound. */
    assert!(!may_run_on(1024, &[true; 2048]));
    assert!(!cpu_live(1024, 2048));
    assert!(!may_run_on_live(1024, &[true; 2048], 2048));
    assert!(!may_run_on(2048, &[true; 4096]));
    /* Live count bounds the CPU with no queue use. */
    assert!(cpu_live(0, 2));
    assert!(cpu_live(1, 2));
    assert!(!cpu_live(2, 2));
    assert!(!cpu_live(0, 0));
    /* Live plus mask needs both at once. */
    assert!(may_run_on_live(0, &[true, true], 2));
    assert!(!may_run_on_live(0, &[false, true], 2));
    assert!(!may_run_on_live(1, &[true, true], 1));
    assert!(!may_run_on_live(0, &[], 2));
    /* In range mask still honors the mask. */
    assert!(may_run_on(0, &[true, false]));
    assert!(!may_run_on(1, &[true, false]));
    assert!(!may_run_on(2, &[true, false]));
}

#[test]
fn sticky_batch_keeps_prior_when_near() {
    /* Batch near frontier stays on prior with no idle need. */
    let allowed = [true, true, true, true];
    let busy = [false, false, false, false];
    let llc = [0, 0, 1, 1];
    let full: [bool; 0] = [];
    let frontier = 1_000_000;
    let near = 1_000_000 + 10_000;
    let (got, reused) =
        select_sticky_model(1, 0, &allowed, &busy, &llc, &full, 2, near, frontier, true);
    assert_eq!(got, Some(1));
    assert!(!reused);
    /* Far deadline skips batch and picks idle. */
    let far = 1_000_000 + 500_000;
    let idle = [false, false, false, true];
    let (got2, reused2) =
        select_sticky_model(1, 0, &allowed, &idle, &llc, &full, 2, far, frontier, true);
    assert_eq!(got2, Some(3));
    assert!(!reused2);
    /* Fresh deadline zero skips batch at once. */
    let (got3, _) = select_sticky_model(1, 0, &allowed, &idle, &llc, &full, 2, 0, frontier, true);
    assert_eq!(got3, Some(3));
    /* Gate off skips batch and picks idle. */
    let (got4, _) =
        select_sticky_model(1, 0, &allowed, &idle, &llc, &full, 2, near, frontier, false);
    assert_eq!(got4, Some(3));
    /* Foreign prior never batches. */
    let narrow = [false, false, true, false];
    let (got5, _) = select_sticky_model(1, 0, &narrow, &busy, &llc, &full, 2, near, frontier, true);
    assert_ne!(got5, Some(1));
}

#[test]
fn mean_migration_never_leaks() {
    /* Join on first CPU then migrate with leave plus join. */
    let mut a = CpuMean::empty();
    let mut b = CpuMean::empty();
    let e = a.join(2_000_000);
    assert_eq!(a.nr, 1);
    assert_eq!(a.sum, 2_000_000);
    a.leave(e);
    assert_eq!(a.nr, 0);
    assert_eq!(a.sum, 0);
    let f = b.join(e);
    assert_eq!(f, 2_000_000);
    assert_eq!(b.nr, 1);
    assert_eq!(b.sum, 2_000_000);
    b.leave(f);
    assert_eq!(b.nr, 0);
    assert_eq!(b.sum, 0);
    /* Shed to park leaves old with no leak. */
    let mut c = CpuMean::empty();
    let g = c.join(4_000_000);
    assert_eq!(c.sum, 4_000_000);
    c.leave(g);
    assert_eq!(c.sum, 0);
    assert_eq!(c.tq(), TQ_SEED_NS);
    /* Repeated migrate stays bounded with no growth. */
    let mut d = CpuMean::empty();
    let mut e2 = CpuMean::empty();
    for _ in 0..8 {
        let v = d.join(1_000_000);
        d.leave(v);
        let w = e2.join(1_000_000);
        e2.leave(w);
    }
    assert_eq!(d.sum, 0);
    assert_eq!(e2.sum, 0);
    assert_eq!(d.nr, 0);
    assert_eq!(e2.nr, 0);
}

#[test]
fn donor_gated_matches_guard() {
    /* Sticky depths below two never steal. */
    assert!(!donor_ok(0));
    assert!(!donor_ok(1));
    assert!(donor_ok(2));
    /* Gated with no sticky gate allows all with no guard. */
    /* The IEDF flag keeps no guard after the 4.2.0 revert. */
    assert!(donor_ok_gated(0, false, false));
    assert!(donor_ok_gated(1, false, false));
    assert!(donor_ok_gated(0, false, true));
    assert!(donor_ok_gated(1, false, true));
    /* Gated with the sticky gate keeps the guard. */
    assert!(!donor_ok_gated(0, true, false));
    assert!(!donor_ok_gated(1, true, false));
    assert!(!donor_ok_gated(0, true, true));
    assert!(!donor_ok_gated(1, true, true));
    assert!(donor_ok_gated(2, true, false));
    assert!(donor_ok_gated(2, true, true));
    assert!(donor_ok_gated(2, false, true));
    assert!(donor_ok_gated(2, false, false));
}

#[test]
fn owner_none_matches_header() {
    assert_eq!(OWNER_NONE, 0xFFFF_FFFF);
    assert_eq!(crate::flow::OWNER_NONE, OWNER_NONE);
    assert_eq!(crate::flow_edf::OWNER_NONE, OWNER_NONE);
}

#[test]
fn facade_matches_helpers() {
    assert_eq!(crate::flow::DISPATCH_BATCH, crate::flow_edf::DISPATCH_BATCH);
    assert_eq!(crate::flow::OWNER_NONE, crate::flow_edf::OWNER_NONE);
    assert_eq!(crate::flow::DSQ_BASE, crate::flow_edf::DSQ_BASE);
    assert_eq!(crate::flow::DSQ_PARK, crate::flow_edf::DSQ_PARK);
    assert_eq!(crate::flow::BATCH_EPS_NS, crate::flow_edf::BATCH_EPS_NS);
    assert_eq!(crate::flow::GRACE_NS, crate::flow_edf::GRACE_NS);
    assert_eq!(crate::flow::EST_MIN_NS, crate::flow_mean::EST_MIN_NS);
    assert_eq!(crate::flow::EST_MAX_NS, crate::flow_mean::EST_MAX_NS);
    assert_eq!(crate::flow::TQ_SEED_NS, crate::flow_mean::TQ_SEED_NS);
    assert_eq!(crate::flow::TQ_MIN_NS, crate::flow_mean::TQ_MIN_NS);
    assert_eq!(crate::flow::TQ_MAX_NS, crate::flow_mean::TQ_MAX_NS);
    assert_eq!(crate::flow::ACCT_MAX_NS, crate::flow_mean::ACCT_MAX_NS);
    assert_eq!(crate::flow::WEIGHT, crate::flow_mean::WEIGHT);
    assert_eq!(crate::flow::LLC_UNKNOWN, crate::flow_select::LLC_UNKNOWN);
    assert_eq!(crate::flow::MAX_CPUS, crate::flow_select::MAX_CPUS);
    assert_eq!(
        crate::flow::STEAL_MIN_DEPTH,
        crate::flow_select::STEAL_MIN_DEPTH
    );
    assert_eq!(crate::flow::STEAL_BOUND, crate::flow_select::STEAL_BOUND);
}
