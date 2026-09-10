/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Group unit tests for the flow scheduler.
 * The tests mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * Two groups split CPUs by id halves with extra
 * to hog. The classifier uses burn only with a
 * 32ms window plus 16ms demote plus 4ms burst plus
 * 4ms low for 64 wins near 2s.
 */
use crate::flow::*;
use std::collections::VecDeque;

#[test]
fn groups_split_by_halves_with_extra_to_hog() {
    assert_eq!(NGROUPS, 2);
    assert_eq!(GROUP_LIGHT, 0);
    assert_eq!(GROUP_HOG, 1);
    assert_eq!(group_of_cpu(0, 0), GROUP_LIGHT);
    assert_eq!(group_of_cpu(0, 1), GROUP_LIGHT);
    assert_eq!(group_of_cpu(0, 2), GROUP_LIGHT);
    assert_eq!(group_of_cpu(1, 2), GROUP_HOG);
    assert_eq!(group_of_cpu(0, 4), GROUP_LIGHT);
    assert_eq!(group_of_cpu(1, 4), GROUP_LIGHT);
    assert_eq!(group_of_cpu(2, 4), GROUP_HOG);
    assert_eq!(group_of_cpu(3, 4), GROUP_HOG);
    assert_eq!(group_of_cpu(0, 3), GROUP_LIGHT);
    assert_eq!(group_of_cpu(1, 3), GROUP_HOG);
    assert_eq!(group_of_cpu(2, 3), GROUP_HOG);
    assert_eq!(group_of_cpu(0, 16), GROUP_LIGHT);
    assert_eq!(group_of_cpu(7, 16), GROUP_LIGHT);
    assert_eq!(group_of_cpu(8, 16), GROUP_HOG);
    assert_eq!(group_of_cpu(15, 16), GROUP_HOG);
}

#[test]
fn parks_are_per_group_at_5000_plus_5001() {
    assert_eq!(PARK_LIGHT, 0x5000);
    assert_eq!(PARK_HOG, 0x5001);
    assert_ne!(PARK_LIGHT, PARK_HOG);
    assert_eq!(park_for_group(GROUP_LIGHT), 0x5000);
    assert_eq!(park_for_group(GROUP_HOG), 0x5001);
    assert_eq!(park_for_group(7), 0x5000);
    assert_eq!(
        park_for_group(GROUP_LIGHT),
        crate::bpf_intf::flow_consts_FLOW_DSQ_PARK as u64
    );
    assert_eq!(
        park_for_group(GROUP_HOG),
        crate::bpf_intf::flow_consts_FLOW_DSQ_PARK_HOG as u64
    );
}

#[test]
fn perf_is_1024_light_plus_512_hog() {
    assert_eq!(PERF_LIGHT, 1024);
    assert_eq!(PERF_HOG, 512);
    assert_eq!(perf_for_group(GROUP_LIGHT), 1024);
    assert_eq!(perf_for_group(GROUP_HOG), 512);
    assert_eq!(perf_for_group(9), 1024);
}

#[test]
fn window_consts_match_spec() {
    assert_eq!(WIN_NS, 32_000_000);
    assert_eq!(DEMOTE_BURN_NS, 16_000_000);
    assert_eq!(DEMOTE_BURST_NS, 4_000_000);
    assert_eq!(PROMOTE_BURN_NS, 4_000_000);
    assert_eq!(PROMOTE_WINS, 64);
    assert_eq!(PINNED_INFLATE_NS, 8_000_000);
    assert_eq!(WIN_NS, 64 * 500_000);
    assert_eq!((PROMOTE_WINS as u64) * WIN_NS, 2_048_000_000);
    assert_eq!(DEMOTE_BURN_NS, 4 * PROMOTE_BURN_NS);
    assert_eq!(WIN_NS, crate::bpf_intf::flow_consts_FLOW_WIN_NS as u64);
    assert_eq!(
        DEMOTE_BURN_NS,
        crate::bpf_intf::flow_consts_FLOW_DEMOTE_BURN_NS as u64
    );
    assert_eq!(
        DEMOTE_BURST_NS,
        crate::bpf_intf::flow_consts_FLOW_DEMOTE_BURST_NS as u64
    );
    assert_eq!(
        PROMOTE_BURN_NS,
        crate::bpf_intf::flow_consts_FLOW_PROMOTE_BURN_NS as u64
    );
    assert_eq!(
        PROMOTE_WINS as u64,
        crate::bpf_intf::flow_consts_FLOW_PROMOTE_WINS as u64
    );
    assert_eq!(
        PINNED_INFLATE_NS,
        crate::bpf_intf::flow_consts_FLOW_PINNED_INFLATE_NS as u64
    );
}

#[test]
fn cold_starts_light_with_no_window() {
    let st = GroupState::cold();
    assert_eq!(st.group, GROUP_LIGHT);
    assert!(!st.is_hog());
    assert_eq!(st.win_start, 0);
    assert_eq!(st.burn, 0);
    assert_eq!(st.low_runs, 0);
    assert!(!win_ready(1_000_000_000, 0));
    assert!(!win_ready(0, 0));
    assert!(!burn_hot(0));
    assert!(!burst_hot(0));
    assert!(burn_low(0));
}

#[test]
fn window_ready_needs_32ms() {
    assert!(!win_ready(1_000_000, 1_000_000));
    assert!(!win_ready(1_000_000 + WIN_NS - 1, 1_000_000));
    assert!(win_ready(1_000_000 + WIN_NS, 1_000_000));
    assert!(win_ready(1_000_000 + WIN_NS + 1, 1_000_000));
    assert!(!win_ready(0, 0));
}

#[test]
fn burst_hot_needs_4ms() {
    assert!(!burst_hot(0));
    assert!(!burst_hot(DEMOTE_BURST_NS - 1));
    assert!(burst_hot(DEMOTE_BURST_NS));
    assert!(burst_hot(DEMOTE_BURST_NS + 1));
    assert!(burst_hot(16_000_000));
}

#[test]
fn burn_hot_needs_16ms_with_4x_gap() {
    assert!(!burn_hot(0));
    assert!(!burn_hot(4_000_000 - 1));
    assert!(!burn_hot((DEMOTE_BURN_NS - 1) as u32));
    assert!(burn_hot(DEMOTE_BURN_NS as u32));
    assert!(burn_hot((DEMOTE_BURN_NS + 1) as u32));
    assert!(!burn_low(DEMOTE_BURN_NS as u32));
    assert!(burn_low(0));
    assert!(burn_low((PROMOTE_BURN_NS - 1) as u32));
    assert!(!burn_low(PROMOTE_BURN_NS as u32));
    assert_eq!(DEMOTE_BURN_NS, 4 * PROMOTE_BURN_NS);
}

#[test]
fn burst_demotes_light_at_once() {
    let mut st = GroupState::cold();
    let now = 100_000_000;
    st.win_start = now;
    let (demoted, promoted) = classify_step(&mut st, now + 1_000_000, 4_000_000);
    assert!(demoted);
    assert!(!promoted);
    assert_eq!(st.group, GROUP_HOG);
    assert!(st.is_hog());
    assert_eq!(st.low_runs, 0);
    assert_eq!(st.burn, 0);
}

#[test]
fn short_bursts_stay_light() {
    let mut st = GroupState::cold();
    let mut now = 100_000_000;
    st.win_start = now;
    for _ in 0..4 {
        now += 1_000_000;
        let (d, p) = classify_step(&mut st, now, 500_000);
        assert!(!d);
        assert!(!p);
        assert_eq!(st.group, GROUP_LIGHT);
    }
    assert!(st.burn > 0);
}

#[test]
fn window_burn_demotes_at_16ms() {
    let mut st = GroupState::cold();
    let start = 100_000_000;
    st.win_start = start;
    st.burn = 0;
    let mut now = start;
    let mut demoted = false;
    for _ in 0..8 {
        now += 5_000_000;
        let step = 3_000_000;
        let (d, _) = classify_step(&mut st, now, step);
        if d {
            demoted = true;
            break;
        }
    }
    if !demoted {
        now = start + WIN_NS + 1;
        let (d, _) = classify_step(&mut st, now, 500_000);
        assert!(!d || st.group == GROUP_HOG);
    }
    let mut st2 = GroupState::cold();
    st2.win_start = start;
    st2.burn = 15_000_000;
    let (d2, _) = classify_step(&mut st2, start + WIN_NS + 1, 1);
    assert!(!d2);
    assert_eq!(st2.group, GROUP_LIGHT);
    let mut st3 = GroupState::cold();
    st3.win_start = start;
    st3.burn = 16_000_000 - 500_000;
    let (d3, _) = classify_step(&mut st3, start + WIN_NS + 1, 500_000);
    assert!(d3);
    assert_eq!(st3.group, GROUP_HOG);
}

#[test]
fn hog_needs_64_low_wins_near_2s() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 0,
    };
    let mut now = st.win_start;
    for i in 0..63 {
        now += WIN_NS + 1;
        let (d, p) = classify_step(&mut st, now, 500_000);
        assert!(!d);
        assert!(!p, "promote early at {i}");
        assert_eq!(st.group, GROUP_HOG);
    }
    assert_eq!(st.low_runs, 63);
    now += WIN_NS + 1;
    let (d, p) = classify_step(&mut st, now, 500_000);
    assert!(!d);
    assert!(p);
    assert_eq!(st.group, GROUP_LIGHT);
    assert_eq!(st.low_runs, 0);
}

#[test]
fn middle_burn_breaks_streak_with_no_move() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 10,
    };
    let now = st.win_start + WIN_NS + 1;
    let mid: u64 = 8_000_000;
    assert!(!burn_low(mid as u32));
    assert!(!burn_hot(mid as u32));
    let (d, p) = classify_step(&mut st, now, mid);
    assert!(!d);
    assert!(!p);
    assert_eq!(st.group, GROUP_HOG);
    assert_eq!(st.low_runs, 0);
}

#[test]
fn hog_burst_breaks_streak_with_no_promote() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 60,
    };
    let (d, p) = classify_step(&mut st, 101_000_000, 4_000_000);
    assert!(!d);
    assert!(!p);
    assert_eq!(st.group, GROUP_HOG);
    assert_eq!(st.low_runs, 0);
}

#[test]
fn inflate_adds_8ms_with_wrap() {
    assert_eq!(inflate_deadline(100), 8_000_100);
    assert_eq!(inflate_deadline(0), 8_000_000);
    assert_eq!(inflate_deadline(u64::MAX - 1_000_000), 6_999_999);
    assert_eq!(inflate_deadline(1_000_000), 1_000_000 + PINNED_INFLATE_NS);
}

#[test]
fn drain_keeps_strict_isolation() {
    let light = |g: u8| GroupTask {
        allowed: vec![true, true, true, true],
        live: true,
        fail: false,
        group: g,
    };
    let mut q = VecDeque::from([light(GROUP_LIGHT), light(GROUP_HOG), light(GROUP_LIGHT)]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 2);
    assert_eq!(skipped, 1);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].group, GROUP_HOG);
    assert!(group_task_ok(0, GROUP_LIGHT, &light(GROUP_LIGHT)));
    assert!(!group_task_ok(0, GROUP_LIGHT, &light(GROUP_HOG)));
    assert!(!group_task_ok(0, GROUP_HOG, &light(GROUP_LIGHT)));
    assert!(group_task_ok(1, GROUP_HOG, &light(GROUP_HOG)));
}

#[test]
fn drain_skips_dead_plus_failed_with_no_cross() {
    let dead = GroupTask {
        allowed: vec![true, true],
        live: false,
        fail: false,
        group: GROUP_LIGHT,
    };
    let failed = GroupTask {
        allowed: vec![true, true],
        live: true,
        fail: true,
        group: GROUP_LIGHT,
    };
    let cross = GroupTask {
        allowed: vec![true, true],
        live: true,
        fail: false,
        group: GROUP_HOG,
    };
    let good = GroupTask {
        allowed: vec![true, true],
        live: true,
        fail: false,
        group: GROUP_LIGHT,
    };
    let mut q = VecDeque::from([dead, failed, cross, good.clone()]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 1);
    assert_eq!(skipped, 1);
    assert_eq!(q.len(), 3);
}

#[test]
fn first_in_group_finds_allowed_in_group() {
    let all = vec![true; 8];
    assert_eq!(first_in_group(&all, GROUP_LIGHT, 8), Some(0));
    assert_eq!(first_in_group(&all, GROUP_HOG, 8), Some(4));
    let mut narrow = vec![false; 8];
    narrow[6] = true;
    assert_eq!(first_in_group(&narrow, GROUP_LIGHT, 8), None);
    assert_eq!(first_in_group(&narrow, GROUP_HOG, 8), Some(6));
    let mut low = vec![false; 8];
    low[1] = true;
    assert_eq!(first_in_group(&low, GROUP_LIGHT, 8), Some(1));
    assert_eq!(first_in_group(&low, GROUP_HOG, 8), None);
    assert_eq!(first_in_group(&[], GROUP_LIGHT, 0), None);
}

#[test]
fn burn_add_caps_at_max() {
    assert_eq!(burn_add(0, 1_000_000), 1_000_000);
    assert_eq!(burn_add(u32::MAX, 1_000_000), u32::MAX);
    assert_eq!(burn_add(u32::MAX - 10, 100), u32::MAX);
}
