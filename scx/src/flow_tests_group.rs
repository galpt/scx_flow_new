/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Group unit tests for the flow scheduler.
 * The tests mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * Two groups split CPUs by id halves with extra
 * to hog and odd extra to hog in both views. The
 * classifier uses burn only with a 32ms window plus
 * 16ms demote plus 4ms burst plus 4ms low for 64 wins
 * near 2s plus 8 short blocks below 1ms with burn
 * below 4ms. Tier 0 models keep both drains. BPF ships
 * Tier 2 peer with donor only.
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
fn perf_is_1024_for_both_groups() {
    assert_eq!(PERF_LIGHT, 1024);
    assert_eq!(PERF_HOG, 1024);
    assert_eq!(perf_for_group(GROUP_LIGHT), 1024);
    assert_eq!(perf_for_group(GROUP_HOG), 1024);
    assert_eq!(perf_for_group(9), 1024);
}

#[test]
fn window_consts_match_spec() {
    assert_eq!(WIN_NS, 32_000_000);
    assert_eq!(DEMOTE_BURN_NS, 16_000_000);
    assert_eq!(DEMOTE_BURST_NS, 4_000_000);
    assert_eq!(DEMOTE_BURST_MID_NS, 2_000_000);
    assert_eq!(DEMOTE_BURST_FLOOR_NS, 1_000_000);
    assert_eq!(PROMOTE_BURN_NS, 4_000_000);
    assert_eq!(PROMOTE_WINS, 64);
    assert_eq!(PROMOTE_WAKE_HITS, 8);
    assert_eq!(WAKE_SHORT_NS, 1_000_000);
    assert_eq!(HETERO_SPREAD_PCT, 10);
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
    assert_eq!(
        PROMOTE_WAKE_HITS as u64,
        crate::bpf_intf::flow_consts_FLOW_PROMOTE_WAKE_HITS as u64
    );
    assert_eq!(
        WAKE_SHORT_NS,
        crate::bpf_intf::flow_consts_FLOW_WAKE_SHORT_NS as u64
    );
    assert_eq!(
        HETERO_SPREAD_PCT,
        crate::bpf_intf::flow_consts_FLOW_HETERO_SPREAD_PCT as u64
    );
    assert_eq!(PERF_HOG, crate::bpf_intf::flow_consts_FLOW_PERF_HOG as u32);
    assert_eq!(
        PERF_LIGHT,
        crate::bpf_intf::flow_consts_FLOW_PERF_LIGHT as u32
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
    assert_eq!(st.wake_hits, 0);
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

/*
 * Allowance maps depth to the burst line. Quiet
 * keeps 4ms, mild halves to 2ms, deep floors at 1ms.
 * Header values match the Rust mirrors with no knob.
 */
#[test]
fn burst_allowance_maps_depth_to_line() {
    assert_eq!(DEMOTE_BURST_NS, 4_000_000);
    assert_eq!(DEMOTE_BURST_MID_NS, 2_000_000);
    assert_eq!(DEMOTE_BURST_FLOOR_NS, 1_000_000);
    assert_eq!(
        DEMOTE_BURST_MID_NS,
        crate::bpf_intf::flow_consts_FLOW_DEMOTE_BURST_MID_NS as u64
    );
    assert_eq!(
        DEMOTE_BURST_FLOOR_NS,
        crate::bpf_intf::flow_consts_FLOW_DEMOTE_BURST_FLOOR_NS as u64
    );
    assert_eq!(burst_allowance(0), 4_000_000);
    assert_eq!(burst_allowance(1), 4_000_000);
    assert_eq!(burst_allowance(2), 2_000_000);
    assert_eq!(burst_allowance(3), 2_000_000);
    assert_eq!(burst_allowance(4), 1_000_000);
    assert_eq!(burst_allowance(5), 1_000_000);
    assert_eq!(burst_allowance(100), 1_000_000);
    assert!(!burst_hot_at(3_999_999, burst_allowance(1)));
    assert!(burst_hot_at(4_000_000, burst_allowance(1)));
    assert!(!burst_hot_at(1_999_999, burst_allowance(2)));
    assert!(burst_hot_at(2_000_000, burst_allowance(2)));
    assert!(!burst_hot_at(999_999, burst_allowance(4)));
    assert!(burst_hot_at(1_000_000, burst_allowance(4)));
}

/*
 * Depth sums light queues only with cap at 4. Hog
 * queues stay out, so cross group flood never lifts
 * the light line. Missing entries count as zero.
 */
#[test]
fn light_depth_sums_light_only_capped_at_4() {
    assert_eq!(light_depth(&[], 0), 0);
    assert_eq!(light_depth(&[0, 0, 0, 0], 4), 0);
    assert_eq!(light_depth(&[1, 0, 0, 0], 4), 1);
    assert_eq!(light_depth(&[0, 0, 5, 5], 4), 0);
    assert_eq!(light_depth(&[1, 0, 10, 10], 4), 1);
    assert_eq!(light_depth(&[1, 1, 0, 0], 4), 2);
    assert_eq!(light_depth(&[2, 2, 0, 0], 4), 4);
    assert_eq!(light_depth(&[10, 10, 10, 10], 4), 4);
    assert_eq!(light_depth(&[1], 1), 1);
    assert_eq!(light_depth(&[5, 5], 2), 4);
}

/*
 * Hog depth sums hog queues only with cap at 4. Light
 * queues stay out, so light flood never lifts the hog
 * view. Display only with no burst use.
 */
#[test]
fn hog_depth_sums_hog_only_capped_at_4() {
    assert_eq!(hog_depth(&[], 0), 0);
    assert_eq!(hog_depth(&[0, 0, 0, 0], 4), 0);
    assert_eq!(hog_depth(&[5, 5, 0, 0], 4), 0);
    assert_eq!(hog_depth(&[0, 0, 1, 0], 4), 1);
    assert_eq!(hog_depth(&[10, 10, 1, 0], 4), 1);
    assert_eq!(hog_depth(&[0, 0, 1, 1], 4), 2);
    assert_eq!(hog_depth(&[0, 0, 2, 2], 4), 4);
    assert_eq!(hog_depth(&[10, 10, 10, 10], 4), 4);
    assert_eq!(hog_depth(&[1], 1), 0);
    assert_eq!(hog_depth(&[5, 5], 2), 4);
}

/*
 * Both depths share one pass with cap at 4 each. The
 * single scan matches the BPF refresh with bounded
 * cost. Light plus hog stay separate with no cross
 * lift.
 */
#[test]
fn group_depths_share_one_pass_capped() {
    assert_eq!(group_depths(&[], 0), (0, 0));
    assert_eq!(group_depths(&[0, 0, 0, 0], 4), (0, 0));
    assert_eq!(group_depths(&[1, 0, 0, 1], 4), (1, 1));
    assert_eq!(group_depths(&[2, 2, 2, 2], 4), (4, 4));
    assert_eq!(group_depths(&[10, 10, 10, 10], 4), (4, 4));
    assert_eq!(group_depths(&[1, 1, 0, 0], 4), (2, 0));
    assert_eq!(group_depths(&[0, 0, 1, 1], 4), (0, 2));
}

/*
 * Quiet keeps the 4ms line. A burst just below 4ms
 * stays light, a burst at 4ms demotes at once.
 */
#[test]
fn quiet_keeps_4ms_line() {
    let mut stay = GroupState::cold();
    stay.win_start = 100_000_000;
    let (d, p) = classify_step_depth(&mut stay, 101_000_000, 3_999_999, 0);
    assert!(!d);
    assert!(!p);
    assert_eq!(stay.group, GROUP_LIGHT);
    let mut move_light = GroupState::cold();
    move_light.win_start = 100_000_000;
    let (d2, p2) = classify_step_depth(&mut move_light, 101_000_000, 4_000_000, 1);
    assert!(d2);
    assert!(!p2);
    assert_eq!(move_light.group, GROUP_HOG);
}

/*
 * Mild pressure uses the 2ms line. A burst just
 * below 2ms stays light, a burst at 2ms demotes.
 */
#[test]
fn mild_pressure_uses_2ms_line() {
    let mut stay = GroupState::cold();
    stay.win_start = 100_000_000;
    let (d, p) = classify_step_depth(&mut stay, 101_000_000, 1_999_999, 2);
    assert!(!d);
    assert!(!p);
    assert_eq!(stay.group, GROUP_LIGHT);
    let mut move_light = GroupState::cold();
    move_light.win_start = 100_000_000;
    let (d2, p2) = classify_step_depth(&mut move_light, 101_000_000, 2_000_000, 3);
    assert!(d2);
    assert!(!p2);
    assert_eq!(move_light.group, GROUP_HOG);
}

/*
 * Deep pressure demotes at the 1ms floor. A burst
 * just below 1ms stays light, a burst at 1ms moves
 * to hog at once with per task worst case at floor.
 */
#[test]
fn deep_pressure_demotes_at_floor() {
    let mut stay = GroupState::cold();
    stay.win_start = 100_000_000;
    let (d, p) = classify_step_depth(&mut stay, 101_000_000, 999_999, 4);
    assert!(!d);
    assert!(!p);
    assert_eq!(stay.group, GROUP_LIGHT);
    let mut move_light = GroupState::cold();
    move_light.win_start = 100_000_000;
    let (d2, p2) = classify_step_depth(&mut move_light, 101_000_000, 1_000_000, 4);
    assert!(d2);
    assert!(!p2);
    assert_eq!(move_light.group, GROUP_HOG);
    let mut deep = GroupState::cold();
    deep.win_start = 100_000_000;
    let (d3, p3) = classify_step_depth(&mut deep, 101_000_000, 1_000_000, 100);
    assert!(d3);
    assert!(!p3);
    assert_eq!(deep.group, GROUP_HOG);
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
        wake_hits: 0,
    };
    let mut now = st.win_start;
    for i in 0..63 {
        now += WIN_NS + 1;
        let (d, p) = classify_step(&mut st, now, 2_000_000);
        assert!(!d);
        assert!(!p, "promote early at {i}");
        assert_eq!(st.group, GROUP_HOG);
    }
    assert_eq!(st.low_runs, 63);
    now += WIN_NS + 1;
    let (d, p) = classify_step(&mut st, now, 2_000_000);
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
        wake_hits: 0,
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
        wake_hits: 0,
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

/*
 * Tier 0 model only. BPF ships Tier 2 peer with donor
 * only and no task recheck, so hetero peer may move
 * cross with strict on uniform hosts.
 */
#[test]
fn drain_keeps_strict_isolation_tier0_model_only() {
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

/*
 * Tier 0 model only. BPF ships Tier 2 peer with donor
 * only and no task recheck, so hetero peer may move
 * cross with strict on uniform hosts.
 */
#[test]
fn drain_skips_dead_plus_failed_with_no_cross_tier0_model_only() {
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

#[test]
fn wake_short_needs_1ms() {
    assert!(wake_short(0));
    assert!(wake_short(500_000));
    assert!(wake_short(WAKE_SHORT_NS - 1));
    assert!(!wake_short(WAKE_SHORT_NS));
    assert!(!wake_short(WAKE_SHORT_NS + 1));
    assert!(!wake_short(4_000_000));
}

#[test]
fn wake_ready_needs_8_hits() {
    assert!(!wake_ready(0));
    assert!(!wake_ready(7));
    assert!(wake_ready(8));
    assert!(wake_ready(9));
    assert!(wake_ready(u16::MAX));
    assert_eq!(PROMOTE_WAKE_HITS, 8);
}

#[test]
fn eight_short_blocks_promote_hog_to_light() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 0,
        wake_hits: 0,
    };
    let mut now = 100_000_000;
    for i in 0..7 {
        now += 1_000_000;
        let (d, p) = classify_step(&mut st, now, 200_000);
        assert!(!d);
        assert!(!p, "promote early at {i}");
        assert_eq!(st.group, GROUP_HOG);
    }
    assert_eq!(st.wake_hits, 7);
    now += 1_000_000;
    let (d, p) = classify_step(&mut st, now, 200_000);
    assert!(!d);
    assert!(p);
    assert_eq!(st.group, GROUP_LIGHT);
    assert_eq!(st.wake_hits, 0);
    assert_eq!(st.low_runs, 0);
}

#[test]
fn middle_window_preserves_wake_hits() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 0,
        wake_hits: 5,
    };
    let now = 100_000_000 + 1_000_000;
    assert!(!win_ready(now, st.win_start));
    let (d, p) = classify_step(&mut st, now, 500_000);
    assert!(!d);
    assert!(!p);
    assert_eq!(st.group, GROUP_HOG);
    assert_eq!(st.wake_hits, 6);
    let mut fresh = GroupState {
        group: GROUP_HOG,
        win_start: 0,
        burn: 0,
        low_runs: 0,
        wake_hits: 3,
    };
    let (d2, p2) = classify_step(&mut fresh, 200_000_000, 500_000);
    assert!(!d2);
    assert!(!p2);
    assert_eq!(fresh.wake_hits, 4);
}

#[test]
fn burn_gated_anti_game_breaks_wake_streak() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 0,
        wake_hits: 7,
    };
    let (d, p) = classify_step(&mut st, 101_000_000, 4_000_000);
    assert!(!d);
    assert!(!p);
    assert_eq!(st.wake_hits, 0);
    let mut hot = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 10_000_000,
        low_runs: 0,
        wake_hits: 7,
    };
    let now = 100_000_000 + WIN_NS + 1;
    let (d2, p2) = classify_step(&mut hot, now, 500_000);
    assert!(!d2);
    assert!(!p2);
    assert_eq!(hot.group, GROUP_HOG);
    assert_eq!(hot.wake_hits, 0);
}

#[test]
fn slow_64_win_path_stays_intact_with_wake() {
    let mut st = GroupState {
        group: GROUP_HOG,
        win_start: 100_000_000,
        burn: 0,
        low_runs: 0,
        wake_hits: 0,
    };
    let mut now = st.win_start;
    for _ in 0..64 {
        now += WIN_NS + 1;
        let _ = classify_step(&mut st, now, 2_000_000);
    }
    assert_eq!(st.group, GROUP_LIGHT);
    let mut burst = GroupState::cold();
    burst.win_start = 100_000_000;
    let (d, _) = classify_step(&mut burst, 101_000_000, 4_000_000);
    assert!(d);
    assert_eq!(burst.wake_hits, 0);
}

#[test]
fn task_state_stays_48_with_wake_at_46() {
    assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 48);
    let base = std::mem::MaybeUninit::<crate::bpf_intf::flow_task_ctx>::uninit();
    let ptr = base.as_ptr();
    let off = unsafe { std::ptr::addr_of!((*ptr).wake_hits) as usize - ptr as usize };
    assert_eq!(off, 46);
    assert_eq!(
        crate::bpf_intf::flow_consts_FLOW_PROMOTE_WAKE_HITS as u64,
        8
    );
}

/*
 * Tier 0 model only for park plus peer. BPF ships Tier
 * 2 with park recheck plus peer donor only and no peer
 * task recheck, so hetero peer may move cross.
 */
#[test]
fn park_per_task_recheck_keeps_only_thief_group_tier0_model_only() {
    let light = |g: u8| GroupTask {
        allowed: vec![true, true],
        live: true,
        fail: false,
        group: g,
    };
    let mut q = VecDeque::from([light(GROUP_LIGHT), light(GROUP_HOG), light(GROUP_LIGHT)]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 2);
    assert_eq!(skipped, 1);
    assert_eq!(q.len(), 1);
    let mut q2 = VecDeque::from([light(GROUP_HOG), light(GROUP_HOG)]);
    let (m2, s2) = group_drain_model(&mut q2, 0, GROUP_LIGHT, 32);
    assert_eq!(m2, 0);
    assert_eq!(s2, 2);
}

/*
 * Tier 0 model only. BPF ships Tier 2 peer with donor
 * only and no task recheck due to verifier jump plus
 * BSS bounds, so a stale cross peer entry may move on
 * hetero hosts with strict on uniform hosts.
 */
#[test]
fn peer_per_task_recheck_skips_stale_cross_tier0_model_only() {
    let mk = |g: u8, allow: bool| GroupTask {
        allowed: vec![allow, true],
        live: true,
        fail: false,
        group: g,
    };
    let mut q = VecDeque::from([mk(GROUP_HOG, true), mk(GROUP_LIGHT, true)]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 1);
    assert_eq!(skipped, 1);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].group, GROUP_HOG);
    assert!(group_task_ok(0, GROUP_LIGHT, &mk(GROUP_LIGHT, true)));
    assert!(!group_task_ok(0, GROUP_LIGHT, &mk(GROUP_HOG, true)));
}

/*
 * Tier 0 model only. BPF ships Tier 2 peer with donor
 * only and no task recheck, so hetero peer may move
 * cross with strict on uniform hosts.
 */
#[test]
fn null_storage_defaults_to_light_tier0_model_only() {
    let bad = GroupTask {
        allowed: vec![true, true],
        live: true,
        fail: false,
        group: 7,
    };
    assert!(group_task_ok(0, GROUP_LIGHT, &bad));
    assert!(!group_task_ok(0, GROUP_HOG, &bad));
    let mut q = VecDeque::from([bad.clone()]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 1);
    assert_eq!(skipped, 0);
    let mut q2 = VecDeque::from([bad]);
    let (m2, s2) = group_drain_model(&mut q2, 0, GROUP_HOG, 32);
    assert_eq!(m2, 0);
    assert_eq!(s2, 1);
}

/*
 * Tier 0 model only. BPF ships Tier 2 peer with donor
 * only and no task recheck, so hetero peer may move
 * cross with strict on uniform hosts.
 */
#[test]
fn mask_fail_never_counts_as_group_skip_tier0_model_only() {
    let cross_mask_fail = GroupTask {
        allowed: vec![false, false],
        live: true,
        fail: false,
        group: GROUP_HOG,
    };
    let mut q = VecDeque::from([cross_mask_fail]);
    let (moved, skipped) = group_drain_model(&mut q, 0, GROUP_LIGHT, 32);
    assert_eq!(moved, 0);
    assert_eq!(skipped, 0);
    assert_eq!(q.len(), 1);
    let dead_cross = GroupTask {
        allowed: vec![true, true],
        live: false,
        fail: false,
        group: GROUP_HOG,
    };
    let mut q2 = VecDeque::from([dead_cross]);
    let (m2, s2) = group_drain_model(&mut q2, 0, GROUP_LIGHT, 32);
    assert_eq!(m2, 0);
    assert_eq!(s2, 0);
}

#[test]
fn spread_needs_10pct() {
    assert!(!spread_exceeds(&[]));
    assert!(!spread_exceeds(&[100]));
    assert!(!spread_exceeds(&[100, 100]));
    assert!(!spread_exceeds(&[100, 105]));
    assert!(!spread_exceeds(&[1000, 1000]));
    assert!(spread_exceeds(&[100, 200]));
    assert!(!spread_exceeds(&[900, 1000]));
    assert!(spread_exceeds(&[899, 1000]));
    assert!(spread_exceeds(&[1024, 512]));
    assert!(!spread_exceeds(&[0, 0]));
    assert!(!spread_exceeds(&[4787082, 4787082]));
    assert!(spread_exceeds(&[4000000, 4787082]));
}

#[test]
fn hetero_needed_checks_both_signals() {
    assert!(!hetero_needed(&[1024, 1024], &[4787082, 4787082]));
    assert!(hetero_needed(&[1024, 512], &[4787082, 4787082]));
    assert!(hetero_needed(&[1024, 1024], &[4000000, 4787082]));
    assert!(hetero_needed(&[1024, 512], &[4000000, 4787082]));
    assert!(!hetero_needed(&[], &[]));
    assert!(!hetero_needed(&[0, 0], &[0, 0]));
}

#[test]
fn sorted_interleave_spreads_fast_across_groups() {
    let caps = vec![1024, 1024, 512, 512];
    let freqs = vec![4000000, 4000000, 4000000, 4000000];
    let out = assign_sorted_interleave(&caps, &freqs, 4);
    assert_eq!(out.len(), 4);
    assert_eq!(out.iter().filter(|&&g| g == GROUP_LIGHT).count(), 2);
    assert_eq!(out.iter().filter(|&&g| g == GROUP_HOG).count(), 2);
    let caps2 = vec![1024, 512, 1024, 512];
    let freqs2 = vec![5000000, 4000000, 5000000, 4000000];
    let out2 = assign_sorted_interleave(&caps2, &freqs2, 4);
    assert_eq!(out2[0], GROUP_LIGHT);
    assert_eq!(out2[2], GROUP_HOG);
    let single = assign_sorted_interleave(&[1024], &[4000000], 1);
    assert_eq!(single, vec![GROUP_LIGHT]);
}

/*
 * Odd counts give the extra CPU to hog in both views.
 * Halves gives 1 light plus 2 hog at 3. Interleave
 * matches with 1 light plus 2 hog, so hetero keeps
 * the same bias with no split.
 */
#[test]
fn odd_counts_give_extra_to_hog_in_both_views() {
    assert_eq!(group_of_cpu(0, 3), GROUP_LIGHT);
    assert_eq!(group_of_cpu(1, 3), GROUP_HOG);
    assert_eq!(group_of_cpu(2, 3), GROUP_HOG);
    let caps = vec![1024, 512, 512];
    let freqs = vec![4000000, 4000000, 4000000];
    let out = assign_sorted_interleave(&caps, &freqs, 3);
    assert_eq!(out.len(), 3);
    assert_eq!(out.iter().filter(|&&g| g == GROUP_LIGHT).count(), 1);
    assert_eq!(out.iter().filter(|&&g| g == GROUP_HOG).count(), 2);
    assert_eq!(out[0], GROUP_LIGHT);
    assert_eq!(out[1], GROUP_HOG);
    assert_eq!(out[2], GROUP_HOG);
    let caps5 = vec![1024, 1024, 1024, 512, 512];
    let freqs5 = vec![4000000; 5];
    let out5 = assign_sorted_interleave(&caps5, &freqs5, 5);
    assert_eq!(out5.iter().filter(|&&g| g == GROUP_LIGHT).count(), 2);
    assert_eq!(out5.iter().filter(|&&g| g == GROUP_HOG).count(), 3);
    let (t, r) = seed_groups(&caps, &freqs, 3);
    assert_eq!(r, 1);
    assert_eq!(t[..3].iter().filter(|&&g| g == GROUP_LIGHT).count(), 1);
    assert_eq!(t[..3].iter().filter(|&&g| g == GROUP_HOG).count(), 2);
}

/*
 * Short slices clamp with no pad. Uniform short stays
 * ready cleared, so missing zeros never fake hetero.
 * Hetero short uses only available entries.
 */
#[test]
fn seed_groups_clamps_short_slices_with_no_pad() {
    let (t1, r1) = seed_groups(&[1024, 1024], &[4000000, 4000000], 4);
    assert_eq!(r1, 0);
    assert!(t1.iter().all(|&g| g == GROUP_LIGHT));
    let (t2, r2) = seed_groups(&[1024, 512], &[4000000, 4000000], 4);
    assert_eq!(r2, 1);
    assert_ne!(t2[0], t2[1]);
    assert_eq!(t2[2], GROUP_LIGHT);
    assert_eq!(t2[3], GROUP_LIGHT);
    let (t3, r3) = seed_groups(&[], &[], 4);
    assert_eq!(r3, 0);
    assert!(t3.iter().all(|&g| g == GROUP_LIGHT));
    let (t4, r4) = seed_groups(&[1024], &[4000000], 4);
    assert_eq!(r4, 0);
    assert!(t4.iter().all(|&g| g == GROUP_LIGHT));
}

#[test]
fn halves_fallback_when_uniform_or_single() {
    let (t1, r1) = seed_groups(
        &[1024, 1024, 1024, 1024],
        &[4000000, 4000000, 4000000, 4000000],
        4,
    );
    assert_eq!(r1, 0);
    assert!(t1.iter().all(|&g| g == GROUP_LIGHT));
    let (t2, r2) = seed_groups(&[1024], &[4000000], 1);
    assert_eq!(r2, 0);
    assert_eq!(t2[0], GROUP_LIGHT);
    let (t3, r3) = seed_groups(&[1024, 512], &[4000000, 4000000], 2);
    assert_eq!(r3, 1);
    assert_ne!(t3[0], t3[1]);
}

#[test]
fn group_live_mirrors_fallback_when_not_ready() {
    let table = [GROUP_HOG; GROUP_TABLE_LEN];
    assert_eq!(group_live(0, 4, &table, 0), group_of_cpu(0, 4));
    assert_eq!(group_live(3, 4, &table, 0), group_of_cpu(3, 4));
    assert_eq!(group_live(0, 1, &table, 0), GROUP_LIGHT);
    let mut good = [GROUP_LIGHT; GROUP_TABLE_LEN];
    good[0] = GROUP_LIGHT;
    good[1] = GROUP_HOG;
    assert_eq!(group_live(0, 2, &good, 1), GROUP_LIGHT);
    assert_eq!(group_live(1, 2, &good, 1), GROUP_HOG);
    let mut bad = [7u8; GROUP_TABLE_LEN];
    bad[0] = 7;
    assert_eq!(group_live(0, 2, &bad, 1), GROUP_LIGHT);
}

#[test]
fn seed_groups_sets_ready_only_when_hetero() {
    let hetero_caps = vec![1024, 1024, 1024, 1024, 512, 512, 512, 512];
    let hetero_freqs = vec![4787082; 8];
    let (t, r) = seed_groups(&hetero_caps, &hetero_freqs, 8);
    assert_eq!(r, 1);
    assert_eq!(t[..8].iter().filter(|&&g| g == GROUP_LIGHT).count(), 4);
    assert_eq!(t[..8].iter().filter(|&&g| g == GROUP_HOG).count(), 4);
    assert_eq!(t.iter().filter(|&&g| g == GROUP_LIGHT).count(), 1020);
    let uniform_caps = vec![1024; 8];
    let uniform_freqs = vec![4787082; 8];
    let (_, r2) = seed_groups(&uniform_caps, &uniform_freqs, 8);
    assert_eq!(r2, 0);
}

/*
 * Hetero keeps dispatch on halves while placement uses
 * live. Strict on uniform hosts. Best effort on hetero
 * hosts with verifier jump plus BSS bounds. Locks the
 * documented split with no live use in dispatch.
 */
#[test]
fn hetero_dispatch_uses_halves_placement_uses_live() {
    let caps = vec![1024, 1024, 512, 512];
    let freqs = vec![4000000, 4000000, 4000000, 4000000];
    let (table, ready) = seed_groups(&caps, &freqs, 4);
    assert_eq!(ready, 1);
    let mut diverged = false;
    for cpu in 0..4 {
        let halves = group_of_cpu(cpu, 4);
        let live = group_live(cpu, 4, &table, ready);
        if halves != live {
            diverged = true;
        }
    }
    assert!(diverged);
    assert_eq!(group_of_cpu(0, 4), GROUP_LIGHT);
    assert_eq!(group_of_cpu(2, 4), GROUP_HOG);
    assert_eq!(group_live(0, 4, &table, ready), GROUP_LIGHT);
    assert_eq!(group_live(1, 4, &table, ready), GROUP_HOG);
    assert_eq!(group_live(2, 4, &table, ready), GROUP_LIGHT);
    let uniform = vec![1024; 4];
    let uniform_freq = vec![4000000; 4];
    let (t2, r2) = seed_groups(&uniform, &uniform_freq, 4);
    assert_eq!(r2, 0);
    for cpu in 0..4 {
        assert_eq!(group_live(cpu, 4, &t2, r2), group_of_cpu(cpu, 4));
    }
}

/*
 * Pinned keeps the CPU with live regroup. A task pinned
 * to one CPU takes the live group of that CPU, so later
 * park plus steal see the same group. Locks the enqueue
 * pinned path with no stale group.
 */
#[test]
fn pinned_regroups_to_live_group() {
    let caps = vec![1024, 1024, 512, 512];
    let freqs = vec![4000000, 4000000, 4000000, 4000000];
    let (table, ready) = seed_groups(&caps, &freqs, 4);
    assert_eq!(ready, 1);
    let pinned = 1u32;
    let live = group_live(pinned, 4, &table, ready);
    assert_eq!(live, GROUP_HOG);
    assert_eq!(group_of_cpu(pinned, 4), GROUP_LIGHT);
    assert_ne!(live, group_of_cpu(pinned, 4));
    let pinned2 = 2u32;
    let live2 = group_live(pinned2, 4, &table, ready);
    assert_eq!(live2, GROUP_LIGHT);
    assert_eq!(group_of_cpu(pinned2, 4), GROUP_HOG);
    assert_ne!(live2, group_of_cpu(pinned2, 4));
}

#[test]
fn first_in_group_live_uses_table_when_ready() {
    let all = vec![true; 4];
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    table[0] = GROUP_HOG;
    table[1] = GROUP_HOG;
    table[2] = GROUP_LIGHT;
    table[3] = GROUP_LIGHT;
    assert_eq!(
        first_in_group_live(&all, GROUP_LIGHT, 4, &table, 1),
        Some(2)
    );
    assert_eq!(first_in_group_live(&all, GROUP_HOG, 4, &table, 1), Some(0));
    assert_eq!(
        first_in_group_live(&all, GROUP_LIGHT, 4, &table, 0),
        Some(0)
    );
    assert_eq!(first_in_group_live(&all, GROUP_HOG, 4, &table, 0), Some(2));
}
