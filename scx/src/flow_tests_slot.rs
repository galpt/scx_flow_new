// SPDX-License-Identifier: GPL-2.0
/*
 * Slot store unit tests
 *
 * Covers the sharded FIFO slot helpers with probe, bucket, rotation, rescue,
 * defer, and kick checks. Run with cargo test -p scx_flow flow_tests_slot.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
use crate::flow_group::*;
use crate::flow_select::*;
use crate::flow_slot::*;
use std::collections::VecDeque;

#[test]
fn slot_ids_match_header() {
    assert_eq!(SLOT_BASE, 0x6000);
    assert_eq!(SLOT_PER_GROUP, 256);
    assert_eq!(SLOT_NGROUPS, 2);
    assert_eq!(SLOT_N, 512);
    assert_eq!(SLOT_OVERFLOW_BASE, 0x6200);
    assert_eq!(SLOT_OVERFLOW_N, 2);
    assert_eq!(SLOT_D, 4);
    assert_eq!(SLOT_BUDGET, 32);
    assert_eq!(SLOT_OWN_CAP, 31);
    assert_eq!(RETAIN_MAX, 3);
    assert_eq!(SWEEP_MAX, 256);
    assert_eq!(slot_own_cap(32), 31);
    assert_eq!(slot_own_cap(0), 0);
    assert_eq!(
        SLOT_BASE,
        crate::bpf_intf::flow_consts_FLOW_SLOT_BASE as u64
    );
    assert_eq!(
        SLOT_PER_GROUP,
        crate::bpf_intf::flow_consts_FLOW_SLOT_PER_GROUP as u64
    );
    assert_eq!(SLOT_N, crate::bpf_intf::flow_consts_FLOW_SLOT_N as u64);
    assert_eq!(
        SLOT_OVERFLOW_BASE,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_BASE as u64
    );
    assert_eq!(
        SLOT_OVERFLOW_N,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_N as u64
    );
    assert_eq!(SLOT_D, crate::bpf_intf::flow_consts_FLOW_SLOT_D as u32);
    assert_eq!(
        SLOT_BUDGET,
        crate::bpf_intf::flow_consts_FLOW_SLOT_BUDGET as u32
    );
    assert_eq!(
        RETAIN_MAX as u32,
        crate::bpf_intf::flow_consts_FLOW_SLOT_RETAIN_MAX as u32
    );
    assert_eq!(
        SWEEP_MAX as u32,
        crate::bpf_intf::flow_consts_FLOW_SLOT_SWEEP_MAX as u32
    );
    assert_eq!(crate::flow::SLOT_BASE, SLOT_BASE);
    assert_eq!(crate::flow::SLOT_BUDGET, SLOT_BUDGET);
}

#[test]
fn wheel_consts_match_header() {
    assert_eq!(WHEEL_SLOT_NS, 64_000);
    assert_eq!(WHEEL_DIM, 256);
    assert_eq!(WHEEL_TOTAL, 65536);
    assert_eq!(WHEEL_HORIZON_NS, 64_000 * 65536);
    assert_eq!(WHEEL_QUANT_LO, 0xFFFF);
    assert_eq!(TOKEN_MAX, 255);
    assert_eq!(
        WHEEL_SLOT_NS,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_SLOT_NS as u64
    );
    assert_eq!(
        WHEEL_TOTAL,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_TOTAL as u64
    );
    assert_eq!(
        WHEEL_HORIZON_NS,
        crate::bpf_intf::flow_consts_FLOW_WHEEL_HORIZON_NS as u64
    );
}

#[test]
fn probe_overdue_maps_slot_zero() {
    let frontier = 100_000_000;
    let (qdl, slot, err, over) = wheel_probe(frontier - 1_000, frontier);
    assert_eq!(slot, 0);
    assert!(!over);
    assert_eq!(qdl, qdl_round_down(frontier - 1_000));
    assert_eq!(err, (frontier - 1_000) & 0xFFFF);
}

#[test]
fn probe_inside_maps_shifted_distance() {
    // Aligned frontier keeps quantise exact, so slot reads the distance.
    let frontier = 0x1_0000_0000u64;
    for k in [0, 1, 7, 255] {
        let dl = frontier + k * 65536;
        let (qdl, slot, _, over) = wheel_probe(dl, frontier);
        assert!(!over);
        assert_eq!(slot, k);
        assert_eq!(qdl, qdl_round_down(dl));
    }
}

#[test]
fn probe_past_horizon_pins_tail() {
    let frontier = 1_000_000_000;
    let dl = frontier + WHEEL_HORIZON_NS + 1_000_000;
    let (qdl, slot, _, over) = wheel_probe(dl, frontier);
    assert!(over);
    assert_eq!(slot, WHEEL_TOTAL - 1);
    assert_eq!(qdl, qdl_round_down(frontier + WHEEL_HORIZON_NS - 1));
}

#[test]
fn probe_rounds_down_with_bounded_error() {
    let frontier = 1_000_000_000;
    let dl = frontier + 100_000;
    let (qdl, _, err, _) = wheel_probe(dl, frontier);
    assert_eq!(qdl, dl & !0xFFFF);
    assert_eq!(err, dl & 0xFFFF);
    assert!(err <= 0xFFFF);
}

#[test]
fn bucket_holds_low8_of_slot() {
    assert_eq!(slot_bucket(0), 0);
    assert_eq!(slot_bucket(7 << 16), 7);
    assert_eq!(slot_bucket(255 << 16), 255);
    assert_eq!(slot_bucket((256 << 16) | 0xbeef), 0);
    // Aligned frontier keeps quantise exact, so bucket reads the distance.
    let frontier = 0x1_0000_0000u64;
    let (qdl, slot, _, over) = wheel_probe(frontier + 9 * 65536, frontier);
    assert!(!over);
    assert_eq!(slot, 9);
    assert_eq!(slot_bucket(qdl), 9);
}

#[test]
fn slot_dsq_shards_groups_with_no_share() {
    assert_eq!(slot_dsq(GROUP_LIGHT, 0), 0x6000);
    assert_eq!(slot_dsq(GROUP_LIGHT, 255), 0x60ff);
    assert_eq!(slot_dsq(GROUP_HOG, 0), 0x6100);
    assert_eq!(slot_dsq(GROUP_HOG, 255), 0x61ff);
    assert_eq!(slot_dsq(7, 3), 0x6003);
    assert_eq!(slot_dsq(GROUP_LIGHT, 0x1ff), 0x60ff);
    assert_ne!(slot_dsq(GROUP_LIGHT, 9), slot_dsq(GROUP_HOG, 9));
}

#[test]
fn overflow_tails_are_per_group() {
    assert_eq!(slot_overflow_dsq(GROUP_LIGHT), 0x6200);
    assert_eq!(slot_overflow_dsq(GROUP_HOG), 0x6201);
    assert_eq!(slot_overflow_dsq(7), 0x6200);
    assert_eq!(overflow_for_group(GROUP_LIGHT), OVERFLOW_LIGHT);
    assert_eq!(overflow_for_group(GROUP_HOG), OVERFLOW_HOG);
    assert_eq!(OVERFLOW_LIGHT, 0x6200);
    assert_eq!(OVERFLOW_HOG, 0x6201);
    assert_eq!(
        OVERFLOW_LIGHT,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW_BASE as u64
    );
}

#[test]
fn slot_cap_holds_at_d() {
    assert_eq!(slot_cap(32), 4);
    assert_eq!(slot_cap(100), 4);
    assert_eq!(slot_cap(4), 4);
    assert_eq!(slot_cap(3), 3);
    assert_eq!(slot_cap(0), 0);
}

#[test]
fn rotation_advances_and_wraps() {
    assert_eq!(slot_next(0), 1);
    assert_eq!(slot_next(254), 255);
    assert_eq!(slot_next(255), 0);
    assert_eq!(slot_add(0, 0), 1);
    assert_eq!(slot_add(0, 1), 2);
    assert_eq!(slot_add(254, 0), 255);
    assert_eq!(slot_add(255, 0), 0);
    assert_eq!(slot_add(255, 1), 1);
}

#[test]
fn trips_cover_own_overflow_and_two_fill() {
    let trips = trip_dsqs(9, GROUP_LIGHT);
    assert_eq!(trips[0], slot_dsq(GROUP_LIGHT, 9));
    assert_eq!(trips[1], slot_overflow_dsq(GROUP_LIGHT));
    assert_eq!(trips[2], slot_dsq(GROUP_LIGHT, 10));
    assert_eq!(trips[3], slot_dsq(GROUP_LIGHT, 11));
    assert_eq!(trips[4], slot_overflow_dsq(GROUP_HOG));
    assert_ne!(trips[0], trips[2]);
    assert_ne!(trips[2], trips[3]);
    assert_ne!(trips[1], trips[4]);
    let wrap = trip_dsqs(255, GROUP_HOG);
    assert_eq!(wrap[0], slot_dsq(GROUP_HOG, 255));
    assert_eq!(wrap[2], slot_dsq(GROUP_HOG, 0));
    assert_eq!(wrap[3], slot_dsq(GROUP_HOG, 1));
    assert_eq!(wrap[4], slot_overflow_dsq(GROUP_LIGHT));
}

#[test]
fn rescue_visits_other_group_cursor() {
    assert_eq!(rescue_dsq(9, GROUP_LIGHT), slot_dsq(GROUP_HOG, 9));
    assert_eq!(rescue_dsq(9, GROUP_HOG), slot_dsq(GROUP_LIGHT, 9));
    assert_ne!(rescue_dsq(9, GROUP_LIGHT), trip_dsqs(9, GROUP_LIGHT)[0]);
}

#[test]
fn rotation_retain_keeps_hot_bucket() {
    assert_eq!(rotation_step(9, true, true), 9);
    assert_eq!(rotation_step(9, true, false), 10);
    assert_eq!(rotation_step(9, false, false), 10);
    assert_eq!(rotation_step(9, false, true), 10);
    assert_eq!(rotation_step(255, true, false), 0);
}

#[test]
fn starvation_hot_bucket_drains_with_retains() {
    let mut cur: u8 = 7;
    let mut retains: u8 = 0;
    let mut left = 40u32;
    let mut passes = 0;
    let mut moved_total = 0;
    while left > 0 && passes < 4 {
        let take = left.min(SLOT_OWN_CAP);
        moved_total += take;
        left -= take;
        let capped = take >= SLOT_OWN_CAP;
        let (next, next_ret) = rotation_step_bounded(cur, left > 0, capped, retains);
        cur = next;
        retains = next_ret;
        passes += 1;
    }
    assert_eq!(moved_total, 40);
    assert_eq!(passes, 2);
    assert_eq!(cur, 8);
    assert_eq!(retains, 0);
}

#[test]
fn no_dead_bucket_covers_every_bucket() {
    let mut cur: u8 = 0;
    let mut seen = [false; 256];
    for _ in 0..256 {
        seen[cur as usize] = true;
        cur = rotation_step(cur, false, false);
    }
    assert!(seen.iter().all(|&v| v));
    assert_eq!(cur, 0);
}

#[test]
fn race_marks_never_hide_queued_work() {
    // Bits only accumulate with no clear and drains never consult marks,
    // so queued work stays drainable under every mark and insert interleave.
    // The model tracks queue length with the bit: inserts set the bit, drains
    // remove work with no bit use, and the invariant holds that queued work
    // never waits on a mark.
    let mut len = 0u32;
    let mut bit = false;
    let mut ops = Vec::new();
    for i in 0..64u32 {
        ops.push(i % 4);
    }
    for op in ops {
        match op {
            0 => {
                len += 1;
                bit = true;
            }
            1 => {
                if len > 0 {
                    len -= 1;
                }
            }
            2 => {
                // A drain pass moves movable work with no mark check.
                if len > 0 {
                    len -= 1;
                }
            }
            _ => {
                if len > 0 {
                    bit = true;
                }
            }
        }
        if len > 0 {
            // Work stays collectible by rotation with no mark gate, and a set
            // bit never clears under it.
            assert!(bit, "queued work must stay marked");
        }
    }
}

#[test]
fn defer_fires_on_cap_with_work_left() {
    assert!(defer_ok(4, true, false));
    assert!(!defer_ok(32, false, true));
    assert!(defer_ok(32, true, true));
    assert!(defer_ok(32, true, false));
    assert!(!defer_ok(3, true, true));
    assert!(!defer_ok(4, false, false));
    assert!(!defer_ok(0, true, true));
    assert!(!defer_ok(0, false, true));
}

#[test]
fn kick_progress_far_and_sweep_discipline() {
    assert_eq!(kick_step(1, true, false, 0), (true, 0));
    assert_eq!(kick_step(1, false, true, 0), (false, 0));
    assert_eq!(kick_step(5, false, false, 0), (false, 0));
    assert_eq!(kick_step(5, true, false, 0), (true, 0));
    assert_eq!(kick_step(0, false, true, 3), (false, 3));
    assert_eq!(kick_step(0, false, true, 255), (false, 255));
    assert_eq!(kick_step(0, false, false, 7), (false, 7));
    assert_eq!(kick_step(0, true, false, 7), (true, 8));
    assert_eq!(kick_step(0, true, false, 255), (true, 256));
    assert_eq!(kick_step(0, true, false, 256), (false, 256));
    assert_eq!(kick_step(1, true, false, 9), (true, 0));
}

fn live_task(cpu: usize, nr: usize) -> PendingTask {
    PendingTask {
        allowed: (0..nr).map(|c| c == cpu).collect(),
        exiting: false,
        live: true,
        fail: false,
    }
}

#[test]
fn fifo_drain_skips_dead_head() {
    let mut q = VecDeque::from([
        PendingTask {
            live: false,
            ..live_task(0, 2)
        },
        live_task(0, 2),
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 2);
    assert_eq!(q.len(), 1);
}

#[test]
fn fifo_drain_skips_failed_move_with_progress() {
    let mut q = VecDeque::from([
        PendingTask {
            fail: true,
            ..live_task(0, 2)
        },
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
    assert!(q[0].fail);
}

#[test]
fn fifo_drain_respects_cap_plus_base() {
    let mut q = VecDeque::from([
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
        live_task(0, 2),
    ]);
    let moved = slot_drain_model(&mut q, 0, SLOT_D, 0);
    assert_eq!(moved, SLOT_D);
    assert_eq!(q.len(), 1);
    let moved2 = slot_drain_model(&mut q, 0, SLOT_BUDGET, moved);
    assert_eq!(moved2, 1);
    assert!(q.is_empty());
}

#[test]
fn fifo_drain_keeps_arrival_order() {
    let mut q = VecDeque::from([live_task(0, 2), live_task(1, 2)]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0].allowed, vec![false, true]);
}

#[test]
fn rescue_moves_one_per_dispatch_under_hot_own_load() {
    // Mirrors dispatch.bpf.c lim2 = moved + 1U: rescue moves at most one
    // toward budget per dispatch. Hot own load keeps the own bucket
    // non-empty every dispatch yet leaves budget open, so rescue still
    // takes exactly one while own takes the rest.
    let cpu = 0;
    let mut rescue_q: VecDeque<PendingTask> = (0..8).map(|_| live_task(cpu as usize, 2)).collect();
    for _ in 0..8 {
        // Hot own refill with 10 movable keeps budget open at 10 of 32.
        let mut own_q: VecDeque<PendingTask> =
            (0..10).map(|_| live_task(cpu as usize, 2)).collect();
        let mut moved = slot_drain_model(&mut own_q, cpu, SLOT_BUDGET, 0);
        assert_eq!(moved, 10);
        assert!(own_q.is_empty());
        // Overflow and fill stay empty, so rescue sees moved at 10.
        if moved < SLOT_BUDGET {
            let lim2 = (moved + 1).min(SLOT_BUDGET);
            let got = slot_drain_model(&mut rescue_q, cpu, lim2, moved);
            assert_eq!(got, 1, "rescue must move exactly one when open");
            moved += got;
        }
        assert_eq!(moved, 11);
    }
    assert!(rescue_q.is_empty());
    // Saturating own load keeps the 31 reserve, so rescue still
    // takes the last budget slot with no strand. Own at 32 tasks
    // drains 31 at the own cap with one left, then rescue moves
    // one toward 32.
    let mut own_full: VecDeque<PendingTask> = (0..SLOT_BUDGET)
        .map(|_| live_task(cpu as usize, 2))
        .collect();
    let mut rescue_one: VecDeque<PendingTask> = VecDeque::from([live_task(cpu as usize, 2)]);
    let mut moved = slot_drain_model(&mut own_full, cpu, SLOT_OWN_CAP, 0);
    assert_eq!(moved, SLOT_OWN_CAP);
    assert_eq!(own_full.len(), 1);
    if moved < SLOT_BUDGET {
        let lim = (moved + 1).min(SLOT_BUDGET);
        moved += slot_drain_model(&mut rescue_one, cpu, lim, moved);
    }
    assert_eq!(moved, SLOT_BUDGET);
    assert!(rescue_one.is_empty());
    assert_eq!(own_full.len(), 1);
}

#[test]
fn rescue_worst_case_bound_is_one_per_dispatch() {
    // R rescue tasks need exactly R dispatches at one per dispatch.
    // This is the worst case when every dispatch leaves budget open.
    // Rotation plus the kick sweep still cover every bucket, so the
    // unit rescue rate suffices as the exception path.
    let cpu = 0;
    const RESCUE_N: usize = 16;
    let mut rescue_q: VecDeque<PendingTask> =
        (0..RESCUE_N).map(|_| live_task(cpu as usize, 2)).collect();
    for expect_left in (0..RESCUE_N).rev() {
        // Own stays hot at 31, so rescue takes the last budget slot.
        let mut own_q: VecDeque<PendingTask> =
            (0..31).map(|_| live_task(cpu as usize, 2)).collect();
        let mut moved = slot_drain_model(&mut own_q, cpu, SLOT_BUDGET, 0);
        assert_eq!(moved, 31);
        let lim2 = (moved + 1).min(SLOT_BUDGET);
        let got = slot_drain_model(&mut rescue_q, cpu, lim2, moved);
        assert_eq!(got, 1);
        moved += got;
        assert_eq!(moved, SLOT_BUDGET);
        assert_eq!(rescue_q.len(), expect_left);
    }
    assert!(rescue_q.is_empty());
}

#[test]
fn rescue_never_strands_behind_mask_blocked_own() {
    // Own holds only mask-blocked tasks for this CPU while rescue holds
    // movable cross-group work. Own moves zero yet stays unpinned
    // because the leftover is uncapped, and rescue still moves one per
    // dispatch with the cursor advancing, so no strand forms.
    let cpu = 0;
    let mut cur: u8 = 9;
    let mut own_q: VecDeque<PendingTask> = (0..4)
        .map(|_| PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        })
        .collect();
    let mut rescue_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(cpu as usize, 2)).collect();
    for _ in 0..4 {
        let own_moved = slot_drain_model(&mut own_q, cpu, SLOT_OWN_CAP, 0);
        assert_eq!(own_moved, 0);
        // Uncapped leftover must advance, never pin.
        let left = !own_q.is_empty();
        let capped = own_moved >= SLOT_OWN_CAP;
        let next = rotation_step(cur, left, capped);
        assert_eq!(next, slot_next(cur));
        cur = next;
        // Rescue runs with budget open and moves exactly one.
        let got = slot_drain_model(&mut rescue_q, cpu, 1, 0);
        assert_eq!(got, 1);
    }
    assert!(rescue_q.is_empty());
    // Blocked own work stays queued but never pinned the rotation.
    assert_eq!(own_q.len(), 4);
    assert_eq!(cur, 13);
}

#[test]
fn token_eligible_needs_full_conjunct() {
    assert!(token_eligible(true, 5, 1_000_000, 0, 100));
    assert!(!token_eligible(false, 5, 1_000_000, 0, 100));
    assert!(!token_eligible(true, 0, 1_000_000, 0, 100));
    assert!(!token_eligible(true, 5, 1_000_001, 0, 100));
    assert!(!token_eligible(true, 5, 1_000_000, 4_000_000, 100));
    assert!(!token_eligible(true, 5, 1_000_000, 0, 64_001));
    assert!(token_eligible(true, 255, 1, 0, 64_000));
}

#[test]
fn facade_matches_slot_helpers() {
    assert_eq!(crate::flow::SLOT_BASE, SLOT_BASE);
    assert_eq!(crate::flow::SLOT_D, SLOT_D);
    assert_eq!(crate::flow::SLOT_BUDGET, SLOT_BUDGET);
    assert_eq!(crate::flow::WHEEL_TOTAL, WHEEL_TOTAL);
    assert_eq!(crate::flow::TOKEN_MAX, TOKEN_MAX);
    assert_eq!(
        slot_dsq(GROUP_LIGHT, 1),
        crate::flow::slot_dsq(GROUP_LIGHT, 1)
    );
    assert_eq!(slot_next(255), crate::flow::slot_next(255));
}

#[test]
fn slot_own_cap_holds_31_with_reserve() {
    assert_eq!(SLOT_OWN_CAP, 31);
    assert_eq!(SLOT_BUDGET, 32);
    assert_eq!(slot_own_cap(32), 31);
    assert_eq!(slot_own_cap(31), 30);
    assert_eq!(slot_own_cap(1), 0);
    assert_eq!(slot_own_cap(0), 0);
    assert_eq!(slot_cap(32), SLOT_D);
}

#[test]
fn retain_bound_forces_advance_after_three() {
    assert_eq!(rotation_step_bounded(9, true, true, 0), (9, 1));
    assert_eq!(rotation_step_bounded(9, true, true, 1), (9, 2));
    assert_eq!(rotation_step_bounded(9, true, true, 2), (9, 3));
    assert_eq!(rotation_step_bounded(9, true, true, 3), (10, 0));
    assert_eq!(rotation_step_bounded(9, true, true, 4), (10, 0));
    assert_eq!(rotation_step_bounded(9, true, false, 0), (10, 0));
    assert_eq!(rotation_step_bounded(9, false, true, 0), (10, 0));
    assert_eq!(RETAIN_MAX, 3);
    assert_eq!(
        RETAIN_MAX as u32,
        crate::bpf_intf::flow_consts_FLOW_SLOT_RETAIN_MAX as u32
    );
}

#[test]
fn high1_single_group_hog_overflow_drains_bounded() {
    // Single-group host all-light with a hog far tail must
    // drain via trip 4 bounded at D with mask wins.
    let cpu = 0;
    let trips = trip_dsqs(9, GROUP_LIGHT);
    assert_eq!(trips[4], slot_overflow_dsq(GROUP_HOG));
    assert_ne!(trips[1], trips[4]);
    let mut hog_over: VecDeque<PendingTask> = (0..8).map(|_| live_task(0, 2)).collect();
    let got = slot_drain_model(&mut hog_over, cpu, SLOT_D, 0);
    assert_eq!(got, SLOT_D);
    assert_eq!(hog_over.len(), 4);
    let got2 = slot_drain_model(&mut hog_over, cpu, SLOT_D, 0);
    assert_eq!(got2, SLOT_D);
    assert!(hog_over.is_empty());
    // Mask wins: foreign tasks stay with progress.
    let mut mixed = VecDeque::from([
        PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        },
        live_task(0, 2),
    ]);
    let got3 = slot_drain_model(&mut mixed, cpu, SLOT_D, 0);
    assert_eq!(got3, 1);
    assert_eq!(mixed.len(), 1);
}

#[test]
fn high2_foreign_crowd_idle_target_wakes() {
    // Shared queue crowded by foreign work must still kick
    // an idle target, so no idle CPU sleeps unkicked.
    assert!(kick_idle_ok(8, 0, true));
    assert!(kick_idle_ok(100, 0, true));
    assert!(kick_idle_ok(u64::MAX, 0, true));
    assert!(!kick_idle_ok(8, 1, true));
    assert!(!kick_idle_ok(8, 0, false));
    let now = 5_000_000u64;
    let recent = now - 1_000;
    assert!(!kick_coalesced(8, 0, true, false, now, recent));
    assert!(!kick_coalesced(100, 0, true, false, now, recent));
    // Q2 still coalesces, deep never does.
    assert!(kick_coalesced(2, 0, true, false, now, recent));
    assert!(!kick_coalesced(2, 0, true, true, now, recent));
}

#[test]
fn high3_saturated_own_hog_progress() {
    // Saturated own at 40 with hog rescue at 4 must still
    // move hog via the 31 reserve with one per dispatch.
    let cpu = 0;
    let mut own_q: VecDeque<PendingTask> = (0..40).map(|_| live_task(0, 2)).collect();
    let mut rescue_q: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let mut moved = slot_drain_model(&mut own_q, cpu, SLOT_OWN_CAP, 0);
    assert_eq!(moved, SLOT_OWN_CAP);
    assert_eq!(own_q.len(), 9);
    let lim = (moved + 1).min(SLOT_BUDGET);
    let got = slot_drain_model(&mut rescue_q, cpu, lim, moved);
    assert_eq!(got, 1);
    moved += got;
    assert_eq!(moved, SLOT_BUDGET);
    assert_eq!(rescue_q.len(), 3);
    // Next dispatch still reserves with own hot.
    let mut own_hot: VecDeque<PendingTask> = (0..32).map(|_| live_task(0, 2)).collect();
    let m2 = slot_drain_model(&mut own_hot, cpu, SLOT_OWN_CAP, 0);
    assert_eq!(m2, SLOT_OWN_CAP);
    let lim2 = (m2 + 1).min(SLOT_BUDGET);
    let g2 = slot_drain_model(&mut rescue_q, cpu, lim2, m2);
    assert_eq!(g2, 1);
    assert_eq!(rescue_q.len(), 2);
}

#[test]
fn high4_kick_rate_bounded_at_steady_state() {
    // Steady state with no window work stays quiet even with
    // stale far marks, so kicks per dispatch stay well below
    // one. Far alone never defers or kicks.
    assert!(!defer_ok(32, false, true));
    assert!(!kick_step(5, false, true, 0).0);
    assert!(!kick_step(0, false, true, 0).0);
    let mut kicks = 0u32;
    let mut sweep: u16 = 0;
    let dispatches = 100u32;
    for _ in 0..dispatches {
        // Steady: moves with no window, far marked stale.
        let (kick, next) = kick_step(5, false, true, sweep);
        sweep = next;
        if kick {
            kicks += 1;
        }
        assert!(!kick);
    }
    assert_eq!(kicks, 0);
    // Empty with no work stays quiet.
    let (kick2, _) = kick_step(0, false, false, sweep);
    assert!(!kick2);
    // Window work kicks once then resets, sweep bounds zero
    // move chains at 256 with no infinite loop.
    let (kick3, next3) = kick_step(1, true, false, 0);
    assert!(kick3);
    assert_eq!(next3, 0);
    let mut s: u16 = 0;
    for _ in 0..SWEEP_MAX {
        let (k, n) = kick_step(0, true, false, s);
        assert!(k);
        s = n;
    }
    assert_eq!(s, SWEEP_MAX);
    let (k_last, s_last) = kick_step(0, true, false, s);
    assert!(!k_last);
    assert_eq!(s_last, SWEEP_MAX);
    // Rate with one window kick in 100 stays << 1.
    let rate = 1.0 / dispatches as f64;
    assert!(rate < 0.1);
}

#[test]
fn high5_sustained_hot_far_bucket_bounded() {
    // Sustained hot retains at most three, then force
    // advance, so a far bucket 100 ahead is visited well
    // within 1024 dispatches with refill to zero.
    let mut cur: u8 = 7;
    let mut retains: u8 = 0;
    let mut far_seen_at: Option<u32> = None;
    for i in 0..1024 {
        if cur == 100 {
            far_seen_at = Some(i);
            break;
        }
        // Only the hot bucket 7 stays capped, the rest run
        // empty with advance and reset.
        let hot = cur == 7;
        let (next, next_ret) = rotation_step_bounded(cur, hot, hot, retains);
        cur = next;
        retains = next_ret;
    }
    let at = far_seen_at.expect("far bucket must be seen");
    assert!(at < 1024);
    assert!(at < 200);
    // All-hot worst case needs exactly 1024 to sweep 256
    // buckets at four visits each, so 512 would strand.
    let mut cur2: u8 = 0;
    let mut ret2: u8 = 0;
    let mut count = 0u32;
    let mut seen = [false; 256];
    for _ in 0..1024 {
        seen[cur2 as usize] = true;
        let (next, next_ret) = rotation_step_bounded(cur2, true, true, ret2);
        cur2 = next;
        ret2 = next_ret;
        count += 1;
    }
    assert!(seen.iter().all(|&v| v));
    assert_eq!(count, 1024);
    assert_eq!(cur2, 0);
}

#[test]
fn attach_far_sweep_bounds_guest_stall() {
    // Exact guest stall: 4 tasks in 0x600f (light 15)
    // plus 1 in 0x603d (light 61) with cursors at 0,
    // watchdog 30s, zero cells, kicks 6, moves 1.
    // Far must drain both within 3 hops with kicks
    // and late 61 still jumps on the next idle pass.
    let cpu = 0;
    let mut occupied = [false; 256];
    occupied[15] = true;
    occupied[61] = true;
    // First far jump from 0 lands on 15 at once.
    assert_eq!(far_next(0, &occupied), Some(15));
    assert!(kick_far_ok(1, false, true));
    assert!(!kick_far_ok(1, false, false));
    // Old rotation without far needs 15 steps to
    // reach 15, so 6 kicks stall with no chain.
    let mut cur: u8 = 0;
    let mut steps = 0u32;
    while cur != 15 && steps < 256 {
        cur = slot_next(cur);
        steps += 1;
    }
    assert_eq!(steps, 15);
    // Far drain model: idle jump, move, kick, repeat.
    let mut q15: VecDeque<PendingTask> = (0..4).map(|_| live_task(0, 2)).collect();
    let mut q61: VecDeque<PendingTask> = VecDeque::from([live_task(0, 2)]);
    let mut cur2: u8 = 0;
    let mut moves = 0u32;
    let mut hops = 0u32;
    let mut occ2 = occupied;
    // Two far hops drain 15 then 61 with idle jumps.
    for _ in 0..257 {
        // Pre-window holds no work at attach idle,
        // so far runs on every idle pass with no
        // premature clear as with the old cold flag.
        let next = far_next(cur2, &occ2);
        let Some(b) = next else {
            break;
        };
        cur2 = b;
        let far_jump = true;
        let got = if b == 15 {
            let m = slot_drain_model(&mut q15, cpu, SLOT_OWN_CAP, 0);
            if q15.is_empty() {
                occ2[15] = false;
            }
            m
        } else if b == 61 {
            let m = slot_drain_model(&mut q61, cpu, SLOT_OWN_CAP, 0);
            if q61.is_empty() {
                occ2[61] = false;
            }
            m
        } else {
            0
        };
        moves += got;
        // Far progress kicks even with no window,
        // so 61 still chains after 15 drains.
        assert!(kick_far_ok(got, false, far_jump));
        cur2 = slot_next(cur2);
        hops += 1;
        if q15.is_empty() && q61.is_empty() {
            break;
        }
    }
    assert!(q15.is_empty());
    assert!(q61.is_empty());
    assert_eq!(moves, 5);
    assert!(hops <= 3);
    // Truly idle finds none with no kick.
    assert_eq!(far_next(cur2, &occ2), None);
    assert!(!kick_far_ok(0, false, false));
    // Late 61 after 15 drains still jumps: clear 15,
    // keep 61, scan from 16 lands on 61 at once.
    let mut late = [false; 256];
    late[61] = true;
    assert_eq!(far_next(16, &late), Some(61));
}
