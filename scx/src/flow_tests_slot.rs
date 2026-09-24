// SPDX-License-Identifier: GPL-2.0
//! Slot store unit tests for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Covers queue ids, insert routing, drain caps, steal need, and donors.

use crate::flow_select::*;
use crate::flow_slot::*;
use std::collections::VecDeque;

/// Queue ids hold base plus id with overflow at 0x6800.
#[test]
fn slot_ids_match_header() {
    assert_eq!(SLOT_BASE, 0x6000);
    assert_eq!(SLOT_OVERFLOW, 0x6800);
    assert_eq!(slot_cpu_dsq(0), 0x6000);
    assert_eq!(slot_cpu_dsq(3), 0x6003);
    assert_eq!(slot_cpu_dsq(1023), 0x6000 + 1023);
    assert_eq!(slot_overflow_dsq(), 0x6800);
    assert_eq!(SLOT_MAX_DSQS, 1025);
    assert_eq!(slot_nr_dsqs(8), 9);
    assert_eq!(slot_nr_dsqs(1024), 1025);
    assert_eq!(
        SLOT_BASE,
        crate::bpf_intf::flow_consts_FLOW_SLOT_BASE as u64
    );
    assert_eq!(
        SLOT_OVERFLOW,
        crate::bpf_intf::flow_consts_FLOW_SLOT_OVERFLOW as u64
    );
}

/// Local trips cover own queue then overflow in drain order.
#[test]
fn local_trips_cover_own_then_overflow() {
    assert_eq!(local_trip_dsqs(0), [0x6000, 0x6800]);
    assert_eq!(local_trip_dsqs(5), [0x6005, 0x6800]);
}

/// Insert rests pinned and dead CPUs in overflow with fail closed.
#[test]
fn insert_dsq_rests_pinned_in_overflow() {
    assert_eq!(insert_dsq(0, true, 8), SLOT_OVERFLOW);
    assert_eq!(insert_dsq(-1, false, 8), SLOT_OVERFLOW);
    assert_eq!(insert_dsq(8, false, 8), SLOT_OVERFLOW);
    assert_eq!(insert_dsq(1024, false, 2048), SLOT_OVERFLOW);
    assert_eq!(insert_dsq(3, false, 8), slot_cpu_dsq(3));
    assert_eq!(insert_dsq(0, false, 8), slot_cpu_dsq(0));
}

/// Trip cap holds at D with own cap at 12 under budget 32.
#[test]
fn slot_cap_holds_at_d() {
    assert_eq!(slot_cap(32), SLOT_D);
    assert_eq!(slot_cap(2), 2);
    assert_eq!(slot_cap(0), 0);
    assert_eq!(slot_own_cap(32), SLOT_OWN_CAP);
    assert_eq!(slot_own_cap(32), 12);
    assert_eq!(slot_own_cap(0), 0);
    assert_eq!(slot_own_cap(1), 1);
    assert_eq!(slot_own_cap(100), 12);
}

fn live_task(cpu: usize, nr: usize) -> PendingTask {
    PendingTask {
        allowed: (0..nr).map(|c| c == cpu).collect(),
        exiting: false,
        live: true,
        fail: false,
    }
}

/// Drain skips a dead head with progress and no stall.
#[test]
fn slot_drain_skips_dead_head() {
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

/// Drain skips a failed move with progress and keeps order.
#[test]
fn slot_drain_skips_failed_move_with_progress() {
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

/// Drain respects cap plus base and keeps queue order.
#[test]
fn slot_drain_respects_cap_plus_base() {
    let mut q: VecDeque<PendingTask> = (0..6).map(|_| live_task(0, 2)).collect();
    let moved = slot_drain_model(&mut q, 0, 4, 0);
    assert_eq!(moved, 4);
    assert_eq!(q.len(), 2);
    let mut q2: VecDeque<PendingTask> = (0..6).map(|_| live_task(0, 2)).collect();
    let moved2 = slot_drain_model(&mut q2, 0, 32, 30);
    assert_eq!(moved2, 2);
    assert_eq!(q2.len(), 4);
}

/// Drain skips foreign tasks with the mask and moves local ones.
#[test]
fn slot_drain_keeps_mask_wins() {
    let mut q = VecDeque::from([live_task(1, 2), live_task(0, 2)]);
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 1);
    assert_eq!(q.len(), 1);
}

/// Drain stops after 4 misses with no full scan.
#[test]
fn slot_drain_stops_at_miss_cap() {
    let mut q: VecDeque<PendingTask> = (0..5)
        .map(|_| PendingTask {
            live: false,
            ..live_task(0, 2)
        })
        .chain(std::iter::once(live_task(0, 2)))
        .collect();
    let moved = slot_drain_model(&mut q, 0, SLOT_BUDGET, 0);
    assert_eq!(moved, 0);
    assert_eq!(q.len(), 6);
}

/// Steal need holds 1 when idle empty else 2.
#[test]
fn steal_need_holds_idle_empty_fast_path() {
    assert_eq!(steal_need(true), 1);
    assert_eq!(steal_need(false), STEAL_MIN_DEPTH);
    assert_eq!(steal_need(false), 2);
}

/// First donor keeps the first peer at or past need with wrap.
#[test]
fn steal_first_donor_keeps_first() {
    let depths = vec![0, 0, 3, 1, 0, 0, 0, 0];
    assert_eq!(steal_first_donor(0, 8, 2, &depths), Some(slot_cpu_dsq(2)));
    assert_eq!(steal_first_donor(0, 8, 4, &depths), None);
    let wrap = vec![2, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(steal_first_donor(6, 8, 1, &wrap), Some(slot_cpu_dsq(0)));
    assert_eq!(steal_first_donor(0, 1, 1, &[5]), None);
}

/// Window holds work when own or overflow is non empty.
#[test]
fn window_gate_covers_local_only() {
    assert!(window_has_work(true, false));
    assert!(window_has_work(false, true));
    assert!(window_has_work(true, true));
    assert!(!window_has_work(false, false));
}

/// May run checks live range and mask with fail closed.
#[test]
fn may_run_on_holds() {
    assert!(may_run_on(0, &[true, false]));
    assert!(!may_run_on(1, &[true, false]));
    assert!(!may_run_on(-1, &[true]));
    assert!(!may_run_on(0, &[]));
    assert!(may_run_on_live(0, &[true], 2));
    assert!(!may_run_on_live(5, &[true, true], 2));
}
