// SPDX-License-Identifier: GPL-2.0
//! Kick rate unit tests for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Covers the 1ms busy rate window and the steal cursor step.

use crate::flow_preempt::*;
use crate::flow_select::*;

/// Zero last always wins with wrap, later kicks need one full window.
#[test]
fn rate_window_holds_1ms() {
    assert!(rate_ok(1_000_000, 0));
    assert!(rate_ok(0, 0));
    assert!(rate_ok(1_000_000, 1_000_000 - 1_000_000));
    assert!(!rate_ok(1_500_000, 1_000_000));
    assert!(rate_ok(2_000_000, 1_000_000));
    assert!(rate_ok(2_000_001, 1_000_000));
    assert_eq!(RATE_WINDOW_NS, 1_000_000);
}

/// Steal start steps one with wrap and rests on small hosts.
#[test]
fn steal_start_steps_one() {
    assert_eq!(steal_start(0, 8), 1);
    assert_eq!(steal_start(7, 8), 0);
    assert_eq!(steal_start(3, 4), 0);
    assert_eq!(steal_start(0, 1), 0);
    assert_eq!(steal_start(0, 0), 0);
}

/// Cursor next steps by 8 with wrap, so passes spread with no hotspot.
#[test]
fn cursor_next_steps_eight() {
    assert_eq!(cursor_next(0, 16), 8);
    assert_eq!(cursor_next(8, 16), 0);
    assert_eq!(cursor_next(7, 8), 7);
    assert_eq!(cursor_next(0, 1), 0);
    assert_eq!(cursor_next(0, 0), 0);
}

/// Steal peers visit bound entries from start with wrap.
#[test]
fn steal_peers_hold_bound() {
    assert_eq!(steal_peers_from(0, 8), vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(steal_peers_from(6, 8), vec![6, 7, 0, 1, 2, 3, 4, 5]);
    assert_eq!(steal_peers_from(0, 8).len(), STEAL_BOUND);
    assert!(steal_peers_from(0, 0).is_empty());
}

/// Select model trusts waker idle, then any idle, prev, then first.
#[test]
fn select_model_holds_order() {
    let allowed = vec![true, true, true, true];
    let idle = vec![false, true, false, false];
    assert_eq!(select_cpu_model(0, 2, &allowed, &idle), Some(1));
    let idle_waker = vec![false, false, true, false];
    assert_eq!(select_cpu_model(0, 2, &allowed, &idle_waker), Some(2));
    let busy = vec![false, false, false, false];
    assert_eq!(select_cpu_model(3, 1, &allowed, &busy), Some(3));
    assert_eq!(select_cpu_model(9, 9, &allowed, &busy), Some(0));
    let none = vec![false, false, false, false];
    assert_eq!(select_cpu_model(0, 1, &none, &busy), None);
}

/// Target pick keeps selected when allowed, else first allowed.
#[test]
fn pick_target_holds() {
    let allowed = vec![true, false, true];
    assert_eq!(pick_target_cpu(0, &allowed), Some(0));
    assert_eq!(pick_target_cpu(1, &allowed), Some(0));
    assert_eq!(pick_target_cpu(9, &allowed), Some(0));
    let none = vec![false, false];
    assert_eq!(pick_target_cpu(0, &none), None);
}

/// Pinned stay keeps the task CPU when allowed.
#[test]
fn stay_target_holds() {
    let allowed = vec![true, true, false];
    assert_eq!(stay_target(0, 1, &allowed), Some(0));
    assert_eq!(stay_target(2, 1, &allowed), Some(1));
    assert_eq!(stay_target(2, 9, &allowed), Some(0));
    let none = vec![false, false];
    assert_eq!(stay_target(0, 1, &none), None);
}

/// Exiting fast path needs an exiting task with the target allowed.
#[test]
fn exiting_target_holds() {
    assert!(exiting_target_ok(true, true));
    assert!(!exiting_target_ok(true, false));
    assert!(!exiting_target_ok(false, true));
    assert!(!exiting_target_ok(false, false));
}
