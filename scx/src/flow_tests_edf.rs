// SPDX-License-Identifier: GPL-2.0
//! Virtual time unit tests for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Covers wrap safe compares, vruntime adds, and frontier steps.

use crate::flow_edf::*;

/// Wrap safe compare keeps order across the u64 wrap.
#[test]
fn time_before_holds_wrap() {
    assert!(time_before(0, 1));
    assert!(!time_before(1, 0));
    assert!(!time_before(5, 5));
    assert!(time_before(u64::MAX, 0));
    assert!(!time_before(0, u64::MAX));
    assert!(time_before(u64::MAX - 1, u64::MAX));
}

/// Vruntime add wraps with the clock and stays ordered.
#[test]
fn vruntime_add_wraps() {
    assert_eq!(vruntime_add(10, 5), 15);
    assert_eq!(vruntime_add(u64::MAX, 1), 0);
    assert_eq!(vruntime_add(0, 0), 0);
}

/// Frontier max never moves backward with wrap safety.
#[test]
fn frontier_max_holds() {
    assert_eq!(frontier_max(10, 20), 20);
    assert_eq!(frontier_max(20, 10), 20);
    assert_eq!(frontier_max(5, 5), 5);
    assert_eq!(frontier_max(u64::MAX, 0), 0);
}

/// Idle frontier resets to the waking time with no zero use.
#[test]
fn frontier_idle_guarded_keeps_old_on_zero() {
    assert_eq!(frontier_idle_guarded(100, 0), 100);
    assert_eq!(frontier_idle_guarded(100, 200), 200);
    assert_eq!(frontier_idle(200), 200);
}

/// Frontier step keeps max on runnable or queued work.
#[test]
fn frontier_step_holds() {
    assert_eq!(frontier_step(100, 200, true, 0), 200);
    assert_eq!(frontier_step(200, 100, true, 0), 200);
    assert_eq!(frontier_step(100, 200, false, 3), 200);
    assert_eq!(frontier_step(200, 100, false, 3), 200);
    assert_eq!(frontier_step(100, 200, false, 0), 200);
    assert_eq!(frontier_step(100, 0, false, 0), 100);
}
