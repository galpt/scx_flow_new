// SPDX-License-Identifier: GPL-2.0
//! Virtual time helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the wrap safe virtual time helpers shared by tests and docs.

/// Bound of moved tasks in one pass.
pub const DISPATCH_BATCH: u32 = 32;

/// True when the first time is before the second with wrap safety.
/// The signed diff keeps order across the u64 wrap with no extra branch.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Advance virtual time by scaled runtime.
/// The sum wraps with the clock, so long runs stay ordered with no check.
#[cfg(test)]
pub fn vruntime_add(v: u64, delta: u64) -> u64 {
    v.wrapping_add(delta)
}

/// Max of two virtual times with wrap safety.
/// The later time wins, so the frontier never moves backward.
#[cfg(test)]
pub fn frontier_max(old: u64, next: u64) -> u64 {
    if time_before(old, next) { next } else { old }
}

/// Frontier for an idle CPU from the waking virtual time.
/// The caller keeps the old frontier when the waking value is zero.
#[cfg(test)]
pub fn frontier_idle(waking_v: u64) -> u64 {
    waking_v
}

/// Guarded idle frontier.
/// Keeps the old frontier when the waking value is zero.
#[cfg(test)]
pub fn frontier_idle_guarded(old: u64, waking_v: u64) -> u64 {
    if waking_v == 0 {
        old
    } else {
        frontier_idle(waking_v)
    }
}

/// Frontier step for a stop.
/// BPF keeps one max with no queue read. Placement and dispatch never read
/// the frontier, so the queued and runnable flags stay for the model only.
/// The step mirrors the BPF max with summed depth passed as queued.
#[cfg(test)]
pub fn frontier_step(old: u64, new_v: u64, runnable: bool, queued: u64) -> u64 {
    let _ = (runnable, queued);
    frontier_max(old, new_v)
}
