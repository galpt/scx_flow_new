// SPDX-License-Identifier: GPL-2.0
//! Kick rate helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the busy kick rate helpers shared by tests and docs.

/// Busy kick window in nanos at 1ms.
#[cfg(test)]
pub const RATE_WINDOW_NS: u64 = 1_000_000;

/// True when one busy kick may run.
/// Zero last always wins with wrap, so the first kick never waits.
/// Later kicks need one full window since the last win.
#[cfg(test)]
pub fn rate_ok(now: u64, last: u64) -> bool {
    if last == 0 {
        return true;
    }
    now.wrapping_sub(last) >= RATE_WINDOW_NS
}
