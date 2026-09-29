// SPDX-License-Identifier: GPL-2.0
//! Loopback dashboard server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the disabled dashboard entry kept as a stability shim. Older
//! harnesses still spawn this thread, so the entry drains the stop flag
//! only with no socket and no port use. Counters stay on the stats
//! server only.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Disabled dashboard start with no serve.
/// Drains the stop flag only with no socket and no port use. Kept so
/// the spawn site never churns; remove both together if the spawn
/// ever goes.
pub fn start(shutdown: Arc<AtomicBool>) {
    let _ = shutdown;
}
