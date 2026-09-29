// SPDX-License-Identifier: GPL-2.0
//! Loopback dashboard server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the disabled dashboard entry. Serving stays off with no port
//! use, so the scheduler exposes counters through the stats server only.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// Disabled dashboard start with no serve.
/// Drains the stop flag only with no socket and no port use.
pub fn start(shutdown: Arc<AtomicBool>) {
    let _ = shutdown;
}
