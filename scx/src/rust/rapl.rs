// SPDX-License-Identifier: GPL-2.0
//! Package energy reads for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the disabled energy probe. Reads stay off with no sysfs use,
//! so the scheduler never pays for energy sampling.

/// Disabled energy reader with no open path.
/// Open always returns None, so the probe stays parked.
pub struct RaplReader;

impl RaplReader {
    /// Open the default package zone with no read.
    /// Returns None always with serving disabled.
    pub fn open_default() -> Option<Self> {
        None
    }
}
