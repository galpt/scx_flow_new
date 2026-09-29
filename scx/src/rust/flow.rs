// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler helpers facade.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Reexports the slice, deadline, placement, and queue helpers.
//! Tests reach the mirrors through this facade, so every reexport is used.
//! The hint timer stays out of the facade with the deadline timer
//! winning here, so test builds keep one timer name with no clash.
//! The hint table helper stays out too with direct path use in tests.

pub use crate::flow_cgrp::HINT_MAX;
pub use crate::flow_edf::*;
#[cfg(test)]
pub use crate::flow_preempt::*;
#[cfg(test)]
pub use crate::flow_runtime::*;
#[cfg(test)]
pub use crate::flow_select::*;
pub use crate::flow_slice::*;
pub use crate::flow_slot::*;
