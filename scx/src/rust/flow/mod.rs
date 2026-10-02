// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler helpers facade.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Reexports the slice, deadline, preempt, and runtime helpers.
//! Tests reach the mirrors through this facade, so every reexport is used.

pub mod cgrp;
pub mod edf;
pub mod preempt;
pub mod runtime;
pub mod select;
pub mod slice;
/* Test-only queue id mirror with no production use, so it stays out of */
/* the binary and only builds for tests. */
#[cfg(test)]
pub mod slot;

pub use self::cgrp::HINT_MAX;
pub use self::edf::*;
#[cfg(test)]
pub use self::preempt::*;
#[cfg(test)]
pub use self::runtime::*;
pub use self::slice::*;
