// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler helpers facade.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Facade over the cgrp, dispatch, edf, lifecycle, preempt, select,
//! slice, slot, timer, vtime, and weight helpers. Tests reach the
//! mirrors through this facade, so every reexport is used.

pub mod cgrp;
#[cfg(test)]
pub mod dispatch;
pub mod edf;
#[cfg(test)]
pub mod lifecycle;
pub mod preempt;
#[cfg(test)]
pub mod property;
pub mod select;
pub mod slice;
#[cfg(test)]
pub mod timer;
#[cfg(test)]
pub mod vtime;
#[cfg(test)]
pub mod weight;
/* Test-only queue id mirror with no production use, so it stays out of */
/* the binary and only builds for tests. */
#[cfg(test)]
pub mod slot;

pub use self::cgrp::HINT_MAX;
pub use self::edf::*;
#[cfg(test)]
pub use self::preempt::*;
pub use self::slice::*;
