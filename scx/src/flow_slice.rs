// SPDX-License-Identifier: GPL-2.0
//! Slice helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the fixed slice shared by BPF and userspace with no knob.

/// Fixed slice in nanos at 1ms.
pub const SLICE_NS: u64 = 1_000_000;
