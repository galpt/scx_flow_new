/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Slice and estimate helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * The slice is fixed at 1ms with no mean and no knob.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement with no table in BPF.
 */

/* Lower bound of a per task estimate in nanos. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanos. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Fixed slice in nanos with no mean and no knob. */
pub const SLICE_NS: u64 = 1_000_000;
/* Fixed weight used for virtual time scaling. */
#[cfg(test)]
pub const WEIGHT: u64 = 1024;

/*
 * Clamp a per task estimate to the estimate range.
 * The floor keeps the value positive. The ceiling
 * keeps a single long run from shaping later choice.
 */
#[cfg(test)]
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Scale an estimate by weight for virtual time. The
 * fixed weight keeps the value unchanged while the
 * signature allows future weights with no call change.
 */
#[cfg(test)]
pub fn scale_by_weight(est: u64, weight: u32) -> u64 {
    if weight == 0 {
        return est;
    }
    if weight == 1024 {
        return est;
    }
    ((est as u128 * 1024) / weight as u128) as u64
}
