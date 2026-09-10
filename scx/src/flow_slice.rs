/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Slice and estimate helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 * The slice is fixed at 1ms with no knob.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement.
 */

/* Lower bound of a per task estimate in nanos. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanos. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Fixed slice in nanos. */
pub const SLICE_NS: u64 = 1_000_000;
/* Fixed weight used for virtual time scaling. */
#[cfg(test)]
pub const WEIGHT: u64 = 1024;
/* Least nice held in the table. */
#[cfg(test)]
pub const NICE_MIN: i32 = -20;
/* Greatest nice held in the table. */
#[cfg(test)]
pub const NICE_MAX: i32 = 19;
/* Steps per doubling for the weight table. */
#[cfg(test)]
pub const WEIGHT_K: u64 = 8;

/*
 * Weight of each nice level from minus 20 to plus 19.
 * Index is nice plus 20 with center 1024 at nice 0.
 * Values fall as nice rises with 8 steps per doubling,
 * so K is 8. Made as 1024 times 2 to minus nice over 8,
 * rounded. The maker is docs only, the table mirrors
 * the BPF rodata for tests.
 */
#[cfg(test)]
pub const WEIGHT_TABLE: [u16; 40] = [
    5793, 5312, 4871, 4467, 4096, 3756, 3444, 3158, 2896, 2656, 2435, 2233, 2048, 1878, 1722, 1579,
    1448, 1328, 1218, 1117, 1024, 939, 861, 790, 724, 664, 609, 558, 512, 470, 431, 395, 362, 332,
    304, 279, 256, 235, 215, 197,
];

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

/*
 * Nice of one static prio minus 120. The value passes
 * through with no clamp, so out of range stays out of
 * range for the weight fallback with no trap.
 */
#[cfg(test)]
pub fn nice_of(static_prio: i32) -> i32 {
    static_prio - 120
}

/*
 * Weight of one nice level from the table. Out of range
 * maps to 1024 with no trap, so unknown tasks stay
 * neutral.
 */
#[cfg(test)]
pub fn weight_of(nice: i32) -> u32 {
    if nice < NICE_MIN || nice > NICE_MAX {
        return 1024;
    }
    let idx = (nice + 20) as usize;
    WEIGHT_TABLE[idx] as u32
}

/*
 * Weight of one static prio through nice. Combines the
 * two steps, so callers pass the prio once with the same
 * fallback to 1024.
 */
#[cfg(test)]
pub fn weight_of_prio(static_prio: i32) -> u32 {
    weight_of(nice_of(static_prio))
}

/*
 * Cap of one weight in nanos with K bounds. Base is
 * slice times 1024 over weight, held in slice over 8 to
 * slice times 8, so extremes stay bounded with no trap.
 */
#[cfg(test)]
pub fn cap_for_weight(weight: u32, slice: u64) -> u64 {
    if weight == 0 {
        return slice;
    }
    if weight == 1024 {
        return slice;
    }
    if slice == 0 {
        return 0;
    }
    let cap = ((slice as u128 * 1024) / weight as u128) as u64;
    let lo = slice / 8;
    let hi = slice * 8;
    if cap < lo {
        return lo;
    }
    if cap > hi {
        return hi;
    }
    cap
}
