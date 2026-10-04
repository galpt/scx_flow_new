// SPDX-License-Identifier: GPL-2.0
//! Fixed slice plus weight helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the knob-free slice plus weight bounds plus the no divide
//! scaler shared by BPF and userspace. Order keys on the fair time of
//! deadline plus virtual deadline, so no nice table is needed here.

/// Fixed slice in nanos at 1ms. Every insert uses this slice.
pub const QUANTUM_NS: u64 = 1_000_000;
/// Base weight with a neutral share.
pub const WEIGHT_BASE: u32 = 128;
/// Least weight admitted.
pub const WEIGHT_MIN: u32 = 1;
/// Largest weight admitted.
pub const WEIGHT_MAX: u32 = 16_384;

/// Clamp one weight into range with fail closed to the nearer bound.
#[cfg(test)]
pub fn weight_clamp(w: u32) -> u32 {
    w.clamp(WEIGHT_MIN, WEIGHT_MAX)
}

/// Combine two shares into one effective share with no divide.
/// Mirrors BPF flow_share_combine with shift right by 7 for divide
/// by 128 plus clamp to range with no wrap.
#[cfg(test)]
pub fn share_combine(task_w: u32, hint_w: u32) -> u32 {
    let t = weight_clamp(task_w);
    let h = weight_clamp(hint_w);
    let eff = ((t as u64) * (h as u64)) >> 7;
    eff.clamp(WEIGHT_MIN as u64, WEIGHT_MAX as u64) as u32
}

/// Effective share of one task plus hint with neutral on zero.
/// Mirrors BPF flow_task_effective_weight with zero mapped to base
/// before the shared combine with no special case at the caller.
#[cfg(test)]
pub fn task_effective_weight(task_w: u32, hint_w: u32) -> u32 {
    let t = if task_w == 0 { WEIGHT_BASE } else { task_w };
    let h = if hint_w == 0 { WEIGHT_BASE } else { hint_w };
    share_combine(t, h)
}

/// Scaled service for one delta at one weight with banded shifts.
/// Mirrors BPF flow_scaled_delta with no divide and saturation.
#[cfg(test)]
pub fn scaled_delta(delta: u64, weight: u32) -> u64 {
    crate::flow::edf::scaled_delta(delta, weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_is_one_millisecond() {
        assert_eq!(QUANTUM_NS, 1_000_000);
    }

    #[test]
    fn weights_clamp_to_range() {
        assert_eq!(weight_clamp(0), WEIGHT_MIN);
        assert_eq!(weight_clamp(128), 128);
        assert_eq!(weight_clamp(99_999), WEIGHT_MAX);
    }

    #[test]
    fn scaler_uses_bands_without_divide() {
        assert_eq!(scaled_delta(1_000_000, 128), 1_000_000);
        assert_eq!(scaled_delta(1_000_000, 16), 8_000_000);
        assert_eq!(scaled_delta(1_000_000, 32), 4_000_000);
        assert_eq!(scaled_delta(1_000_000, 1024), 125_000);
    }

    #[test]
    fn shares_stack_over_128() {
        assert_eq!(share_combine(128, 128), 128);
        assert_eq!(share_combine(128, 32), 32);
        assert_eq!(share_combine(128, 1024), 1024);
        assert_eq!(share_combine(1, 1), 1);
        assert_eq!(share_combine(16_384, 16_384), 16_384);
        assert_eq!(task_effective_weight(0, 0), 128);
        assert_eq!(task_effective_weight(128, 32), 32);
        assert_eq!(task_effective_weight(0, 1024), 1024);
    }
}
