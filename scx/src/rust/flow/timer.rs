// SPDX-License-Identifier: GPL-2.0
//! Decay timer mirror for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF timer.bpf.c with the disabled stale minimum decay.
//! Tier waits wake by direct kick on insert with no timer, so no timer
//! callback runs in the default shape. A stale minimum holds until the
//! next charge and stays bounded by the 2ms lag clamp plus eligibility,
//! so no decay is needed. The decay helper is an intentional no-op kept
//! for veristat plus a future operator wire.
//! Test-only with no map use and no cost.

/// No-op decay of one CPU minimum toward the sample.
/// Mirrors BPF flow_timer_decay disabled shape: returns the current
/// minimum unchanged with no state cost. Callers keep the BPF default
/// with no timer wait and wake by direct kick.
#[cfg(test)]
pub fn decay_noop(cur_min: u64, _sample: u64) -> u64 {
    cur_min
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_stays_noop() {
        assert_eq!(decay_noop(100, 200), 100);
        assert_eq!(decay_noop(0, 0), 0);
        assert_eq!(decay_noop(u64::MAX, 0), u64::MAX);
    }
}
