// SPDX-License-Identifier: GPL-2.0
//! Duty admission helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the duty average, fast lane, and probation helpers.
//! The BPF admit path lives in enqueue.bpf.c with enable in
//! lifecycle.bpf.c, and this file mirrors the lane predicates.

/// Duty average shift at alpha 1 over 8.
pub const DUTY_SHIFT: u32 = 3;
/// Fast lane duty under 15 percent.
pub const DUTY_FAST: u8 = 38;
/// Batch class duty at 50 percent.
pub const DUTY_BATCH: u8 = 128;
/// Burst instant value for short runnable segments.
#[cfg(test)]
pub const DUTY_BURST_INST: u8 = 64;
/// Probation wake cycles for fresh tasks.
pub const PROB_CYCLES: u8 = 2;
/// Starvation floor in nanos at 1.5ms.
pub const STARVE_NS: u64 = 1_500_000;

/// Duty step with alpha 1 over 8 and a burst allowance.
/// Voluntary stops decay toward zero. Short runnable bursts climb gently
/// toward 64, and long runnable segments climb toward 255.
#[cfg(test)]
pub fn duty_step(duty: u8, runnable: bool, delta_ns: u64) -> u8 {
    let inst: u32 = if !runnable {
        0
    } else if delta_ns <= STARVE_NS {
        DUTY_BURST_INST as u32
    } else {
        255
    };
    let d = duty as u32;
    if inst >= d {
        (d + ((inst - d) >> DUTY_SHIFT)) as u8
    } else {
        (d - ((d - inst) >> DUTY_SHIFT)) as u8
    }
}

/// Wake cycles left in one probation byte.
/// Fresh tasks hold two cycles, and each low duty wake spends one.
#[cfg(test)]
pub fn prob_count(prob: u8) -> u8 {
    prob & 0x03
}

/// True when the last stop was a voluntary sleep.
/// Bit 7 carries the signal with no extra field.
#[cfg(test)]
pub fn prob_vol(prob: u8) -> bool {
    prob & 0x80 != 0
}

/// Probation byte from cycles plus sleep flag.
/// Counts stay in the low bits with the flag kept apart.
#[cfg(test)]
pub fn prob_make(count: u8, vol: bool) -> u8 {
    let mut v = count & 0x03;
    if vol {
        v |= 0x80;
    }
    v
}

/// True when one arrival may use the fast lane.
/// Needs a normal policy with low duty, a wakeup with the sleep flag, or a
/// preempt flagged arrival under half duty past probation. Kernel urgency
/// with low duty bypasses probation alone for normal tasks only with fast
/// room else deadline. Mirrors the BPF lane check with no probe and no
/// divide. Wakeup is the enqueue flag and sleep is the probation flag, so
/// both must hold for the voluntary path with no combined shortcut.
#[cfg(test)]
pub fn fast_eligible(
    policy_normal: bool,
    prob: u8,
    duty: u8,
    wakeup: bool,
    preempt: bool,
    urgent: bool,
) -> bool {
    if !policy_normal {
        return false;
    }
    if urgent && duty < DUTY_FAST {
        return true;
    }
    if prob_count(prob) != 0 {
        return false;
    }
    duty < DUTY_FAST || (wakeup && prob_vol(prob)) || (preempt && duty < DUTY_BATCH)
}

/// Next probation byte after one sleep wake arrival.
/// Spends one cycle only for voluntary wakes under 15 percent duty.
#[cfg(test)]
pub fn prob_tick(prob: u8, wakeup: bool, duty: u8) -> u8 {
    if prob_count(prob) != 0 && wakeup && prob_vol(prob) && duty < DUTY_FAST {
        prob_make(prob_count(prob) - 1, true)
    } else {
        prob
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_decays_duty() {
        let mut d = 200u8;
        for _ in 0..40 {
            d = duty_step(d, false, 0);
        }
        assert!(d < DUTY_FAST);
    }

    #[test]
    fn spin_climbs_duty() {
        let mut d = 0u8;
        for _ in 0..60 {
            d = duty_step(d, true, 5_000_000);
        }
        assert!(d >= DUTY_BATCH);
    }

    #[test]
    fn burst_climbs_gently() {
        let d = duty_step(0, true, 1_000_000);
        assert_eq!(d, (64u32 >> 3) as u8);
    }

    #[test]
    fn probation_needs_two_low_wakes() {
        let fresh = prob_make(PROB_CYCLES, true);
        assert!(!fast_eligible(true, fresh, 0, true, false, false));
        let one = prob_tick(fresh, true, 0);
        assert_eq!(prob_count(one), 1);
        let done = prob_tick(one, true, 0);
        assert!(fast_eligible(true, done, 0, true, false, false));
    }

    #[test]
    fn high_duty_blocks_without_voluntary_wake() {
        let done = prob_make(0, false);
        assert!(!fast_eligible(true, done, 200, false, false, false));
        assert!(!fast_eligible(true, done, 200, true, false, false));
        let sleepy = prob_make(0, true);
        assert!(fast_eligible(true, sleepy, 200, true, false, false));
        assert!(!fast_eligible(true, sleepy, 200, false, false, false));
        assert!(!fast_eligible(false, sleepy, 0, true, false, false));
    }

    #[test]
    fn voluntary_needs_wakeup_and_sleep_flag() {
        let sleepy = prob_make(0, true);
        let awake = prob_make(0, false);
        assert!(fast_eligible(true, sleepy, 200, true, false, false));
        assert!(!fast_eligible(true, awake, 200, true, false, false));
        assert!(!fast_eligible(true, sleepy, 200, false, false, false));
        assert!(!fast_eligible(true, awake, 200, false, false, false));
        assert!(fast_eligible(true, awake, 0, false, false, false));
        assert!(fast_eligible(
            true,
            awake,
            DUTY_FAST - 1,
            false,
            false,
            false
        ));
        assert!(!fast_eligible(true, awake, DUTY_FAST, false, false, false));
    }

    #[test]
    fn preempt_lane_opens_under_half_duty() {
        let done = prob_make(0, false);
        assert!(fast_eligible(true, done, 100, false, true, false));
        assert!(fast_eligible(
            true,
            done,
            DUTY_BATCH - 1,
            false,
            true,
            false
        ));
        assert!(!fast_eligible(true, done, 100, false, false, false));
        assert!(!fast_eligible(true, done, DUTY_BATCH, false, true, false));
        assert!(!fast_eligible(true, done, 200, false, true, false));
        assert!(!fast_eligible(false, done, 0, false, true, false));
        let fresh = prob_make(PROB_CYCLES, true);
        assert!(!fast_eligible(true, fresh, 0, false, true, false));
    }

    #[test]
    fn urgent_bypass_opens_probation_under_fast_duty() {
        let fresh = prob_make(PROB_CYCLES, true);
        assert!(fast_eligible(true, fresh, 0, false, false, true));
        assert!(fast_eligible(
            true,
            fresh,
            DUTY_FAST - 1,
            false,
            false,
            true
        ));
        assert!(!fast_eligible(true, fresh, DUTY_FAST, false, false, true));
        assert!(!fast_eligible(true, fresh, 200, false, false, true));
        assert!(!fast_eligible(false, fresh, 0, false, false, true));
        let done = prob_make(0, false);
        assert!(fast_eligible(true, done, 0, false, false, true));
        assert!(!fast_eligible(true, done, 200, false, false, true));
    }
}
