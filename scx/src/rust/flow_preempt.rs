// SPDX-License-Identifier: GPL-2.0
//! Kick rule helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the busy kick rule shared by tests and docs.
//! The BPF busy path validates the occupant CPU before the compare,
//! then compares the arrival key against the occupant key
//! under one RCU pass, then kicks at once for a strictly earlier
//! arrival. Equal or later arrivals pace at slice expiry with no
//! window and no shorten. A zero occupant deadline means no order
//! yet, so the arrival paces with no kick. Parked arrivals send
//! idle kicks only with no busy kick ever. Rust mirrors are read only
//! predicates. See enqueue.bpf.c for the kick order.

/// True when one arrival preempts the busy occupant.
/// Needs a strictly earlier deadline, so equal arrivals pace at slice
/// expiry and later arrivals wait their turn in deadline order.
/// A zero occupant deadline never preempts, since no order exists yet.
#[cfg(test)]
pub fn preempt_earlier(new_deadline: u64, occ_deadline: u64) -> bool {
    if occ_deadline == 0 {
        return false;
    }
    crate::flow_edf::time_before(new_deadline, occ_deadline)
}

/// True when the occupant CPU validates for a preempt compare.
/// Needs the trusted task CPU to match the enqueue target, so a
/// migrated occupant never kicks the wrong CPU.
#[cfg(test)]
pub fn preempt_cpu_valid(trusted_cpu: i32, target: i32) -> bool {
    trusted_cpu == target
}

/// True when one arrival may kick a busy CPU.
/// Open arrivals compare keys for a strictly earlier win, while
/// parked arrivals stay idle only with no busy kick ever.
#[cfg(test)]
pub fn may_kick_busy(parked: bool) -> bool {
    !parked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_arrival_preempts() {
        assert!(preempt_earlier(100, 200));
    }

    #[test]
    fn equal_arrival_paces_at_expiry() {
        assert!(!preempt_earlier(200, 200));
    }

    #[test]
    fn later_arrival_waits_its_turn() {
        assert!(!preempt_earlier(300, 200));
    }

    #[test]
    fn wrap_keeps_kick_order() {
        assert!(preempt_earlier(u64::MAX, 1));
        assert!(!preempt_earlier(1, u64::MAX));
    }

    #[test]
    fn zero_occupant_never_preempts() {
        assert!(!preempt_earlier(100, 0));
        assert!(!preempt_earlier(0, 0));
        assert!(!preempt_earlier(u64::MAX, 0));
    }

    #[test]
    fn migrated_occupant_never_kicks_wrong_cpu() {
        assert!(preempt_cpu_valid(3, 3));
        assert!(!preempt_cpu_valid(2, 3));
        assert!(!preempt_cpu_valid(-1, 3));
        assert!(!preempt_cpu_valid(3, -1));
    }

    #[test]
    fn parks_stay_idle_only() {
        assert!(may_kick_busy(false));
        assert!(!may_kick_busy(true));
    }
}
