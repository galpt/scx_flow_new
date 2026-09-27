// SPDX-License-Identifier: GPL-2.0
//! Kick rule helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the busy kick rule shared by tests and docs.
//! The BPF busy path compares the arrival deadline against the
//! occupant deadline under one RCU pass, then kicks at once for a
//! strictly earlier arrival. Equal or later arrivals pace at slice
//! expiry with no window and no shorten. Rust mirrors are read only
//! predicates. See enqueue.bpf.c for the kick order.

/// True when one arrival preempts the busy occupant.
/// Needs a strictly earlier deadline, so equal arrivals pace at slice
/// expiry and later arrivals wait their turn in deadline order.
#[cfg(test)]
pub fn preempt_earlier(new_deadline: u64, occ_deadline: u64) -> bool {
    crate::flow_edf::time_before(new_deadline, occ_deadline)
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
}
