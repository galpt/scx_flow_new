// SPDX-License-Identifier: GPL-2.0
//! Deadline helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the wrap safe deadline helpers shared by tests and docs.
//! The BPF deadline lives in enqueue.bpf.c with the step in
//! intf.h, and this file mirrors the order predicates.

/// Bound of moved tasks in one pass.
pub const DISPATCH_BATCH: u32 = 32;
/// Starvation floor in nanos at 2ms, twice the fixed quantum.
pub const STARVE_NS: u64 = 2_000_000;

/// True when the first time is before the second with wrap safety.
/// The signed diff keeps order across the u64 wrap with no extra branch.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// Later of two times with wrap safety.
/// The later time wins, so a fresh deadline never trails the clock.
#[cfg(test)]
pub fn time_max(a: u64, b: u64) -> u64 {
    if time_before(a, b) { b } else { a }
}

/// Next deadline from the later of now and the last deadline.
/// A long sleep never earns credit, and a back to back arrival queues
/// behind its own last deadline with one step per arrival.
#[cfg(test)]
pub fn deadline_next(last: u64, now: u64, weight: u32) -> u64 {
    time_max(last, now).wrapping_add(crate::flow_slice::deadline_step(weight))
}

/// True when one queued task waited past the 2ms floor.
/// Unknown stamps never count, so fresh tasks miss past.
#[cfg(test)]
pub fn starved(wait_at: u64, now: u64) -> bool {
    if wait_at == 0 || time_before(now, wait_at) {
        return false;
    }
    now - wait_at > STARVE_NS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_holds_later_time() {
        assert_eq!(time_max(10, 20), 20);
        assert_eq!(time_max(20, 10), 20);
    }

    #[test]
    fn fresh_arrival_anchors_past_now() {
        assert_eq!(deadline_next(0, 10_000_000, 100), 11_000_000);
    }

    #[test]
    fn sleep_earns_no_credit() {
        assert_eq!(deadline_next(1_000, 10_000_000, 100), 11_000_000);
    }

    #[test]
    fn back_to_back_queues_behind_last() {
        assert_eq!(deadline_next(10_000_000, 9_000_000, 100), 11_000_000);
        assert_eq!(deadline_next(10_000_000, 9_000_000, 1000), 10_100_000);
    }

    #[test]
    fn wrap_keeps_order() {
        assert!(time_before(u64::MAX, 1));
        assert_eq!(time_max(u64::MAX, 1), 1);
    }

    #[test]
    fn starve_needs_old_stamp() {
        assert!(starved(100, 100 + STARVE_NS + 1));
        assert!(!starved(100, 100 + STARVE_NS));
        assert!(!starved(0, u64::MAX));
        assert!(!starved(200, 100));
    }
}
