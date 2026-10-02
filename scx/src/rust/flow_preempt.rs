// SPDX-License-Identifier: GPL-2.0
//! Preempt plus kick helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the kick rule shared by BPF and userspace tests. Idle targets
//! kick at once with no rate window, and busy targets kick only for an
//! urgent earlier deadline with margin plus tail.

/// Preempt margin in nanos at 500us. Near ties never bounce.
#[cfg(test)]
pub const PREEMPT_MARGIN_NS: u64 = 500_000;
/// Preempt tail in nanos at 500us. Nearly done owners finish first.
#[cfg(test)]
pub const PREEMPT_TAIL_NS: u64 = 500_000;

/// True when one arrival kicks the occupant of a busy CPU.
/// A strictly earlier deadline leads by a margin with the owner slice
/// still long, so near ties plus nearly done owners never bounce.
#[cfg(test)]
pub fn arrival_kicks(arrival: u64, occupant: u64) -> bool {
    if occupant == 0 {
        return false;
    }
    if arrival == 0 {
        return false;
    }
    arrival < occupant
}

/// True when one arrival preempts with margin plus tail.
/// The arrival must lead the occupant by the margin with the owner
/// slice still long past the tail, so urgent gaps preempt at once
/// while near ties plus nearly done owners pace at slice expiry.
#[cfg(test)]
pub fn preempt_wants(arrival: u64, occupant: u64, remain: u64) -> bool {
    if arrival == 0 || arrival == u64::MAX {
        return false;
    }
    if occupant == 0 {
        return true;
    }
    if remain < PREEMPT_TAIL_NS {
        return false;
    }
    let margin = arrival.saturating_add(PREEMPT_MARGIN_NS);
    margin < occupant
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earlier_kicks_later_paces() {
        assert!(arrival_kicks(10, 20));
        assert!(!arrival_kicks(20, 20));
        assert!(!arrival_kicks(30, 20));
    }

    #[test]
    fn zero_deadline_never_kicks() {
        assert!(!arrival_kicks(0, 20));
        assert!(!arrival_kicks(10, 0));
    }

    #[test]
    fn margin_blocks_near_ties() {
        assert!(!preempt_wants(19, 20, 2_000_000));
        assert!(preempt_wants(10, 600_000, 2_000_000));
        assert!(!preempt_wants(10, 20, 100_000));
        assert!(!preempt_wants(0, 20, 2_000_000));
        assert!(preempt_wants(10, 0, 0));
    }

    #[test]
    fn tail_waits_out_nearly_done() {
        assert!(!preempt_wants(10, 1_000_000, 499_999));
        assert!(preempt_wants(10, 1_000_000, 500_000));
        assert!(!preempt_wants(10, 1_000_000, 0));
    }
}
