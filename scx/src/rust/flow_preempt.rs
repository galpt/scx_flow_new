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

/// True when the first time is before the second with wrap safety.
/// Mirrors BPF flow_time_before with the signed diff, so order holds
/// across the u64 wrap with no branch.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// True when one arrival kicks the occupant of a busy CPU.
/// A strictly earlier deadline kicks, so equal or later arrivals pace
/// at slice expiry. A zero arrival or occupant means no order yet, so
/// no kick. A max arrival fails closed, so a wrapped sum never kicks.
/// Order uses wrap safe time before, so the check holds across wrap.
#[cfg(test)]
pub fn arrival_kicks(arrival: u64, occupant: u64) -> bool {
    if occupant == 0 {
        return false;
    }
    if arrival == 0 || arrival == u64::MAX {
        return false;
    }
    time_before(arrival, occupant)
}

/// True when one arrival preempts with margin plus tail.
/// The arrival must lead the occupant strictly with the margin also
/// strictly before, so near ties never bounce. The owner must have
/// started with remaining slice strictly past the tail, so nearly done
/// owners finish instead of taking a kick. A zero occupant deadline or
/// a zero owner start means no order yet, so no kick. A max arrival or
/// a saturated margin fails closed. Remain holds the owner end minus
/// now saturating, so remain must exceed the tail strictly. Order uses
/// wrap safe time before throughout.
#[cfg(test)]
pub fn preempt_wants(arrival: u64, occupant: u64, remain: u64, occ_start: u64) -> bool {
    if arrival == 0 || arrival == u64::MAX {
        return false;
    }
    if occupant == 0 {
        return false;
    }
    if !time_before(arrival, occupant) {
        return false;
    }
    let margin = arrival.saturating_add(PREEMPT_MARGIN_NS);
    if margin == u64::MAX {
        return false;
    }
    if !time_before(margin, occupant) {
        return false;
    }
    if occ_start == 0 {
        return false;
    }
    if remain <= PREEMPT_TAIL_NS {
        return false;
    }
    true
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
        assert!(!arrival_kicks(u64::MAX, 20));
    }

    #[test]
    fn wrap_uses_signed_order() {
        assert!(time_before(10, 20));
        assert!(!time_before(20, 20));
        assert!(!time_before(20, 10));
    }

    #[test]
    fn margin_blocks_near_ties() {
        assert!(!preempt_wants(19, 20, 2_000_000, 1));
        assert!(preempt_wants(10, 600_000, 2_000_000, 1));
        assert!(!preempt_wants(10, 20, 100_000, 1));
        assert!(!preempt_wants(0, 20, 2_000_000, 1));
        assert!(!preempt_wants(10, 0, 0, 1));
        assert!(!preempt_wants(10, 600_000, 2_000_000, 0));
        assert!(!preempt_wants(u64::MAX, 600_000, 2_000_000, 1));
    }

    #[test]
    fn tail_waits_out_nearly_done() {
        assert!(!preempt_wants(10, 1_000_000, 499_999, 1));
        assert!(!preempt_wants(10, 1_000_000, 500_000, 1));
        assert!(preempt_wants(10, 1_000_000, 500_001, 1));
        assert!(!preempt_wants(10, 1_000_000, 0, 1));
    }
}
