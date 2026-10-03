// SPDX-License-Identifier: GPL-2.0
//! Preempt plus kick plus eligibility helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the kick rule plus the eligibility gate shared by BPF and
//! userspace tests. Idle plus busy targets kick only for eligible
//! arrivals, and busy targets also need an urgent earlier fair time
//! with margin plus tail.

/// Preempt margin in nanos at 100us. Near ties never bounce.
#[cfg(test)]
pub const PREEMPT_MARGIN_NS: u64 = 100_000;
/// Preempt tail in nanos at 100us. Nearly done owners finish first.
#[cfg(test)]
pub const PREEMPT_TAIL_NS: u64 = 100_000;
/// Preempt floor in nanos at 100us. Margin plus tail never drop below this.
#[cfg(test)]
pub const PREEMPT_FLOOR_NS: u64 = 100_000;

/// True when the first time is before the second with wrap safety.
/// Mirrors BPF flow_time_before with the signed diff, so order holds
/// across the u64 wrap with no branch.
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/// True when one arrival kicks the occupant of a busy CPU.
/// A strictly earlier fair time kicks, so equal or later arrivals pace
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

/// True when one vruntime is eligible against the CPU minimum.
/// Mirrors BPF flow_eligible with the 2ms lag bound.
#[cfg(test)]
pub fn eligible(vruntime: u64, min_vruntime: u64, vlag: i32) -> bool {
    crate::flow::edf::eligible(vruntime, min_vruntime, vlag)
}

/// True when one arrival preempts with eligibility plus margin plus tail.
/// The arrival must be eligible against the target minimum, then lead
/// the occupant strictly with the margin also strictly before, so near
/// ties never bounce. The owner must have started with remaining slice
/// strictly past the tail, so nearly done owners finish instead of
/// taking a kick. A zero occupant deadline or a zero owner start means
/// no order yet, so no kick. A max arrival or a saturated margin fails
/// closed. Remain holds the owner end minus now saturating, so remain
/// must exceed the tail strictly. Order uses wrap safe time before
/// throughout.
#[cfg(test)]
pub fn preempt_wants(
    arrival: u64,
    occupant: u64,
    remain: u64,
    occ_start: u64,
    vruntime: u64,
    min_vruntime: u64,
    vlag: i32,
) -> bool {
    if !eligible(vruntime, min_vruntime, vlag) {
        return false;
    }
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

/// True when one idle kick fires for an eligible arrival.
/// Ineligible hogs pace through tiers with no idle jump.
#[cfg(test)]
pub fn idle_kick_wants(vruntime: u64, min_vruntime: u64, vlag: i32) -> bool {
    eligible(vruntime, min_vruntime, vlag)
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
        assert!(!preempt_wants(19, 20, 2_000_000, 1, 0, 0, 0));
        assert!(preempt_wants(10, 600_000, 2_000_000, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 100_010, 2_000_000, 1, 0, 0, 0));
        assert!(preempt_wants(10, 100_011, 2_000_000, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 20, 100_000, 1, 0, 0, 0));
        assert!(!preempt_wants(0, 20, 2_000_000, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 0, 0, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 600_000, 2_000_000, 0, 0, 0, 0));
        assert!(!preempt_wants(u64::MAX, 600_000, 2_000_000, 1, 0, 0, 0));
    }

    #[test]
    fn eligibility_gates_preempt_and_idle() {
        assert!(!preempt_wants(
            10, 600_000, 2_000_000, 1, 5_000_000, 1_000_000, 0
        ));
        assert!(preempt_wants(10, 600_000, 2_000_000, 1, 500, 1_000, 0));
        assert!(idle_kick_wants(500, 1_000, 0));
        assert!(!idle_kick_wants(5_000_000, 1_000_000, 0));
        assert!(eligible(1_000, 1_000, 0));
        assert!(!eligible(1_001, 1_000, 0));
    }

    #[test]
    fn tail_waits_out_nearly_done() {
        assert!(!preempt_wants(10, 1_000_000, 99_999, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 1_000_000, 100_000, 1, 0, 0, 0));
        assert!(preempt_wants(10, 1_000_000, 100_001, 1, 0, 0, 0));
        assert!(!preempt_wants(10, 1_000_000, 0, 1, 0, 0, 0));
    }

    #[test]
    fn floor_stays_at_100us_with_single_kick() {
        assert_eq!(PREEMPT_MARGIN_NS, PREEMPT_FLOOR_NS);
        assert_eq!(PREEMPT_TAIL_NS, PREEMPT_FLOOR_NS);
        assert_eq!(PREEMPT_FLOOR_NS, 100_000);
        assert_eq!(
            PREEMPT_MARGIN_NS,
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64
        );
        assert_eq!(
            PREEMPT_TAIL_NS,
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64
        );
    }
}
