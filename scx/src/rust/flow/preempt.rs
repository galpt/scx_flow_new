// SPDX-License-Identifier: GPL-2.0
//! Preempt and kick helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the kick rule. Idle targets kick at once. Busy targets kick
//! solely for a strictly earlier deadline. Equal or later deadlines
//! wait for slice expiry.

/// True when one arrival kicks the occupant of a busy CPU.
/// A strictly earlier deadline kicks at once. Equal or later deadlines
/// pace at slice expiry. Empty deadlines pace in every case.
pub fn arrival_kicks(arrival: u64, occupant: u64) -> bool {
    if occupant == 0 {
        return false;
    }
    if arrival == 0 {
        return false;
    }
    arrival < occupant
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
    fn empty_deadline_paces() {
        assert!(!arrival_kicks(0, 20));
        assert!(!arrival_kicks(10, 0));
    }
}
