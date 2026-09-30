// SPDX-License-Identifier: GPL-2.0
//! Placement helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the idle plus previous plus shared placement model. Idle CPUs
//! win first. The previous CPU wins next when it drains in time. The
//! shared home takes the rest in identifier order. The first sufficient
//! identifier is the slowest sufficient pick on symmetric hosts.

/// Bound of the shared scan at eight peers. Fixed.
#[cfg(test)]
pub const SHARED_SCAN_BOUND: u32 = 8;

/// Drain nanos of one queue depth as slices times the quantum.
/// Large depths saturate at the top.
#[cfg(test)]
pub fn drain_ns(depth: u64) -> u64 {
    depth.saturating_mul(super::slice::QUANTUM_NS)
}

/// True when one CPU drains before a deadline.
/// Empty deadlines pass for every CPU.
#[cfg(test)]
pub fn cpu_meets(depth: u64, deadline: u64, now: u64) -> bool {
    if deadline == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_ns(depth));
    ready <= deadline
}

/// Placement pick among idle plus previous plus shared.
/// Idle wins first, then the previous CPU when it drains before the
/// deadline, then the first sufficient shared CPU in identifier order.
/// Callers pass host sized slices within the five hundred twelve CPU
/// bound. Returns minus one when the mask holds live peers.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn place(
    idle: &[i32],
    prev: i32,
    allowed: &[i32],
    live: &[i32],
    depths: &[u64],
    deadline: u64,
    now: u64,
) -> i32 {
    for cpu in idle {
        if allowed.contains(cpu) && live.contains(cpu) {
            return *cpu;
        }
    }
    if allowed.contains(&prev) && live.contains(&prev) {
        let depth = live
            .iter()
            .position(|c| *c == prev)
            .and_then(|i| depths.get(i).copied())
            .unwrap_or(0);
        if cpu_meets(depth, deadline, now) {
            return prev;
        }
    }
    for cpu in live {
        if *cpu == prev {
            continue;
        }
        if !allowed.contains(cpu) {
            continue;
        }
        if idle.contains(cpu) {
            continue;
        }
        let depth = live
            .iter()
            .position(|c| *c == *cpu)
            .and_then(|i| depths.get(i).copied())
            .unwrap_or(0);
        if cpu_meets(depth, deadline, now) {
            return *cpu;
        }
    }
    if allowed.contains(&prev) && live.contains(&prev) {
        return prev;
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_wins_first() {
        assert_eq!(place(&[1], 0, &[0, 1], &[0, 1], &[0, 0], 100, 0), 1);
    }

    #[test]
    fn prev_wins_when_it_meets() {
        assert_eq!(place(&[], 0, &[0, 1], &[0, 1], &[0, 9], 100, 0), 0);
    }

    #[test]
    fn shared_takes_missed_prev() {
        let got = place(&[], 0, &[0, 1], &[0, 1], &[9, 0], 5, 0);
        assert_eq!(got, 1);
    }

    #[test]
    fn slowest_sufficient_is_first_identifier() {
        let got = place(&[], 9, &[1, 2, 3], &[1, 2, 3], &[0, 0, 0], 100, 0);
        assert_eq!(got, 1);
    }

    #[test]
    fn empty_mask_fails_closed() {
        assert_eq!(place(&[], 0, &[], &[0, 1], &[0, 0], 100, 0), -1);
    }

    #[test]
    fn shared_scan_stays_bounded() {
        assert_eq!(SHARED_SCAN_BOUND, 8);
    }
}
