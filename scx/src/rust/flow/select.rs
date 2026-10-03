// SPDX-License-Identifier: GPL-2.0
//! Placement helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the idle plus previous plus shared placement model with the
//! slowest sufficient pick plus near minimum tiebreak shared by BPF and
//! userspace tests. The BPF placement lives in select_cpu.bpf.c, and
//! this file mirrors the order with no map use.

/// Bound of the shared scan at 8 peers. Fixed with no knob.
#[cfg(test)]
pub const SHARED_SCAN_BOUND: u32 = 8;
/// Near minimum window in capacity units at 64. Peers within this
/// distance of the best defer to the smallest minimum.
#[cfg(test)]
pub const NEAR_MIN_WINDOW: u32 = 64;

/// Drain nanos of one queue depth as slices times the quantum.
/// Saturates on wrap, so a huge depth clamps instead of wrapping to
/// an idle view.
#[cfg(test)]
pub fn drain_ns(depth: u64) -> u64 {
    depth.saturating_mul(crate::flow::slice::QUANTUM_NS)
}

/// True when one CPU can finish its drain before a deadline.
/// A zero deadline means no order yet, so every CPU meets.
#[cfg(test)]
pub fn cpu_meets(depth: u64, deadline: u64, now: u64) -> bool {
    if deadline == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_ns(depth));
    ready <= deadline
}

/// True when one CPU can finish its drain before a fair time.
/// Mirrors the deadline check for the fair key.
#[cfg(test)]
pub fn cpu_meets_fair(depth: u64, vtime: u64, now: u64) -> bool {
    if vtime == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_ns(depth));
    ready <= vtime
}

/// Placement pick among idle plus previous plus shared with fair tiebreak.
/// Idle wins first, then the previous CPU when it drains before the
/// deadline, then the slowest sufficient shared CPU with near minimum
/// tiebreak on the smallest minimum vruntime. Peers within 64 capacity
/// units of the best count as tied, so lagging CPUs take work first.
/// Test-only mirror with no map use where the BPF pass scans at most
/// eight peers from a cursor, while this mirror walks the passed live
/// slice in order. Callers pass host-sized slices within the 512 CPU
/// bound, so the walk stays short with no extra cap here. Units plus
/// minimums run parallel to live with base plus zero on short slices.
/// Returns minus one when no allowed CPU is live.
#[cfg(test)]
pub fn place(
    idle: &[i32],
    prev: i32,
    allowed: &[i32],
    live: &[i32],
    depths: &[u64],
    units: &[u32],
    mins: &[u64],
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
    let mut best: i32 = -1;
    let mut best_units: u32 = u32::MAX;
    let mut best_min: u64 = u64::MAX;
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
        let idx = live.iter().position(|c| *c == *cpu).unwrap_or(usize::MAX);
        let depth = depths.get(idx).copied().unwrap_or(0);
        if !cpu_meets(depth, deadline, now) {
            continue;
        }
        let unit = units.get(idx).copied().unwrap_or(1024);
        let min = mins.get(idx).copied().unwrap_or(0);
        if best == -1 {
            best = *cpu;
            best_units = unit;
            best_min = min;
            continue;
        }
        if unit.saturating_add(NEAR_MIN_WINDOW) < best_units {
            best = *cpu;
            best_units = unit;
            best_min = min;
            continue;
        }
        if unit > best_units.saturating_add(NEAR_MIN_WINDOW) {
            continue;
        }
        if min > best_min {
            continue;
        }
        if min == best_min && *cpu >= best {
            continue;
        }
        if unit < best_units {
            best_units = unit;
        }
        best_min = min;
        best = *cpu;
    }
    if best != -1 {
        return best;
    }
    if allowed.contains(&prev) && live.contains(&prev) {
        return prev;
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units(n: usize) -> Vec<u32> {
        vec![1024; n]
    }

    fn mins(n: usize) -> Vec<u64> {
        vec![0; n]
    }

    #[test]
    fn idle_wins_first() {
        assert_eq!(
            place(
                &[1],
                0,
                &[0, 1],
                &[0, 1],
                &[0, 0],
                &units(2),
                &mins(2),
                100,
                0
            ),
            1
        );
    }

    #[test]
    fn prev_wins_when_it_meets() {
        assert_eq!(
            place(
                &[],
                0,
                &[0, 1],
                &[0, 1],
                &[0, 9],
                &units(2),
                &mins(2),
                100,
                0
            ),
            0
        );
    }

    #[test]
    fn shared_takes_missed_prev() {
        let got = place(&[], 0, &[0, 1], &[0, 1], &[9, 0], &units(2), &mins(2), 5, 0);
        assert_eq!(got, 1);
    }

    #[test]
    fn slowest_sufficient_is_first_id() {
        let got = place(
            &[],
            9,
            &[1, 2, 3],
            &[1, 2, 3],
            &[0, 0, 0],
            &units(3),
            &mins(3),
            100,
            0,
        );
        assert_eq!(got, 1);
    }

    #[test]
    fn near_min_tiebreak_prefers_smallest_min() {
        let got = place(
            &[],
            9,
            &[1, 2, 3],
            &[1, 2, 3],
            &[0, 0, 0],
            &[1024, 1024, 1024],
            &[300, 100, 200],
            100,
            0,
        );
        assert_eq!(got, 2);
    }

    #[test]
    fn clearly_slower_wins_over_min() {
        let got = place(
            &[],
            9,
            &[1, 2],
            &[1, 2],
            &[0, 0],
            &[512, 1024],
            &[900, 100],
            100,
            0,
        );
        assert_eq!(got, 1);
    }

    #[test]
    fn empty_mask_fails_closed() {
        assert_eq!(
            place(&[], 0, &[], &[0, 1], &[0, 0], &units(2), &mins(2), 100, 0),
            -1
        );
    }

    #[test]
    fn shared_scan_stays_bounded() {
        assert_eq!(SHARED_SCAN_BOUND, 8);
        assert_eq!(NEAR_MIN_WINDOW, 64);
    }

    #[test]
    fn fair_meets_mirrors_deadline() {
        assert!(cpu_meets_fair(0, 100, 0));
        assert!(!cpu_meets_fair(9, 5, 0));
    }
}
