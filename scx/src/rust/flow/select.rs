// SPDX-License-Identifier: GPL-2.0
//! Placement helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the idle plus previous plus shared placement model with the
//! slowest sufficient pick plus near minimum tiebreak shared by BPF and
//! userspace tests. The BPF placement lives in select_cpu.bpf.c, and
//! this file mirrors the order with no map use.

/// Bound of the shared scan at 16 peers. Fixed with no knob.
/// Steal scans 8 to 16 peers proportional to remaining visits.
#[cfg(test)]
pub const SHARED_SCAN_BOUND: u32 = 16;
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

/// Combined drain nanos of local plus node depths with saturation.
/// Mirrors BPF flow_cpu_drain, so a busy node holds the local tier.
#[cfg(test)]
pub fn drain_combined(local: u64, node: u64) -> u64 {
    drain_ns(local).saturating_add(drain_ns(node))
}

/// True when one CPU can finish its drain before a deadline.
/// A zero deadline means no order yet, so every CPU meets. BPF sums
/// local plus node via drain_combined for the tier plus bypass checks,
/// while this single-depth helper serves placement unit tests. Use
/// cpu_meets_combined for tier plus bypass mirrors.
#[cfg(test)]
pub fn cpu_meets(depth: u64, deadline: u64, now: u64) -> bool {
    if deadline == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_ns(depth));
    ready <= deadline
}

/// True when one CPU can finish its combined drain before a deadline.
/// Mirrors BPF flow_cpu_meets with local plus node saturation, so a
/// busy node holds the tier with no wait. A zero deadline meets all.
#[cfg(test)]
pub fn cpu_meets_combined(local: u64, node: u64, deadline: u64, now: u64) -> bool {
    if deadline == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_combined(local, node));
    ready <= deadline
}

/// True when one CPU can finish its drain before a fair time.
/// Mirrors the deadline check for the fair key. BPF sums local plus
/// node via drain_combined for the fair-key tier plus bypass checks,
/// while this single-depth helper serves placement unit tests. Use
/// cpu_meets_fair_combined for tier plus bypass mirrors.
#[cfg(test)]
pub fn cpu_meets_fair(depth: u64, vtime: u64, now: u64) -> bool {
    if vtime == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_ns(depth));
    ready <= vtime
}

/// True when one CPU can finish its combined drain before a fair time.
/// Mirrors BPF flow_cpu_meets_fair with local plus node saturation.
/// A zero fair time means no fair order yet, so the check passes.
#[cfg(test)]
pub fn cpu_meets_fair_combined(local: u64, node: u64, vtime: u64, now: u64) -> bool {
    if vtime == 0 {
        return true;
    }
    let ready = now.saturating_add(drain_combined(local, node));
    ready <= vtime
}

/// Steal window in peers from remaining visits with 8 to 16 bounds.
/// Mirrors BPF flow_steal_one proportional window, so a fresh pass scans
/// sixteen peers while a spent pass scans eight peers with no hotspot.
#[cfg(test)]
pub fn steal_window(visits: u32) -> u32 {
    let remain = 64u32.saturating_sub(visits);
    let window = 8u32.saturating_add(remain >> 3);
    window.clamp(8, 16)
}

/// Saturated backlog of tier queues as local plus node plus machine.
/// Mirrors BPF dispatch steal early-out counts with saturation, so a
/// huge depth clamps instead of wrapping to idle. Visits stay shared.
#[cfg(test)]
pub fn steal_backlog(local: u64, node: u64, machine: u64) -> u64 {
    local.saturating_add(node).saturating_add(machine)
}

/// True when the steal tier skips its peer scan for this pass.
/// Mirrors BPF dispatch saturated early-out, so a globally busy pass
/// with any tier backlog skips up to sixteen peer scans cheaply.
#[cfg(test)]
pub fn steal_should_skip(local: u64, node: u64, machine: u64) -> bool {
    steal_backlog(local, node, machine) != 0
}

/// Placement pick among idle plus previous plus shared with fair tiebreak.
/// Idle wins first, then the previous CPU when it drains before the
/// deadline, then the slowest sufficient shared CPU with near minimum
/// tiebreak on the smallest minimum vruntime. Peers within 64 capacity
/// units of the best count as tied, so lagging CPUs take work first.
/// Test-only mirror with no map use where the BPF pass scans at most
/// sixteen peers from the cursor and skips the busy waker, and this
/// mirror walks the same bounded window from the passed cursor with
/// the same skip. Minimum order uses the wrap safe signed diff like
/// BPF, so the tiebreak holds across the u64 wrap. Callers pass
/// host-sized slices within the 1024 CPU bound with units plus
/// minimums parallel to live. Returns minus one when no allowed CPU
/// is live. Perf stays bounded at sixteen peers with no extra walk.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
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
    this_cpu: i32,
    cursor: u32,
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
    let n = live.len();
    if n > 1 && n <= 1024 {
        let start = ((cursor.wrapping_add(1)) % n as u32) as usize;
        for off in 0..SHARED_SCAN_BOUND as usize {
            if off >= n {
                break;
            }
            let idx = (start + off) % n;
            let cpu = live[idx];
            // The busy waker stays out like BPF, since an idle waker
            // already returned above and a busy waker would only stack.
            if cpu == this_cpu {
                continue;
            }
            if !allowed.contains(&cpu) {
                continue;
            }
            if idle.contains(&cpu) {
                continue;
            }
            let depth = depths.get(idx).copied().unwrap_or(0);
            if !cpu_meets(depth, deadline, now) {
                continue;
            }
            let unit = units.get(idx).copied().unwrap_or(1024);
            let min = mins.get(idx).copied().unwrap_or(0);
            if best == -1 {
                best = cpu;
                best_units = unit;
                best_min = min;
                continue;
            }
            if unit.saturating_add(NEAR_MIN_WINDOW) < best_units {
                best = cpu;
                best_units = unit;
                best_min = min;
                continue;
            }
            if unit > best_units.saturating_add(NEAR_MIN_WINDOW) {
                continue;
            }
            if min != best_min && !crate::flow::edf::time_before(min, best_min) {
                continue;
            }
            if min == best_min && cpu >= best {
                continue;
            }
            if unit < best_units {
                best_units = unit;
            }
            best_min = min;
            best = cpu;
        }
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
                0,
                0,
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
                0,
                99,
                0
            ),
            0
        );
    }

    #[test]
    fn shared_takes_missed_prev() {
        let got = place(
            &[],
            0,
            &[0, 1],
            &[0, 1],
            &[9, 0],
            &units(2),
            &mins(2),
            5,
            0,
            0,
            1,
        );
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
            99,
            2,
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
            99,
            2,
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
            99,
            1,
        );
        assert_eq!(got, 1);
    }

    #[test]
    fn empty_mask_fails_closed() {
        assert_eq!(
            place(
                &[],
                0,
                &[],
                &[0, 1],
                &[0, 0],
                &units(2),
                &mins(2),
                100,
                0,
                99,
                0
            ),
            -1
        );
    }

    #[test]
    fn shared_scan_stays_bounded() {
        assert_eq!(SHARED_SCAN_BOUND, 16);
        assert_eq!(NEAR_MIN_WINDOW, 64);
        // Wrap safe minimum order holds across the u64 wrap.
        assert!(crate::flow::edf::time_before(u64::MAX, 10));
        assert!(!crate::flow::edf::time_before(10, u64::MAX - 10));
        // Busy waker stays out while the cursor window still finds
        // the lagging peer within sixteen.
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
            1,
            2,
        );
        assert_eq!(got, 2);
        // Cursor rotation still visits all peers when the host holds
        // fewer than sixteen CPUs.
        let again = place(
            &[],
            9,
            &[1, 2, 3],
            &[1, 2, 3],
            &[0, 0, 0],
            &units(3),
            &mins(3),
            100,
            0,
            99,
            0,
        );
        assert_eq!(again, 1);
    }

    #[test]
    fn fair_meets_mirrors_deadline() {
        assert!(cpu_meets_fair(0, 100, 0));
        assert!(!cpu_meets_fair(9, 5, 0));
    }

    #[test]
    fn combined_drain_holds_node_busy() {
        assert_eq!(drain_combined(0, 0), 0);
        assert_eq!(drain_combined(1, 1), 2_000_000);
        // Fair-key tier gates local on the fair time with combined drain,
        // so a busy node holds the tier with no wait. Combined helpers
        // mirror BPF flow_cpu_drain with saturation and no double scale.
        assert!(!cpu_meets_combined(9, 9, 5, 0));
        assert!(!cpu_meets_fair_combined(9, 9, 5, 0));
        assert!(cpu_meets_combined(0, 0, 100, 0));
        assert!(cpu_meets_fair_combined(0, 0, 100, 0));
        // Single-depth helpers still serve placement unit checks.
        assert!(!cpu_meets(9, 5, 0));
        assert!(!cpu_meets_fair(9, 5, 0));
        assert!(cpu_meets(0, 100, 0));
    }

    #[test]
    fn steal_window_spans_8_to_16() {
        assert_eq!(steal_window(0), 16);
        assert_eq!(steal_window(64), 8);
        assert_eq!(steal_window(32), 12);
        assert!(steal_window(0) <= SHARED_SCAN_BOUND);
        assert!(steal_window(64) >= 8);
    }

    #[test]
    fn steal_skips_when_tiers_busy() {
        // Saturated early-out mirrors BPF dispatch with shared visits.
        assert!(!steal_should_skip(0, 0, 0));
        assert!(steal_should_skip(1, 0, 0));
        assert!(steal_should_skip(0, 1, 0));
        assert!(steal_should_skip(0, 0, 1));
        assert_eq!(steal_backlog(u64::MAX, 1, 1), u64::MAX);
        assert!(steal_should_skip(u64::MAX, 0, 0));
    }
}
