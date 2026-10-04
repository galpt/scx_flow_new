// SPDX-License-Identifier: GPL-2.0
//! Placement helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the idle plus previous plus shared placement model with the
//! slowest sufficient pick plus near minimum tiebreak shared by BPF and
//! userspace tests. The BPF placement lives in select_cpu.bpf.c, and
//! this file mirrors the order with no map use.

/// Bound of the shared scan at 8 peers. Fixed with no knob.
/// Steal scans 4 to 8 peers proportional to remaining visits.
#[cfg(test)]
pub const SHARED_SCAN_BOUND: u32 = 8;
/// Bound of the BSF fallback at 4 peers. Halves the fallback cost
/// versus SSF with the same order, so select pays at most 12 peers.
#[cfg(test)]
pub const BSF_SCAN_BOUND: u32 = 4;
/// Near minimum window in capacity units at 64. Peers within this
/// distance of the best defer to the smallest minimum.
#[cfg(test)]
pub const NEAR_MIN_WINDOW: u32 = 64;

/// True when one value holds exactly one bit with no divide.
/// Zero never counts, so the mask path never runs on empty hosts.
#[cfg(test)]
pub fn is_pow2(n: u64) -> bool {
    n != 0 && (n & (n.wrapping_sub(1))) == 0
}

/// Wrap base into 0 to n minus 1 with a pow2 fast path.
/// Powers of two mask with no divide, others modulo same order.
/// Mirrors BPF flow_wrap_idx, so cursor math stays cheap on 16 CPUs.
#[cfg(test)]
pub fn wrap_idx(base: u64, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    if is_pow2(n as u64) {
        (base & (n as u64).wrapping_sub(1)) as u32
    } else {
        (base % n as u64) as u32
    }
}

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

/// Steal window in peers from remaining visits with 4 to 8 bounds.
/// Mirrors BPF flow_steal_one proportional window, so a fresh pass scans
/// eight peers while a spent pass scans four peers with no hotspot.
#[cfg(test)]
pub fn steal_window(visits: u32) -> u32 {
    let remain = 8u32.saturating_sub(visits);
    let window = 4u32.saturating_add(remain >> 1);
    window.clamp(4, 8)
}

/// Saturated backlog of tier queues as local plus node plus machine
/// plus overflow. Mirrors BPF dispatch steal early-out counts with
/// saturation, so a huge depth clamps instead of wrapping to idle.
/// Visits stay shared across the five tiers.
#[cfg(test)]
pub fn steal_backlog(local: u64, node: u64, machine: u64, overflow: u64) -> u64 {
    local
        .saturating_add(node)
        .saturating_add(machine)
        .saturating_add(overflow)
}

/// True when the steal tier skips its peer scan for this pass.
/// Mirrors BPF dispatch saturated early-out over all four queued
/// tiers, so a globally busy pass with any tier backlog skips up to
/// eight peer scans cheaply.
#[cfg(test)]
pub fn steal_should_skip(local: u64, node: u64, machine: u64, overflow: u64) -> bool {
    steal_backlog(local, node, machine, overflow) != 0
}

/// Next placement cursor after one successful pick.
/// Mirrors BPF select advance of start plus one where start is cursor
/// plus one, so the cursor moves by two per pick with no hotspot.
/// Pow2 hosts mask with no divide through wrap_idx.
/// Returns zero on an empty host with no divide.
#[cfg(test)]
pub fn cursor_next(cursor: u32, n: usize) -> u32 {
    if n == 0 {
        return 0;
    }
    let n = n as u32;
    let start = wrap_idx(cursor.wrapping_add(1) as u64, n);
    wrap_idx(start.wrapping_add(1) as u64, n)
}

/// Best sufficient fallback with the smallest combined drain.
/// Mirrors BPF flow_bsf_pick with no topology signal: scans at most
/// four peers from the cursor, skips the busy waker, keeps only peers
/// that meet the deadline via combined local plus node drain, then
/// takes the smallest combined drain. Ties keep the first peer in
/// scan order. Returns minus one when no allowed peer meets.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn bsf_pick(
    allowed: &[i32],
    live: &[i32],
    local: &[u64],
    node: &[u64],
    deadline: u64,
    now: u64,
    this_cpu: i32,
    cursor: u32,
) -> i32 {
    let n = live.len();
    if n <= 1 || n > 1024 {
        return -1;
    }
    let start = wrap_idx(cursor.wrapping_add(1) as u64, n as u32) as usize;
    let mut best: i32 = -1;
    let mut best_drain: u64 = u64::MAX;
    for off in 0..BSF_SCAN_BOUND as usize {
        if off >= n {
            break;
        }
        let idx = wrap_idx(start as u64 + off as u64, n as u32) as usize;
        let cpu = live[idx];
        if cpu == this_cpu {
            continue;
        }
        if !allowed.contains(&cpu) {
            continue;
        }
        let ld = local.get(idx).copied().unwrap_or(0);
        let nd = node.get(idx).copied().unwrap_or(0);
        if !cpu_meets_combined(ld, nd, deadline, now) {
            continue;
        }
        let drain = drain_combined(ld, nd);
        if best == -1 || drain < best_drain {
            best_drain = drain;
            best = cpu;
        }
    }
    best
}

/// Placement pick among idle plus previous plus shared with fair tiebreak.
/// Idle wins first, then the previous CPU when it drains before the
/// deadline, then the slowest sufficient shared CPU with near minimum
/// tiebreak on the smallest minimum vruntime. Peers within 64 capacity
/// units of the best count as tied, so lagging CPUs take work first.
/// Test-only SSF mirror with no map use where the BPF pass scans at
/// most eight peers from the cursor and skips the busy waker, and this
/// mirror walks the same bounded window from the passed cursor with
/// the same skip. BPF tries SSF then the bsf_pick fallback with the
/// smallest combined drain, so callers try place then bsf_pick in the
/// same order. Minimum order uses the wrap safe signed diff like BPF,
/// so the tiebreak holds across the u64 wrap. Callers pass host-sized
/// slices within the 1024 CPU bound with units plus minimums parallel
/// to live. Returns minus one when no allowed CPU is live. Perf stays
/// bounded at eight peers with no extra walk. Cursor advance uses
/// cursor_next with plus two per pick.
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
        let start = wrap_idx(cursor.wrapping_add(1) as u64, n as u32) as usize;
        for off in 0..SHARED_SCAN_BOUND as usize {
            if off >= n {
                break;
            }
            let idx = wrap_idx(start as u64 + off as u64, n as u32) as usize;
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
        assert_eq!(SHARED_SCAN_BOUND, 8);
        assert_eq!(NEAR_MIN_WINDOW, 64);
        // Wrap safe minimum order holds across the u64 wrap.
        assert!(crate::flow::edf::time_before(u64::MAX, 10));
        assert!(!crate::flow::edf::time_before(10, u64::MAX - 10));
        // Busy waker stays out while the cursor window still finds
        // the lagging peer within eight.
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
        // fewer than eight CPUs.
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
    fn steal_window_spans_4_to_8() {
        assert_eq!(steal_window(0), 8);
        assert_eq!(steal_window(8), 4);
        assert_eq!(steal_window(4), 6);
        assert!(steal_window(0) <= SHARED_SCAN_BOUND);
        assert!(steal_window(8) >= 4);
    }

    #[test]
    fn steal_skips_when_tiers_busy() {
        // Saturated early-out mirrors BPF dispatch over local plus
        // node plus machine plus overflow with shared visits.
        assert!(!steal_should_skip(0, 0, 0, 0));
        assert!(steal_should_skip(1, 0, 0, 0));
        assert!(steal_should_skip(0, 1, 0, 0));
        assert!(steal_should_skip(0, 0, 1, 0));
        assert!(steal_should_skip(0, 0, 0, 1));
        assert_eq!(steal_backlog(u64::MAX, 1, 1, 1), u64::MAX);
        assert!(steal_should_skip(u64::MAX, 0, 0, 0));
    }

    #[test]
    fn bsf_takes_smallest_combined_drain() {
        // Symmetric hosts spread via the smallest combined drain.
        assert_eq!(BSF_SCAN_BOUND, 4);
        assert_eq!(
            BSF_SCAN_BOUND,
            crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u32
        );
        let got = bsf_pick(
            &[1, 2, 3],
            &[1, 2, 3],
            &[9, 0, 5],
            &[9, 0, 0],
            100,
            0,
            99,
            0,
        );
        assert_eq!(got, 2);
        // No peer meets when every drain misses the deadline.
        let miss = bsf_pick(&[1, 2], &[1, 2], &[9, 9], &[9, 9], 5, 0, 99, 0);
        assert_eq!(miss, -1);
        // Busy waker stays out while the window still finds a peer.
        let skip = bsf_pick(&[1, 2, 3], &[1, 2, 3], &[0, 0, 0], &[0, 0, 0], 100, 0, 1, 2);
        assert_ne!(skip, 1);
        assert!(skip == 2 || skip == 3);
    }

    #[test]
    fn wrap_idx_masks_pow2_and_mods_rest() {
        assert_eq!(wrap_idx(0, 0), 0);
        assert!(is_pow2(16));
        assert!(!is_pow2(0));
        assert!(!is_pow2(12));
        assert!(!is_pow2(1000));
        // Pow2 hosts mask with the same order as modulo.
        assert_eq!(wrap_idx(17, 16), 1);
        assert_eq!(wrap_idx(32, 16), 0);
        assert_eq!(wrap_idx(18, 16), 18 % 16);
        // Non pow2 hosts modulo with the same result.
        assert_eq!(wrap_idx(17, 12), 17 % 12);
        assert_eq!(wrap_idx(100, 6), 100 % 6);
        // Cursor math stays identical through the helper.
        assert_eq!(cursor_next(0, 16), 2);
        assert_eq!(wrap_idx(1, 16), 1);
    }

    #[test]
    fn cursor_advances_by_two() {
        assert_eq!(cursor_next(0, 4), 2);
        assert_eq!(cursor_next(3, 4), 1);
        assert_eq!(cursor_next(0, 0), 0);
        // Window stays four to eight with the cursor spread.
        assert_eq!(steal_window(0), 8);
        assert_eq!(cursor_next(1, 3), 0);
    }
}
