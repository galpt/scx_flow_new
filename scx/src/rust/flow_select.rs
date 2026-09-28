// SPDX-License-Identifier: GPL-2.0
//! Placement helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the hint only placement helpers shared by tests and docs.
//! Placement order lives in select_cpu.bpf.c with the key choice
//! in enqueue.bpf.c, and this file mirrors the scan predicates.
//! The scan best never beats the previous CPU on a tie, so warmth
//! never loses to load with the best versus previous compare below.
//!
//! Depth is one running bit per CPU with idle at zero and busy at
//! one, so the scan needs no queue read. Live means below the
//! attach snapshot with no kernel online read. An offlined CPU
//! needs a restart with no live rebalance.
//!
//! Full drain order lives in BPF dispatch with tree plus park plus
//! global phases. No steal tier exists, so every CPU serves the
//! global order with mask wins.

/// Compile time CPU bound. Mirrors the BPF header.
#[cfg(test)]
pub const MAX_CPUS: u32 = 1024;
/// Bound of peers visited by one placement scan.
pub const SCAN_BOUND: usize = 8;

/// Check that a CPU may run a task with the given mask.
/// A negative CPU fails closed. A CPU at or past 1024 fails closed.
/// A missing entry fails closed.
#[cfg(test)]
pub fn may_run_on(cpu: i32, allowed: &[bool]) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    if let Some(&ok) = allowed.get(cpu as usize) {
        return ok;
    }
    false
}

/// Check that a CPU is live for tests.
/// Needs zero or past zero and below live count and below 1024.
#[cfg(test)]
pub fn cpu_live(cpu: i32, nr_cpus: usize) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    (cpu as usize) < nr_cpus
}

/// Check that a CPU is live and allowed for tests.
#[cfg(test)]
pub fn may_run_on_live(cpu: i32, allowed: &[bool], nr_cpus: usize) -> bool {
    if !cpu_live(cpu, nr_cpus) {
        return false;
    }
    may_run_on(cpu, allowed)
}

/// First idle CPU in the mask.
/// Returns none when no allowed CPU is idle.
#[cfg(test)]
pub fn pick_any_idle(allowed: &[bool], idle: &[bool]) -> Option<u32> {
    for (cpu, &ok) in allowed.iter().enumerate() {
        if !ok {
            continue;
        }
        if let Some(true) = idle.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/// Start peer for one placement scan from cursor plus salt.
/// Steps one past the cursor with the prandom salt and wraps, so
/// repeated passes spread with no hot spot.
#[cfg(test)]
pub fn place_start(cursor: u32, salt: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    (cursor.wrapping_add(1).wrapping_add(salt)) % nr_cpus as u32
}

/// Idlest live allowed peer in the same cache domain.
/// Visits bound peers from a start with wrap and keeps the peer with
/// the least running bit. Skips the waker, offline peers, foreign
/// masks, and foreign domains. A missing depth never wins, a missing
/// domain view fails open to the same domain, and ties keep the first
/// peer. Live is the attach snapshot with no online read. Returns none
/// when no peer qualifies or when the CPU count is out of bound. The
/// caller keeps the previous CPU when this best is not idler, so
/// warmth never loses to load. See best beats and place pick below.
#[cfg(test)]
pub fn shallowest_llc_peer(
    start: u32,
    nr_cpus: usize,
    want_llc: Option<u32>,
    llcs: &[u32],
    running: &[u64],
    allowed: &[bool],
    self_cpu: u32,
) -> Option<u32> {
    if nr_cpus <= 1 || nr_cpus > MAX_CPUS as usize {
        return None;
    }
    let mut best: Option<u32> = None;
    let mut best_depth = u64::MAX;
    for off in 0..SCAN_BOUND as u32 {
        let peer = start.wrapping_add(off) % nr_cpus as u32;
        if peer == self_cpu {
            continue;
        }
        if (peer as u64) >= MAX_CPUS as u64 {
            continue;
        }
        if (peer as usize) >= nr_cpus {
            continue;
        }
        if !may_run_on(peer as i32, allowed) {
            continue;
        }
        if let Some(want) = want_llc {
            match llcs.get(peer as usize) {
                Some(&llc) if llc != want => continue,
                _ => {}
            }
        }
        let depth = running.get(peer as usize).copied().unwrap_or(u64::MAX);
        if depth < best_depth {
            best_depth = depth;
            best = Some(peer);
        }
    }
    best
}

/// True when one scan best beats the previous CPU.
/// Needs a best depth strictly idler than the previous depth, so a
/// busier peer never moves cache warmth. Equal keeps the previous CPU.
#[cfg(test)]
pub fn best_beats_prev(prev_depth: u64, best_depth: u64) -> bool {
    best_depth < prev_depth
}

/// Pick between the previous CPU and the scan best with no worse guard.
/// Keeps the previous CPU when allowed and the scan best is missing or not
/// idler, else takes the scan best. Returns none when neither allows.
/// Models the BPF fallback with the best versus previous compare.
#[cfg(test)]
pub fn place_pick(
    prev_ok: bool,
    prev: i32,
    prev_depth: u64,
    best: Option<u32>,
    best_depth: u64,
) -> Option<u32> {
    if let Some(b) = best {
        if !prev_ok || best_depth < prev_depth {
            return Some(b);
        }
        if prev_ok {
            return Some(prev as u32);
        }
    }
    if prev_ok {
        return Some(prev as u32);
    }
    None
}

/// Full placement model for tests with the cache scan always on.
/// Walks waker idle, any idle, the bound 8 scan from a start, then the
/// previous versus best compare, then the first allowed CPU. Returns
/// none for park use when no CPU allows.
#[cfg(test)]
pub fn select_cpu_model(
    prev: i32,
    cur: i32,
    allowed: &[bool],
    idle: &[bool],
    llcs: &[u32],
    running: &[u64],
    start: u32,
) -> Option<u32> {
    if may_run_on(cur, allowed) && idle.get(cur as usize).copied().unwrap_or(false) {
        return Some(cur as u32);
    }
    if let Some(c) = pick_any_idle(allowed, idle) {
        return Some(c);
    }
    let nr = allowed.len();
    let prev_ok = may_run_on(prev, allowed);
    let prev_depth = if prev_ok {
        running.get(prev as usize).copied().unwrap_or(u64::MAX)
    } else {
        u64::MAX
    };
    let want = llcs.get(cur.max(0) as usize).copied();
    let cur_u = if cur < 0 { u32::MAX } else { cur as u32 };
    let best = shallowest_llc_peer(start, nr, want, llcs, running, allowed, cur_u);
    let best_depth = best
        .and_then(|b| running.get(b as usize).copied())
        .unwrap_or(u64::MAX);
    if let Some(p) = place_pick(prev_ok, prev, prev_depth, best, best_depth) {
        return Some(p);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/// Target CPU for one enqueue with trust in select.
/// Keeps the selected CPU when allowed, else the first allowed CPU.
/// Returns none for park use when no CPU allows.
/// Pinned tasks never reach here, they rest in park with no kick.
#[cfg(test)]
pub fn pick_target_cpu(selected: i32, allowed: &[bool]) -> Option<u32> {
    if may_run_on(selected, allowed) {
        return Some(selected as u32);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/// True when the exiting fast path may run on the target.
/// Needs an exiting task with the target inside the mask.
#[cfg(test)]
pub fn exiting_target_ok(exiting: bool, tgt_allowed: bool) -> bool {
    exiting && tgt_allowed
}

/// Next cursor for one placement scan from a start.
/// Steps by 8 with wrap, so passes spread with no hot spot.
#[cfg(test)]
pub fn cursor_next(start: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    start.wrapping_add(8) % nr_cpus as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_checks_fail_closed() {
        assert!(may_run_on(0, &[true, false]));
        assert!(!may_run_on(1, &[true, false]));
        assert!(!may_run_on(-1, &[true]));
        assert!(!may_run_on(1024, &[true]));
        assert!(!may_run_on(0, &[]));
        assert!(cpu_live(0, 4));
        assert!(!cpu_live(4, 4));
        assert!(!cpu_live(-1, 4));
        assert!(may_run_on_live(0, &[true], 4));
        assert!(!may_run_on_live(3, &[true], 2));
    }

    #[test]
    fn select_prefers_idle_then_scan() {
        let allowed = vec![true, true, true];
        let idle = vec![false, true, false];
        let llcs = vec![0u32, 0, 0];
        let running = vec![1u64, 0, 1];
        assert_eq!(
            select_cpu_model(0, 2, &allowed, &idle, &llcs, &running, 0),
            Some(1)
        );
        let idle_none = vec![false, false, false];
        assert_eq!(
            select_cpu_model(2, 0, &allowed, &idle_none, &llcs, &running, 1),
            Some(1)
        );
        assert_eq!(pick_target_cpu(1, &allowed), Some(1));
        assert_eq!(pick_target_cpu(9, &allowed), Some(0));
        assert!(exiting_target_ok(true, true));
        assert!(!exiting_target_ok(false, true));
        assert_eq!(pick_any_idle(&allowed, &idle), Some(1));
    }

    #[test]
    fn waker_idle_wins_without_scan() {
        let allowed = vec![true, true];
        let idle = vec![false, true];
        let llcs = vec![0u32, 0];
        let running = vec![1u64, 0];
        assert_eq!(
            select_cpu_model(0, 1, &allowed, &idle, &llcs, &running, 0),
            Some(1)
        );
    }

    #[test]
    fn empty_mask_falls_to_park() {
        let allowed = vec![false, false];
        let idle = vec![true, true];
        let llcs = vec![0u32, 0];
        let running = vec![0u64, 0];
        assert_eq!(
            select_cpu_model(0, 0, &allowed, &idle, &llcs, &running, 0),
            None
        );
        assert_eq!(pick_target_cpu(0, &allowed), None);
    }

    #[test]
    fn scan_beats_busy_previous_only() {
        let allowed = vec![true, true, true, true];
        let idle_none = vec![false, false, false, false];
        let llcs = vec![0u32, 0, 0, 0];
        let running = vec![1u64, 0, 1, 1];
        assert_eq!(
            select_cpu_model(0, 3, &allowed, &idle_none, &llcs, &running, 0),
            Some(1)
        );
        let all_busy = vec![1u64, 1, 1, 1];
        assert_eq!(
            select_cpu_model(0, 3, &allowed, &idle_none, &llcs, &all_busy, 0),
            Some(0)
        );
    }

    #[test]
    fn place_cursor_spreads_with_wrap() {
        assert_eq!(place_start(0, 0, 0), 0);
        assert_eq!(place_start(0, 0, 4), 1);
        assert_eq!(place_start(3, 0, 4), 0);
        assert_eq!(place_start(0, 2, 4), 3);
        assert_eq!(place_start(0, 4, 4), 1);
        assert_eq!(cursor_next(0, 4), 0);
        assert_eq!(cursor_next(1, 4), 1);
    }

    #[test]
    fn starve_uses_two_millisecond_floor() {
        use crate::flow_edf::STARVE_NS;
        assert!(crate::flow_edf::starved(100, 100 + STARVE_NS + 1));
        assert!(!crate::flow_edf::starved(100, 100 + STARVE_NS));
    }

    #[test]
    fn place_start_spreads_with_salt() {
        assert_eq!(place_start(0, 0, 0), 0);
        assert_eq!(place_start(0, 0, 4), 1);
        assert_eq!(place_start(3, 0, 4), 0);
        assert_eq!(place_start(0, 2, 4), 3);
        assert_eq!(place_start(0, 4, 4), 1);
    }

    #[test]
    fn idlest_peer_wins_same_domain() {
        let allowed = vec![true, true, true, true];
        let llcs = vec![0u32, 0, 0, 1];
        let running = vec![1u64, 0, 1, 0];
        assert_eq!(
            shallowest_llc_peer(0, 4, Some(0), &llcs, &running, &allowed, 0),
            Some(1)
        );
        assert_eq!(
            shallowest_llc_peer(0, 4, Some(1), &llcs, &running, &allowed, 0),
            Some(3)
        );
        assert_eq!(
            shallowest_llc_peer(0, 4, None, &llcs, &running, &allowed, 0),
            Some(1)
        );
    }

    #[test]
    fn idlest_peer_skips_self_mask_and_domain() {
        let allowed = vec![true, false, true, true];
        let llcs = vec![0u32, 0, 0, 0];
        let running = vec![1u64, 0, 1, 0];
        assert_eq!(
            shallowest_llc_peer(0, 4, Some(0), &llcs, &running, &allowed, 0),
            Some(3)
        );
        let foreign = vec![0u32, 1, 1, 1];
        assert_eq!(
            shallowest_llc_peer(1, 4, Some(0), &foreign, &running, &allowed, 0),
            None
        );
        assert_eq!(
            shallowest_llc_peer(0, 1, Some(0), &llcs, &running, &allowed, 0),
            None
        );
        assert_eq!(
            shallowest_llc_peer(0, 2048, Some(0), &llcs, &running, &allowed, 0),
            None
        );
    }

    #[test]
    fn busier_peer_never_beats_previous() {
        assert!(!best_beats_prev(0, 1));
        assert!(!best_beats_prev(1, 1));
        assert!(!best_beats_prev(0, 0));
        assert!(best_beats_prev(1, 0));
    }

    #[test]
    fn place_pick_keeps_previous_when_not_idler() {
        assert_eq!(place_pick(true, 0, 1, Some(1), 1), Some(0));
        assert_eq!(place_pick(true, 0, 0, Some(1), 0), Some(0));
        assert_eq!(place_pick(true, 0, 1, Some(1), 0), Some(1));
        assert_eq!(place_pick(true, 0, 1, None, u64::MAX), Some(0));
        assert_eq!(place_pick(false, 0, u64::MAX, Some(1), 1), Some(1));
        assert_eq!(place_pick(false, 0, u64::MAX, None, u64::MAX), None);
    }
}
