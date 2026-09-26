// SPDX-License-Identifier: GPL-2.0
//! Placement and steal helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the placement and steal helpers shared by tests and docs.

/// Compile time CPU bound. Mirrors the BPF header.
#[cfg(test)]
pub const MAX_CPUS: u32 = 1024;
/// Bound of peers visited by one steal scan.
#[cfg(test)]
pub const STEAL_BOUND: usize = 8;
/// Least donor depth that always allows a steal.
#[cfg(test)]
pub const STEAL_MIN_DEPTH: u64 = 2;

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

/// Full select model for tests.
/// Mirrors the BPF order of waker idle, any idle, previous, then first.
/// Returns none for overflow use when no CPU allows.
/// Approximate when the caller passes summed depth as queued.
#[cfg(test)]
pub fn select_cpu_model(prev: i32, cur: i32, allowed: &[bool], idle: &[bool]) -> Option<u32> {
    if may_run_on(cur, allowed) && idle.get(cur as usize).copied().unwrap_or(false) {
        return Some(cur as u32);
    }
    if let Some(c) = pick_any_idle(allowed, idle) {
        return Some(c);
    }
    if may_run_on(prev, allowed) {
        return Some(prev as u32);
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
/// Returns none for overflow use when no CPU allows.
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

/// Pinned target for one enqueue.
/// Keeps the task CPU when allowed, else the selected CPU, else the first.
/// Returns none for overflow use when no CPU allows.
#[cfg(test)]
pub fn stay_target(here: i32, selected: i32, allowed: &[bool]) -> Option<u32> {
    if may_run_on(here, allowed) {
        return Some(here as u32);
    }
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

/// Start peer for one dispatch from the cursor.
/// Steps one with wrap, so repeated passes spread with no hot spot.
#[cfg(test)]
pub fn steal_start(cursor: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    if nr_cpus == 1 {
        return 0;
    }
    (cursor.wrapping_add(1)) % nr_cpus as u32
}

/// Peers visited by one steal scan from a start.
/// Takes bound peers with wrap, so high CPUs reach low peers.
#[cfg(test)]
pub fn steal_peers_from(start: u32, nr_cpus: usize) -> Vec<u32> {
    let mut out = Vec::with_capacity(STEAL_BOUND);
    if nr_cpus == 0 {
        return out;
    }
    for off in 0..STEAL_BOUND as u32 {
        out.push(start.wrapping_add(off) % nr_cpus as u32);
    }
    out
}

/// Next cursor for one dispatch from a start.
/// Steps by 8 with wrap, so passes spread with no hot spot.
#[cfg(test)]
pub fn cursor_next(start: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    start.wrapping_add(8) % nr_cpus as u32
}

/// Pending task for dispatch models.
/// The mask names allowed CPUs. The live flag marks tasks with a trusted
/// reference. A cleared live flag models a NULL lookup from the pid table.
/// The fail flag models a failed move skipped with progress.
/// The wait stamp holds the enqueue time in nanos for starvation.
/// Zero means unknown and never counts as starved.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTask {
    /// Allowed CPUs. Index is the CPU.
    pub allowed: Vec<bool>,
    /// True when the task is exiting.
    pub exiting: bool,
    /// False models a NULL pid lookup.
    pub live: bool,
    /// True models a failed queue move.
    pub fail: bool,
    /// Enqueue time in nanos. Zero means unknown.
    pub wait_at: u64,
}

/// True when one queued task waited past the 1.5ms floor.
/// Unknown stamps never count, so fresh tasks miss past.
#[cfg(test)]
pub fn starved(wait_at: u64, now: u64) -> bool {
    if wait_at == 0 || now < wait_at {
        return false;
    }
    now - wait_at > crate::flow_admit::STARVE_NS
}

/// True when one donor may serve a gated cross domain move.
/// Donors hold at least two, so the owner keeps one task back.
#[cfg(test)]
pub fn gated_donor_ok(depth: u64) -> bool {
    depth >= 2
}

/// Sibling donor id when live and deep enough.
/// Returns none when the sibling is unknown, self, offline, or shallow.
#[cfg(test)]
pub fn sib_donor(sib: u32, cpu: u32, nr: usize, need: u64, depths: &[u64]) -> Option<u32> {
    if sib == 0xffffffff {
        return None;
    }
    if sib == cpu {
        return None;
    }
    if (sib as usize) >= nr {
        return None;
    }
    if depths.get(sib as usize).copied().unwrap_or(0) < need {
        return None;
    }
    Some(sib)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(allowed: &[bool], wait_at: u64) -> PendingTask {
        PendingTask {
            allowed: allowed.to_vec(),
            exiting: false,
            live: true,
            fail: false,
            wait_at,
        }
    }

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
    fn select_prefers_idle_then_previous() {
        let allowed = vec![true, true, true];
        let idle = vec![false, true, false];
        assert_eq!(select_cpu_model(0, 2, &allowed, &idle), Some(1));
        let idle_none = vec![false, false, false];
        assert_eq!(select_cpu_model(2, 0, &allowed, &idle_none), Some(2));
        assert_eq!(pick_target_cpu(1, &allowed), Some(1));
        assert_eq!(stay_target(2, 1, &allowed), Some(2));
        assert!(exiting_target_ok(true, true));
        assert!(!exiting_target_ok(false, true));
        assert_eq!(pick_any_idle(&allowed, &idle), Some(1));
    }

    #[test]
    fn steal_cursor_spreads_with_wrap() {
        assert_eq!(steal_start(0, 4), 1);
        assert_eq!(steal_start(3, 4), 0);
        assert_eq!(cursor_next(0, 4), 0);
        assert_eq!(cursor_next(1, 4), 1);
        let peers = steal_peers_from(3, 4);
        assert_eq!(peers.len(), STEAL_BOUND);
        assert_eq!(peers[0], 3);
        assert_eq!(peers[1], 0);
    }

    #[test]
    fn starve_needs_old_stamp() {
        assert!(starved(100, 100 + crate::flow_admit::STARVE_NS + 1));
        assert!(!starved(100, 100 + crate::flow_admit::STARVE_NS));
        assert!(!starved(0, u64::MAX));
        assert!(!starved(200, 100));
        assert!(gated_donor_ok(2));
        assert!(!gated_donor_ok(1));
    }

    #[test]
    fn sibling_wins_when_deep() {
        let depths = vec![0u64, 3, 0, 0];
        assert_eq!(sib_donor(1, 0, 4, 2, &depths), Some(1));
        assert_eq!(sib_donor(0xffffffff, 0, 4, 1, &depths), None);
        assert_eq!(sib_donor(0, 0, 4, 1, &depths), None);
        assert_eq!(sib_donor(9, 0, 4, 1, &depths), None);
        assert_eq!(sib_donor(2, 0, 4, 2, &depths), None);
    }

    #[test]
    fn pending_task_builds_for_drain_models() {
        let t = task(&[true], 50);
        assert!(t.live && !t.fail && !t.exiting);
        assert_eq!(t.wait_at, 50);
    }
}
