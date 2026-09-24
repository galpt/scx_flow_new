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
}
