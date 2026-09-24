// SPDX-License-Identifier: GPL-2.0
//! Slot store helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! One queue per CPU plus one overflow tail with bounded LIFO at K 8.

/// Tasks moved by one slot trip at most. Fixed at 4 with no knob.
pub const SLOT_D: u32 = 4;
/// Tasks moved by one dispatch pass at most. Fixed at 32 with no knob.
pub const SLOT_BUDGET: u32 = 32;
/// Base id of the per CPU queues.
#[cfg(test)]
pub const SLOT_BASE: u64 = 0x6000;
/// Id of the overflow tail shared by every CPU.
#[cfg(test)]
pub const SLOT_OVERFLOW: u64 = 0x6800;
/// Max DSQs at 1024 CPUs. Holds 1024 per CPU plus one overflow.
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 1025;
/// Own queue cap at budget minus one. Fixed at 31 with no knob.
#[cfg(test)]
pub const SLOT_OWN_CAP: u32 = 31;
/// Head inserts in one LIFO period at 8 with one tail.
#[cfg(test)]
pub const LIFO_K: u64 = 8;
/// Inserts in one LIFO period at 9 with 8 heads.
#[cfg(test)]
pub const LIFO_PERIOD: u64 = 9;
/// LIFO sequences at 1025 with per CPU plus overflow.
#[cfg(test)]
pub const LIFO_NSEQ: u64 = 1025;

/// Slot id of one CPU queue from base plus id.
/// One queue per CPU keeps enqueue and dispatch O(1).
#[cfg(test)]
pub fn slot_cpu_dsq(cpu: u32) -> u64 {
    SLOT_BASE + cpu as u64
}

/// Slot id of the overflow tail shared by every CPU.
/// Pinned and homeless tasks rest here with mask wins on drain.
#[cfg(test)]
pub fn slot_overflow_dsq() -> u64 {
    SLOT_OVERFLOW
}

/// Count of DSQs for one host with per CPU plus overflow.
/// Holds nr plus one, so eight CPUs need nine queues.
#[cfg(test)]
pub fn slot_nr_dsqs(nr: u64) -> u64 {
    nr + 1
}

/// DSQ id for one insert with pinned overflow.
/// Pinned tasks rest in the overflow tail with no per CPU use.
/// Dead CPUs rest in overflow with fail closed.
#[cfg(test)]
pub fn insert_dsq(cpu: i32, pinned: bool, nr: usize) -> u64 {
    if pinned {
        return slot_overflow_dsq();
    }
    if cpu < 0 {
        return slot_overflow_dsq();
    }
    if (cpu as usize) >= nr {
        return slot_overflow_dsq();
    }
    if (cpu as u64) >= 1024 {
        return slot_overflow_dsq();
    }
    slot_cpu_dsq(cpu as u32)
}

/// Local queue ids for one dispatch in drain order.
/// Holds the own queue then the overflow tail with no share.
#[cfg(test)]
pub fn local_trip_dsqs(cpu: u32) -> [u64; 2] {
    [slot_cpu_dsq(cpu), slot_overflow_dsq()]
}

/// Cap of one trip at D under the dispatch budget.
/// Returns the min of budget and 4.
#[cfg(test)]
pub fn slot_cap(budget: u32) -> u32 {
    budget.min(SLOT_D)
}

/// Own queue cap at budget minus one.
/// Holds 31 with budget 32, so overflow and steal keep one slot.
#[cfg(test)]
pub fn slot_own_cap(budget: u32) -> u32 {
    budget.saturating_sub(1)
}

/// Drain up to a cap from one slot queue for one CPU.
/// The scan visits every queued task in queue order and moves each live
/// task with the CPU in the mask. Dead, foreign, and failed tasks are
/// skipped with progress, so one bad head never blocks later work.
/// Returns the count moved.
#[cfg(test)]
pub fn slot_drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved + base < cap
            && task.live
            && !task.fail
            && crate::flow_select::may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
        } else {
            kept.push_back(task);
        }
    }
    *queue = kept;
    moved
}

/// True when one local window holds work.
/// Window holds the own queue plus the overflow tail.
#[cfg(test)]
pub fn window_has_work(own: bool, over: bool) -> bool {
    own || over
}

/// Least donor depth for one steal with idle empty fast path.
/// Holds one when idle empty, else two.
#[cfg(test)]
pub fn steal_need(idle_empty: bool) -> u64 {
    if idle_empty {
        1
    } else {
        crate::flow_select::STEAL_MIN_DEPTH
    }
}

/// First donor DSQ id from one scan window with keep first.
/// Visits bound peers from start with wrap and keeps the first peer with
/// queued at or past need. Returns the DSQ id on hit and none on miss.
#[cfg(test)]
pub fn steal_first_donor(start: u32, nr: usize, need: u64, depths: &[u64]) -> Option<u64> {
    if nr <= 1 {
        return None;
    }
    for off in 0..crate::flow_select::STEAL_BOUND as u32 {
        let peer = start.wrapping_add(off) % nr as u32;
        if (peer as usize) >= nr {
            continue;
        }
        if (peer as u64) >= 1024 {
            continue;
        }
        let q = depths.get(peer as usize).copied().unwrap_or(0);
        if q < need {
            continue;
        }
        return Some(slot_cpu_dsq(peer));
    }
    None
}

/// True when one insert takes head with bounded LIFO at K 8.
/// Takes head for 8 of 9 with one tail plus one forced tail at MAX.
/// Fresh work wins fast while the tail keeps the starve bound at 9.
#[cfg(test)]
pub fn lifo_take_head(seq: u32) -> bool {
    if seq == u32::MAX {
        return false;
    }
    (seq as u64 % LIFO_PERIOD) != LIFO_K
}

/// Index of one LIFO sequence with per CPU plus overflow at 1025.
/// Per CPU holds the id and overflow holds 1024 with no share.
#[cfg(test)]
pub fn lifo_idx(over: bool, cpu: u32) -> u32 {
    if over { 1024 } else { cpu }
}
