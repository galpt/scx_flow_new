// SPDX-License-Identifier: GPL-2.0
//! Queue store helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! One shallow FIFO plus one deadline queue per CPU with a shared tail.

/// Tasks moved by one fast trip at most. Fixed at 4 with no knob.
pub const SLOT_D: u32 = 4;
/// Tasks moved by one dispatch pass at most. Fixed at 32 with no knob.
pub const SLOT_BUDGET: u32 = 32;
/// Base id of the per CPU fast queues.
#[cfg(test)]
pub const FAST_BASE: u64 = 0x6000;
/// Base id of the per CPU deadline queues.
#[cfg(test)]
pub const VTIME_BASE: u64 = 0x6800;
/// Id of the overflow tail shared by every CPU.
#[cfg(test)]
pub const SLOT_OVERFLOW: u64 = 0x7000;
/// Id of the kernel global queue for homeless tasks.
#[cfg(test)]
pub const SLOT_GLOBAL: u64 = 0;
/// Max DSQs at 1024 CPUs. Holds two per CPU plus one overflow.
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 2049;
/// Own deadline queue cap at 12 under budget 32. Fixed with no knob.
#[cfg(test)]
pub const SLOT_OWN_CAP: u32 = 12;
/// Shared tail cap at 4 under the dispatch budget. Fixed with no knob.
#[cfg(test)]
pub const SLOT_OVER_CAP: u32 = 4;
/// Gated starvation cap at 4 under the dispatch budget. Fixed with no knob.
#[cfg(test)]
pub const SLOT_GATED_CAP: u32 = 4;
/// Miss cap of one drain trip at 4. Fixed with no knob.
#[cfg(test)]
pub const SLOT_MISS_CAP: u32 = 4;

/// Fast queue id of one CPU from base plus id.
/// One shallow queue per CPU keeps sleepy wakeups local.
#[cfg(test)]
pub fn fast_dsq(cpu: u32) -> u64 {
    FAST_BASE + cpu as u64
}

/// Deadline queue id of one CPU from base plus id.
/// One ordered queue per CPU keeps steady work fair.
#[cfg(test)]
pub fn vtime_dsq(cpu: u32) -> u64 {
    VTIME_BASE + cpu as u64
}

/// Id of the overflow tail shared by every CPU.
/// Pinned and homeless tasks rest here with mask wins on drain.
#[cfg(test)]
pub fn slot_overflow_dsq() -> u64 {
    SLOT_OVERFLOW
}

/// Id of the kernel global queue for homeless tasks.
/// Tasks without state or without a live CPU rest here with mask
/// wins on drain, and the drain counts the global moves.
#[cfg(test)]
pub fn slot_global_dsq() -> u64 {
    SLOT_GLOBAL
}

/// Count of DSQs for one host with two per CPU plus overflow.
/// Holds twice nr plus one, so eight CPUs need seventeen queues.
#[cfg(test)]
pub fn slot_nr_dsqs(nr: u64) -> u64 {
    nr * 2 + 1
}

/// DSQ id for one insert with pinned overflow.
/// Pinned tasks rest in the overflow tail with no per CPU use.
/// Homeless tasks rest in the kernel global queue with fail closed.
/// Dead CPUs rest in global with fail closed.
#[cfg(test)]
pub fn insert_dsq(cpu: i32, pinned: bool, nr: usize) -> u64 {
    if pinned {
        return slot_overflow_dsq();
    }
    if cpu < 0 {
        return slot_global_dsq();
    }
    if (cpu as usize) >= nr {
        return slot_global_dsq();
    }
    if (cpu as u64) >= 1024 {
        return slot_global_dsq();
    }
    fast_dsq(cpu as u32)
}

/// Local queue ids for one dispatch in drain order.
/// Holds the fast queue, the deadline queue, then the overflow tail.
#[cfg(test)]
pub fn local_trip_dsqs(cpu: u32) -> [u64; 3] {
    [fast_dsq(cpu), vtime_dsq(cpu), slot_overflow_dsq()]
}

/// Cap of one fast trip at depth under the dispatch budget.
/// Returns the min of budget and 4.
#[cfg(test)]
pub fn slot_cap(budget: u32) -> u32 {
    budget.min(SLOT_D)
}

/// Own deadline queue cap at 12 under budget 32.
/// Holds 12 with budget 32, so overflow and steal keep room.
#[cfg(test)]
pub fn slot_own_cap(budget: u32) -> u32 {
    budget.min(SLOT_OWN_CAP)
}

/// Shared tail cap at 4 under the dispatch budget.
/// Returns the min of budget and 4 with no head stall.
#[cfg(test)]
pub fn tail_cap(budget: u32) -> u32 {
    budget.min(SLOT_OVER_CAP)
}

/// Drain up to a cap from one queue for one CPU.
/// The scan visits queued tasks in queue order and moves each live
/// task with the CPU in the mask. Dead, foreign, and failed tasks count
/// one miss each with a miss cap at 4, so one bad head never blocks later
/// work. The walk stops at cap plus base with no full scan.
/// Returns the count moved.
#[cfg(test)]
pub fn slot_drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
) -> u32 {
    slot_drain_inner(queue, cpu, cap, base, None, u64::MAX)
}

/// Starvation drain for the gated passes with a 1.5ms floor.
/// Young tasks count one miss each, so old tasks behind them surface.
/// Tasks without a wait stamp miss past with no move.
#[cfg(test)]
pub fn slot_drain_starved_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
    now: u64,
) -> u32 {
    slot_drain_inner(
        queue,
        cpu,
        cap,
        base,
        Some(now),
        crate::flow_admit::STARVE_NS,
    )
}

#[cfg(test)]
fn slot_drain_inner(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
    now: Option<u64>,
    floor_ns: u64,
) -> u32 {
    let mut moved = 0;
    let mut miss = 0u32;
    let mut kept = std::collections::VecDeque::new();
    let mut rest = std::collections::VecDeque::new();
    std::mem::swap(queue, &mut rest);
    for task in rest.drain(..) {
        if moved + base >= cap || miss >= SLOT_MISS_CAP {
            kept.push_back(task);
            continue;
        }
        if let Some(t) = now {
            let old = task.wait_at != 0 && t >= task.wait_at && t - task.wait_at > floor_ns;
            if !old {
                miss += 1;
                kept.push_back(task);
                continue;
            }
        }
        let ok = task.live && !task.fail && crate::flow_select::may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
            miss = 0;
        } else {
            miss += 1;
            kept.push_back(task);
        }
    }
    *queue = kept;
    moved
}

/// True when one local window holds work.
/// Window holds the fast queue plus the deadline queue.
#[cfg(test)]
pub fn window_has_work(fast: bool, vtime: bool) -> bool {
    fast || vtime
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

/// First donor deadline queue id from one scan window with keep first.
/// Visits bound peers from start with wrap and keeps the first peer with
/// queued at or past need. Fast queues never take part, so stolen work
/// always comes from deadline queues. Returns the DSQ id on hit.
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
        return Some(vtime_dsq(peer));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const OVERFLOW_BELOW_LOCAL_ON: bool = SLOT_OVERFLOW < 0xc000000000000000;
    const QUEUE_COUNT_FITS: bool = SLOT_MAX_DSQS == 2049;

    #[test]
    fn ids_stay_below_local_on() {
        const { assert!(OVERFLOW_BELOW_LOCAL_ON) }
        const { assert!(QUEUE_COUNT_FITS) }
        assert!(fast_dsq(1023) < 0xc000000000000000);
        assert!(vtime_dsq(1023) < 0xc000000000000000);
        assert_eq!(slot_nr_dsqs(8), 17);
        assert_eq!(slot_overflow_dsq(), SLOT_OVERFLOW);
    }

    #[test]
    fn insert_targets_fast_or_overflow() {
        assert_eq!(insert_dsq(3, false, 8), FAST_BASE + 3);
        assert_eq!(insert_dsq(3, true, 8), SLOT_OVERFLOW);
        assert_eq!(insert_dsq(-1, false, 8), SLOT_GLOBAL);
        assert_eq!(insert_dsq(9, false, 8), SLOT_GLOBAL);
        assert_eq!(slot_global_dsq(), 0);
        assert_eq!(
            local_trip_dsqs(2),
            [FAST_BASE + 2, VTIME_BASE + 2, SLOT_OVERFLOW]
        );
    }

    #[test]
    fn caps_hold_budget_discipline() {
        assert_eq!(slot_cap(32), 4);
        assert_eq!(slot_cap(2), 2);
        assert_eq!(slot_own_cap(32), 12);
        assert_eq!(slot_own_cap(5), 5);
        assert_eq!(tail_cap(32), 4);
        assert_eq!(tail_cap(1), 1);
        assert_eq!(SLOT_GATED_CAP, 4);
        assert_eq!(SLOT_MISS_CAP, 4);
        assert_eq!(SLOT_OVER_CAP, 4);
        assert_eq!(SLOT_OWN_CAP, 12);
    }

    #[test]
    fn window_and_need_match_dispatch() {
        assert!(window_has_work(true, false));
        assert!(window_has_work(false, true));
        assert!(!window_has_work(false, false));
        assert_eq!(steal_need(true), 1);
        assert_eq!(steal_need(false), 2);
    }

    #[test]
    fn drain_moves_allowed_with_miss_cap() {
        let mut q = std::collections::VecDeque::from(vec![
            crate::flow_select::PendingTask {
                allowed: vec![true],
                exiting: false,
                live: true,
                fail: false,
                wait_at: 10,
            },
            crate::flow_select::PendingTask {
                allowed: vec![false],
                exiting: false,
                live: true,
                fail: false,
                wait_at: 10,
            },
        ]);
        assert_eq!(slot_drain_model(&mut q, 0, 4, 0), 1);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn starved_drain_skips_young_tasks() {
        let now = 10_000_000u64;
        let mut q = std::collections::VecDeque::from(vec![
            crate::flow_select::PendingTask {
                allowed: vec![true],
                exiting: false,
                live: true,
                fail: false,
                wait_at: now - 100,
            },
            crate::flow_select::PendingTask {
                allowed: vec![true],
                exiting: false,
                live: true,
                fail: false,
                wait_at: now - 5_000_000,
            },
        ]);
        assert_eq!(slot_drain_starved_model(&mut q, 0, 4, 0, now), 1);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn steal_never_touches_fast_queues() {
        let depths = vec![9u64; 4];
        let got = steal_first_donor(0, 4, 2, &depths).unwrap();
        assert_eq!(got, VTIME_BASE);
        assert_ne!(got, FAST_BASE);
        assert!(steal_first_donor(0, 1, 1, &depths).is_none());
    }
}
