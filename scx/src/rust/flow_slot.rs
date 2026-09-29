// SPDX-License-Identifier: GPL-2.0
//! Queue store helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! One local queue per CPU plus one shared queue per node plus one
//! machine queue plus one overflow tail.

/// Tasks moved by one dispatch pass at most. Fixed at 16 with no knob.
pub const SLOT_BUDGET: u32 = 16;
/// Local tier cap at 8 under budget 16. Fixed with no knob.
pub const SLOT_LOCAL_CAP: u32 = 8;
/// Node tier cap at 4 under budget 16. Fixed with no knob.
pub const SLOT_NODE_CAP: u32 = 4;
/// Machine tier cap at 2 under budget 16. Fixed with no knob.
pub const SLOT_MACHINE_CAP: u32 = 2;
/// Overflow tier cap at 2 under budget 16. Fixed with no knob.
pub const SLOT_OVER_CAP: u32 = 2;
/// Miss cap of one drain trip at 3. Fixed with no knob.
pub const SLOT_MISS_CAP: u32 = 3;
/// Base id of the per CPU local queues.
#[cfg(test)]
pub const LOCAL_BASE: u64 = 0x5100;
/// Base id of the per node shared queues.
#[cfg(test)]
pub const NODE_BASE: u64 = 0x5900;
/// Id of the machine queue shared by every CPU.
#[cfg(test)]
pub const SLOT_MACHINE: u64 = 0x5A00;
/// Id of the overflow tail shared by every CPU.
#[cfg(test)]
pub const SLOT_OVERFLOW: u64 = 0x5A01;
/// Id of the kernel global queue for homeless tasks.
#[cfg(test)]
pub const SLOT_GLOBAL: u64 = 0;
/// Max DSQs at 512 CPUs. Holds 512 local plus 8 node plus machine plus overflow.
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 522;
/// Max nodes bound shared with the BPF header.
#[cfg(test)]
pub const MAX_NODES: u64 = 8;

/// Local queue id of one CPU from base plus id.
/// One ordered queue per CPU keeps deadline order local.
#[cfg(test)]
pub fn local_dsq(cpu: u32) -> u64 {
    LOCAL_BASE + cpu as u64
}

/// Shared queue id of one node from base plus id.
/// One ordered queue per node shares work inside the node.
#[cfg(test)]
pub fn node_dsq(node: u32) -> u64 {
    NODE_BASE + node as u64
}

/// Id of the machine queue shared by every CPU.
/// Work with no node home rests here with mask wins on drain.
#[cfg(test)]
pub fn machine_dsq() -> u64 {
    SLOT_MACHINE
}

/// Id of the overflow tail shared by every CPU.
/// Missed parks plus pinned tasks rest here with mask wins on drain.
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

/// True when one id names a live scheduler queue.
/// Local plus node plus machine plus overflow pass, and all other
/// ids fail, so a stale id never moves work.
#[cfg(test)]
pub fn dsq_valid(dsq: u64) -> bool {
    if (LOCAL_BASE..LOCAL_BASE + 512).contains(&dsq) {
        return true;
    }
    if (NODE_BASE..NODE_BASE + MAX_NODES).contains(&dsq) {
        return true;
    }
    if dsq == SLOT_MACHINE {
        return true;
    }
    if dsq == SLOT_OVERFLOW {
        return true;
    }
    false
}

/// Count of DSQs for one host with local plus node plus two.
/// Holds 512 plus 8 plus 2 on a full host.
#[cfg(test)]
pub fn slot_nr_dsqs() -> u64 {
    SLOT_MAX_DSQS
}

/// Local tier cap at 8 under budget 16.
/// Holds 8 with budget 16, so the shared tier keeps room.
#[cfg(test)]
pub fn slot_local_cap(budget: u32) -> u32 {
    budget.min(SLOT_LOCAL_CAP)
}

/// Node tier cap at 4 under the dispatch budget.
/// Returns the min of budget and 4 with no head stall.
#[cfg(test)]
pub fn slot_node_cap(budget: u32) -> u32 {
    budget.min(SLOT_NODE_CAP)
}

/// Machine tier cap at 2 under the dispatch budget.
/// Returns the min of budget and 2 with no head stall.
#[cfg(test)]
pub fn slot_machine_cap(budget: u32) -> u32 {
    budget.min(SLOT_MACHINE_CAP)
}

/// Overflow tier cap at 2 under the dispatch budget.
/// Returns the min of budget and 2 with no head stall.
#[cfg(test)]
pub fn slot_over_cap(budget: u32) -> u32 {
    budget.min(SLOT_OVER_CAP)
}

/// Drain up to a cap from one queue for one CPU.
/// The scan visits queued tasks in queue order and moves each live
/// task with the CPU in the mask. Dead, foreign, and failed tasks count
/// one miss each with a miss cap at 3, so one bad head never blocks later
/// work. The walk stops at cap plus base with no full scan.
/// Returns the count moved.
#[cfg(test)]
pub fn slot_drain_model(
    queue: &mut std::collections::VecDeque<crate::flow::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
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
        let ok = task.live && !task.fail && crate::flow::may_run_on(cpu, &task.allowed);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_header() {
        assert_eq!(LOCAL_BASE, 0x5100);
        assert_eq!(NODE_BASE, 0x5900);
        assert_eq!(SLOT_MACHINE, 0x5A00);
        assert_eq!(SLOT_OVERFLOW, 0x5A01);
        assert_eq!(SLOT_GLOBAL, 0);
        assert_eq!(SLOT_MAX_DSQS, 522);
        assert_eq!(slot_global_dsq(), SLOT_GLOBAL);
        assert_eq!(slot_nr_dsqs(), SLOT_MAX_DSQS);
        assert!(dsq_valid(local_dsq(0)));
        assert!(dsq_valid(local_dsq(511)));
        assert!(!dsq_valid(local_dsq(512)));
        assert!(dsq_valid(node_dsq(0)));
        assert!(dsq_valid(node_dsq(7)));
        assert!(!dsq_valid(node_dsq(8)));
        assert!(dsq_valid(machine_dsq()));
        assert!(dsq_valid(slot_overflow_dsq()));
        assert!(!dsq_valid(0x6000));
    }

    #[test]
    fn caps_fit_budget() {
        assert_eq!(SLOT_BUDGET, 16);
        assert_eq!(slot_local_cap(16), 8);
        assert_eq!(slot_node_cap(16), 4);
        assert_eq!(slot_machine_cap(16), 2);
        assert_eq!(slot_over_cap(16), 2);
        assert_eq!(SLOT_MISS_CAP, 3);
    }

    #[test]
    fn drain_moves_allowed_in_order() {
        let mut q = std::collections::VecDeque::from([
            crate::flow::PendingTask::live(&[0], 100),
            crate::flow::PendingTask {
                live: false,
                fail: false,
                allowed: vec![0],
                deadline: 100,
                depth_ahead: 0,
            },
            crate::flow::PendingTask::live(&[1], 100),
        ]);
        let moved = slot_drain_model(&mut q, 0, 16, 0);
        assert_eq!(moved, 1);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn drain_stops_at_miss_cap() {
        let mut q = std::collections::VecDeque::from([
            crate::flow::PendingTask::live(&[1], 100),
            crate::flow::PendingTask::live(&[1], 100),
            crate::flow::PendingTask::live(&[1], 100),
            crate::flow::PendingTask::live(&[1], 100),
            crate::flow::PendingTask::live(&[0], 100),
        ]);
        let moved = slot_drain_model(&mut q, 0, 16, 0);
        assert_eq!(moved, 0);
        assert_eq!(q.len(), 5);
    }
}
