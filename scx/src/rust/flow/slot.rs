// SPDX-License-Identifier: GPL-2.0
//! Queue store helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! One local queue per CPU plus one shared queue per node plus one
//! machine queue with no overflow tail. Every queue uses the kernel
//! priority queue with deadline order, so no queue mixes orders.
//! Homeless tasks wait in the machine queue with all other shared
//! work, so no queue id names the kernel global queue. Dispatch
//! drains local plus node plus machine in priority order with moves
//! uncapped to remaining slots and visits capped at 64 per pass.

/// Base id of the per CPU local queues.
#[cfg(test)]
pub const LOCAL_BASE: u64 = 0x5100;
/// Base id of the per node shared queues.
#[cfg(test)]
pub const NODE_BASE: u64 = 0x5900;
/// Id of the machine queue shared by every CPU.
#[cfg(test)]
pub const SLOT_MACHINE: u64 = 0x5A00;
/// Max DSQs at 512 CPUs. Holds 512 local plus 8 node plus machine.
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 521;
/// Max nodes bound shared with the BPF header.
#[cfg(test)]
pub const MAX_NODES: u64 = 8;

/// Local queue id of one CPU from base plus id.
/// One priority queue per CPU keeps deadline order local.
#[cfg(test)]
pub fn local_dsq(cpu: u32) -> u64 {
    LOCAL_BASE + cpu as u64
}

/// Shared queue id of one node from base plus id.
/// One priority queue per node shares work inside the node.
#[cfg(test)]
pub fn node_dsq(node: u32) -> u64 {
    NODE_BASE + node as u64
}

/// Id of the machine queue shared by every CPU.
/// Work with no node home rests here priority ordered with mask wins.
#[cfg(test)]
pub fn machine_dsq() -> u64 {
    SLOT_MACHINE
}

/// True when one id names a live scheduler queue.
/// Local plus node plus machine pass, and all other ids fail, so a
/// stale id never moves work. The kernel global queue stays out on
/// purpose with homeless work in the machine queue.
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
    false
}

/// Count of DSQs for one host with local plus node plus one.
/// Holds 512 plus 8 plus 1 on a full host.
#[cfg(test)]
pub fn slot_nr_dsqs() -> u64 {
    SLOT_MAX_DSQS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_header() {
        assert_eq!(LOCAL_BASE, 0x5100);
        assert_eq!(NODE_BASE, 0x5900);
        assert_eq!(SLOT_MACHINE, 0x5A00);
        assert_eq!(SLOT_MAX_DSQS, 521);
        assert_eq!(slot_nr_dsqs(), SLOT_MAX_DSQS);
        assert!(dsq_valid(local_dsq(0)));
        assert!(dsq_valid(local_dsq(511)));
        assert!(!dsq_valid(local_dsq(512)));
        assert!(dsq_valid(node_dsq(0)));
        assert!(dsq_valid(node_dsq(7)));
        assert!(!dsq_valid(node_dsq(8)));
        assert!(dsq_valid(machine_dsq()));
        assert!(!dsq_valid(0));
        assert!(!dsq_valid(0x5A01));
        assert!(!dsq_valid(0x6000));
    }
}
