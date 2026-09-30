// SPDX-License-Identifier: GPL-2.0
//! Queue identifiers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the queue identifiers. One local queue serves each CPU. One
//! shared queue serves each node. One machine queue serves the host.
//! One overflow tail serves parks. Init reserves the full set as an
//! ABI placeholder so identifiers stay stable across releases while
//! dispatch moves admitted tasks in daemon order. A single tail
//! avoids cross tier moves that would bounce cache and NUMA locality.
//! Undrained queues hold zero tasks and cost solely at init.

/// Bound for CPUs served. Mirrors the BPF header.
pub const MAX_CPUS: u64 = 512;
/// Bound for nodes served. Mirrors the BPF header.
#[cfg(test)]
pub const MAX_NODES: u64 = 8;
/// Base identifier of the per CPU local queues.
#[cfg(test)]
pub const LOCAL_BASE: u64 = 0x5100;
/// Base identifier of the per node shared queues.
#[cfg(test)]
pub const NODE_BASE: u64 = 0x5900;
/// Identifier of the machine queue shared by every CPU.
#[cfg(test)]
pub const SLOT_MACHINE: u64 = 0x5A00;
/// Identifier of the overflow tail shared by every CPU.
#[cfg(test)]
pub const SLOT_OVERFLOW: u64 = 0x5A01;
/// Queue count at five hundred twelve local, eight node, two shared.
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 522;

/// Local queue identifier of one CPU from base plus identifier.
/// One ordered queue per CPU keeps deadline order near the CPU.
#[cfg(test)]
pub fn local_dsq(cpu: u32) -> u64 {
    LOCAL_BASE + cpu as u64
}

/// Shared queue identifier of one node from base plus identifier.
/// One ordered queue per node shares work inside the node.
#[cfg(test)]
pub fn node_dsq(node: u32) -> u64 {
    NODE_BASE + node as u64
}

/// Identifier of the machine queue shared by every CPU.
/// Work resting here waits for the next free CPU.
#[cfg(test)]
pub fn machine_dsq() -> u64 {
    SLOT_MACHINE
}

/// Identifier of the overflow tail shared by every CPU.
/// Parks rest here with no run until admit.
#[cfg(test)]
pub fn slot_overflow_dsq() -> u64 {
    SLOT_OVERFLOW
}

/// True when one identifier names a live queue.
/// Local, node, machine, overflow pass. Stale identifiers fail.
#[cfg(test)]
pub fn dsq_valid(dsq: u64) -> bool {
    if (LOCAL_BASE..LOCAL_BASE + MAX_CPUS).contains(&dsq) {
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

/// Queue count for one host with local, node, two shared.
/// Holds five hundred twenty two on a full host.
#[cfg(test)]
pub fn slot_nr_dsqs() -> u64 {
    SLOT_MAX_DSQS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_match_header() {
        assert_eq!(LOCAL_BASE, 0x5100);
        assert_eq!(NODE_BASE, 0x5900);
        assert_eq!(SLOT_MACHINE, 0x5A00);
        assert_eq!(SLOT_OVERFLOW, 0x5A01);
        assert_eq!(SLOT_MAX_DSQS, 522);
        assert_eq!(slot_nr_dsqs(), SLOT_MAX_DSQS);
        assert!(dsq_valid(local_dsq(0)));
        assert!(dsq_valid(local_dsq(511)));
        assert!(!dsq_valid(local_dsq(512)));
        assert!(dsq_valid(node_dsq(0)));
        assert!(dsq_valid(node_dsq(7)));
        assert!(!dsq_valid(node_dsq(8)));
        assert!(dsq_valid(machine_dsq()));
        assert!(dsq_valid(slot_overflow_dsq()));
        assert!(!dsq_valid(0));
        assert!(!dsq_valid(0x6000));
    }
}
