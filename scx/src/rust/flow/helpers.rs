// SPDX-License-Identifier: GPL-2.0
//! Paired ledger helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the paired share, order, task helpers for the mirror with
//! single exit through one return. Every admit pairs an add with a
//! drop exactly once in the mirror. Every remove pairs share drop,
//! order remove, task clear in one place. Every reject pairs order
//! cleanup with parks accounting. Callers reach all three through
//! here so a missed cleanup cannot leak shares or linger keys in the
//! mirror. Core owns authority with the mirror never gating dispatch.

use super::Daemon;
use super::runtime::AdmitDecision;

impl Daemon {
    /// Park with order cleanup plus parks accounting in one place.
    /// Drops the stored share when asked then clears the order row then
    /// counts one reject plus one park. Zero identifiers park with no
    /// row change. Fresh identifiers park with no share drop. Stale
    /// CPUs plus deep queues park with share drop. Callers return the
    /// parked decision at once with no extra work.
    pub(crate) fn reject_park(&mut self, pid: u32, drop: bool) -> AdmitDecision {
        if drop {
            self.drop_stored(pid);
        }
        self.order.remove(pid);
        self.rejects += 1;
        self.parks += 1;
        AdmitDecision::Park
    }

    /// Clear share plus order in one place with no counters.
    /// Drops the stored share then clears the order row. Missing rows
    /// pass through with no state change. Requeue refresh uses this
    /// before the fresh insert so the old share never lingers. Lost
    /// enqueue cleanup uses this so unknown identifiers leave no key.
    pub(crate) fn unpublish(&mut self, pid: u32) {
        self.drop_stored(pid);
        self.order.remove(pid);
    }

    /// Clear share, order, task in one place with no counters.
    /// Drops the stored share then clears the order row then clears the
    /// task row. Complete plus stale collection use this so admitted
    /// sums never leak and stale order never runs. Missing rows pass
    /// through with no state change.
    pub(crate) fn remove_row(&mut self, pid: u32) {
        self.drop_stored(pid);
        self.order.remove(pid);
        self.tasks.remove(&pid);
    }
}
