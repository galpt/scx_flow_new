// SPDX-License-Identifier: GPL-2.0
//! Paired ledger helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the paired share, order, task helpers for the mirror with
//! single exit through one return. Every admit pairs an add with a
//! drop exactly once in the mirror. Every remove pairs share drop,
//! order remove, task clear, view clear in one place. Every reject
//! pairs order cleanup with view cleanup plus parks accounting.
//! Callers reach all three through here so a missed cleanup cannot
//! leak shares or linger keys in the mirror. Core owns authority with
//! the mirror never gating dispatch.

use super::Daemon;
use super::runtime::AdmitDecision;

impl Daemon {
    /// Park with order plus view cleanup plus parks accounting.
    /// Clears the order row plus cached views then counts one reject
    /// plus one park. Zero identifiers park with no row change. Fresh
    /// identifiers park with no share drop. Stale CPUs plus deep queues
    /// park after the caller drops the stored share. Callers return the
    /// parked decision at once with no extra work.
    pub(crate) fn reject_park(&mut self, pid: u32) -> AdmitDecision {
        self.order.remove(pid);
        self.clear_views(pid);
        self.rejects += 1;
        self.parks += 1;
        AdmitDecision::Park
    }

    /// Clear share plus order plus views in one place with no counters.
    /// Drops the stored share then clears the order row plus cached
    /// views. Missing rows pass through with no state change. Requeue
    /// refresh uses this before the fresh insert so the old share plus
    /// old views never linger. Lost enqueue cleanup uses this so
    /// unknown identifiers leave no key.
    pub(crate) fn unpublish(&mut self, pid: u32) {
        self.drop_stored(pid);
        self.order.remove(pid);
        self.clear_views(pid);
    }

    /// Clear share, order, task, views in one place with no counters.
    /// Drops the stored share then clears the order row then clears the
    /// task row plus cached views. Complete plus stale collection use
    /// this so admitted sums never leak and stale order never runs.
    /// Missing rows pass through with no state change.
    pub(crate) fn remove_row(&mut self, pid: u32) {
        self.drop_stored(pid);
        self.order.remove(pid);
        self.tasks.remove(&pid);
        self.clear_views(pid);
    }

    /// Clear cached head plus owner views for one task.
    /// Drops the owner view plus any low byte slot pointing at the pid,
    /// so a removed task never lingers as a hint. Zero identifiers pass
    /// through with no change. Best effort with validation before use,
    /// so a missed clear still falls back with no wrong move.
    fn clear_views(&mut self, pid: u32) {
        if pid == 0 {
            return;
        }
        self.mask_hint.remove(&pid);
        let stale: Vec<u32> = self
            .head_hint
            .iter()
            .filter_map(|(k, v)| (v.1 == pid).then_some(*k))
            .collect();
        for k in stale {
            self.head_hint.remove(&k);
        }
    }
}
