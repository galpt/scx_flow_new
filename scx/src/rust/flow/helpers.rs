// SPDX-License-Identifier: GPL-2.0
//! Paired ledger helpers for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the paired share, order, task helpers for the mirror with
//! single exit through one return. Every admit pairs an add with a
//! drop exactly once in the mirror. Every remove pairs share drop,
//! order remove, task clear, view clear in one place. Every reject
//! parks keyed at the top key with order insert plus view store plus
//! parks accounting, mirroring the core reject path. Zero plus capped
//! parks stay rowless with counts solely. Callers reach all three
//! through here so a missed cleanup cannot leak shares or linger keys
//! in the mirror. Core owns authority with the mirror never gating
//! dispatch.

use super::Daemon;
use super::runtime::AdmitDecision;

impl Daemon {
    /// Park keyed at the top key with order plus view store.
    /// Stores the far deadline with the top key plus one head plus one
    /// owner view when the CPU fits, mirroring the core reject path so
    /// rejects drain ordered last. Zero identifiers park with no row
    /// change since zero never keys the tree. Capped tables park fresh
    /// identifiers with no row change so the map stays capped. Depth
    /// full parks keep the task row plus views with no order insert so
    /// order stays capped while the task cap still holds. Callers pass
    /// the enqueue sequence plus CPU plus now for the stored row.
    /// Callers return the parked decision at once.
    pub(crate) fn reject_park(
        &mut self,
        pid: u32,
        wire_seq: u64,
        cpu: u32,
        now: u64,
    ) -> AdmitDecision {
        if pid == 0 {
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        if !self.tasks.contains_key(&pid) && self.tasks.len() >= super::runtime::TASKS_CAP {
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        let store_cpu = if (cpu as u64) < super::slot::MAX_CPUS {
            cpu
        } else {
            0
        };
        let far = u64::MAX;
        self.tasks.insert(
            pid,
            super::runtime::TaskState {
                release: now,
                deadline: far,
                share: 0,
                admit_cpu: store_cpu,
                #[cfg(test)]
                wire_seq,
            },
        );
        if self.order.len() < super::runtime::ORDER_DEPTH_MAX {
            self.order.insert(pid, far, wire_seq);
        }
        self.store_views(pid, far, 0, store_cpu);
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
