// SPDX-License-Identifier: GPL-2.0
//! Daemon order plus admission plus protocol for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the daemon order plus the admission table plus the wire
//! protocol. The daemon keeps one quantized queue plus one admitted
//! row per CPU plus one hint table. Order follows deadlines solely
//! through the quantized tree. The BPF core parks FIFO and notifies.
//! The daemon order stays a shadow view for observability while the
//! core executes FIFO. Times stay in the monotonic domain shared with
//! the core. Parks include backpressure drops. Hints stay derived
//! from task weight keyed by task identifier.

use std::collections::HashMap;

use super::cgrp::HintTable;
use super::veb::FlowVeb;

/// Wire kind for enqueue notify from the core.
pub const PROTO_ENQUEUE: u64 = 1;
/// Reserved kind for daemon internal order decisions. Never emitted
/// by the core. Observed values hold at the core with progress kept.
pub const PROTO_ORDER: u64 = 2;
/// Reserved kind for daemon internal dispatch decisions. Never
/// emitted by the core. Observed values hold at the core.
pub const PROTO_DISPATCH: u64 = 3;
/// Wire kind for complete notify from the core.
pub const PROTO_COMPLETE: u64 = 4;
/// First sequence handed to fresh tasks.
pub const SEQ_INIT: u64 = 1;
/// Max queued entries tracked before the core parks FIFO.
pub const ORDER_DEPTH_MAX: usize = 512;
/// Max moves per dispatch pass. Mirrors the BPF header.
pub const DISPATCH_BATCH: usize = 16;

/// Admission decision for one enqueue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Admitted with the stored share in per mille.
    Admit {
        /// Stored share held until complete.
        share: u64,
        /// CPU holding the share.
        cpu: u32,
    },
    /// Parked FIFO with the core holding the task.
    Park,
}

/// Fail reason for the fail open matrix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailReason {
    /// Ring pressure dropped one notify.
    RingFull,
    /// Sequence gap found one lost notify.
    SeqGap,
    /// Daemon lag left the core waiting.
    DaemonLag,
    /// Stale CPU met one notify.
    BadCpu,
    /// Stale key met one order.
    BadKey,
}

/// Fail open action taken by the core or by the daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailAction {
    /// Park FIFO at the overflow tail.
    ParkFifo,
    /// Resync sequence from the next notify.
    Resync,
    /// Drop the stored share and park FIFO.
    DropShare,
    /// Hold the task at the core with an idle kick.
    HoldKick,
}

/// Fail open matrix shared by the core and by the daemon.
/// ParkFifo parks FIFO. Resync accepts the fresh sequence.
/// DropShare drops the stored share then parks. HoldKick holds at
/// the core with progress preserved.
pub fn fail_open(reason: &FailReason) -> FailAction {
    match reason {
        FailReason::RingFull => FailAction::ParkFifo,
        FailReason::SeqGap => FailAction::Resync,
        FailReason::DaemonLag => FailAction::ParkFifo,
        FailReason::BadCpu => FailAction::DropShare,
        FailReason::BadKey => FailAction::HoldKick,
    }
}

/// Per task state held by the daemon.
/// Share stays zero for parks. Admit CPU names the row holding the
/// share. Release anchors the miss check. Order uses deadlines
/// solely with stored shares for admission.
#[derive(Clone, Debug)]
pub struct TaskState {
    /// Last release time in nanos.
    pub release: u64,
    /// Absolute deadline in nanos.
    pub deadline: u64,
    /// Stored per mille share with zero for parks.
    pub share: u64,
    /// CPU holding the stored share.
    pub admit_cpu: u32,
}

/// Daemon holding the quantized queue plus admission rows.
/// Admitted rows hold one per mille sum per CPU. Tasks hold one
/// stored share each. Adds pair with drops exactly once per admit.
/// Wire sequence tracks notifies while order sequence tracks queued
/// tasks. Disable plus exit notifies drop shares through complete.
pub struct Daemon {
    order: FlowVeb,
    hints: HintTable,
    admitted: Vec<u64>,
    tasks: HashMap<u32, TaskState>,
    next_seq: u64,
    wire_last: u64,
    /// Tasks admitted under the use bound.
    pub admits: u64,
    /// Tasks parked on admission reject.
    pub rejects: u64,
    /// Monotonic completions past release plus deadline.
    pub misses: u64,
    /// Overflow parks from misses plus rejects plus drops.
    pub parks: u64,
}

impl Daemon {
    /// Empty daemon over five hundred twelve CPUs.
    pub fn new() -> Self {
        Self {
            order: FlowVeb::new(),
            hints: HintTable::new(),
            admitted: vec![0u64; super::slot::MAX_CPUS as usize],
            tasks: HashMap::new(),
            next_seq: SEQ_INIT,
            wire_last: 0,
            admits: 0,
            rejects: 0,
            misses: 0,
            parks: 0,
        }
    }

    /// Hint table for weight derived updates.
    pub fn hints_mut(&mut self) -> &mut HintTable {
        &mut self.hints
    }

    /// Admitted per mille sum for one CPU with zero past the bound.
    pub fn admitted(&self, cpu: u32) -> u64 {
        self.admitted.get(cpu as usize).copied().unwrap_or(0)
    }

    /// Queued entry count now held in the tree.
    #[cfg(test)]
    pub fn queue_len(&self) -> usize {
        self.order.len()
    }

    /// Least queued entry with empty for vacant queues.
    #[cfg(test)]
    pub fn peek_order(&self) -> Option<super::veb::FlowEntry> {
        self.order.peek_min().cloned()
    }

    /// Last observed wire sequence.
    #[cfg(test)]
    pub fn wire_last(&self) -> u64 {
        self.wire_last
    }

    /// Next order sequence for fresh admits.
    #[cfg(test)]
    pub fn next_order(&self) -> u64 {
        self.next_seq
    }

    /// Share of one hint through the default period on miss.
    /// A two millisecond slice in a sixteen millisecond period takes
    /// one hundred twenty five per mille.
    #[cfg(test)]
    pub fn share_for(&self, hint_us: u32) -> u64 {
        let period = super::edf::task_period(hint_us);
        super::edf::slice_permillle(period)
    }

    /// Drop the stored share of one task with floor at zero.
    /// Clears the stored value so repeat drops stay empty.
    pub(crate) fn drop_stored(&mut self, pid: u32) {
        let (share, cpu) = match self.tasks.get(&pid) {
            Some(t) => (t.share, t.admit_cpu),
            None => return,
        };
        if share == 0 {
            return;
        }
        if let Some(row) = self.admitted.get_mut(cpu as usize) {
            *row = row.saturating_sub(share);
        }
        if let Some(t) = self.tasks.get_mut(&pid) {
            t.share = 0;
            t.admit_cpu = 0;
        }
    }

    /// Handle one enqueue notify from the core.
    /// Fresh hints flow through the hint table. Stored shares add
    /// once and drop once. Rejects park FIFO at the core. Stale CPUs
    /// drop the stored share then park. Depth overflow drops the
    /// stored share then parks. Order sequence advances solely on
    /// admits while wire sequence stays untouched here.
    pub fn handle_enqueue(&mut self, pid: u32, hint_us: u32, cpu: u32, now: u64) -> AdmitDecision {
        if cpu as u64 >= super::slot::MAX_CPUS {
            let action = fail_open(&FailReason::BadCpu);
            debug_assert_eq!(action, FailAction::DropShare);
            self.drop_stored(pid);
            self.order.remove(pid);
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        if self.order.len() >= ORDER_DEPTH_MAX {
            self.drop_stored(pid);
            self.order.remove(pid);
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        if self.tasks.contains_key(&pid) {
            self.drop_stored(pid);
            self.order.remove(pid);
        }
        let hint = if hint_us != 0 {
            hint_us
        } else {
            self.hints.lookup(pid as u64) as u32
        };
        let period = super::edf::task_period(hint);
        let deadline = super::edf::deadline_at(now, period);
        let share = super::edf::slice_permillle(period);
        let held = self.admitted(cpu);
        if share != 0 && !super::edf::admit_ok(held, share) {
            self.tasks.insert(
                pid,
                TaskState {
                    release: now,
                    deadline,
                    share: 0,
                    admit_cpu: 0,
                },
            );
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        if share != 0 {
            let row = &mut self.admitted[cpu as usize];
            *row = row.saturating_add(share);
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.tasks.insert(
            pid,
            TaskState {
                release: now,
                deadline,
                share,
                admit_cpu: cpu,
            },
        );
        self.order.insert(pid, deadline, seq);
        self.admits += 1;
        AdmitDecision::Admit { share, cpu }
    }

    /// Handle one complete notify from the core.
    /// Drops the stored share exactly once. Misses count when
    /// monotonic time passes release plus deadline on a blocking
    /// complete. Runtime charge stays in the core total.
    pub fn handle_complete(&mut self, pid: u32, now: u64, runnable: bool) {
        let (release, deadline) = match self.tasks.get(&pid) {
            Some(t) => (t.release, t.deadline),
            None => {
                self.order.remove(pid);
                return;
            }
        };
        self.drop_stored(pid);
        self.order.remove(pid);
        if !runnable && super::edf::missed(release, deadline, now) {
            self.misses += 1;
            self.parks += 1;
        }
        self.tasks.remove(&pid);
    }

    /// Note one observed wire sequence.
    /// In order notifies advance the wire mark. Duplicates plus
    /// reorder plus forward jumps report resync through the fail open
    /// matrix. Zero stays ignored. Callers execute the resync park.
    pub fn note_seq(&mut self, seq: u64) -> FailAction {
        if seq == 0 {
            return FailAction::ParkFifo;
        }
        if seq <= self.wire_last {
            self.wire_last = self.wire_last.max(seq);
            return fail_open(&FailReason::SeqGap);
        }
        if self.wire_last != 0 && seq > self.wire_last.saturating_add(1) {
            self.wire_last = seq;
            return fail_open(&FailReason::SeqGap);
        }
        self.wire_last = seq;
        FailAction::ParkFifo
    }

    /// Pick one CPU for one task through the shared placement model.
    /// Callers pass live depths in rank order.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn pick_cpu(
        &self,
        idle: &[i32],
        prev: i32,
        allowed: &[i32],
        live: &[i32],
        depths: &[u64],
        deadline: u64,
        now: u64,
    ) -> i32 {
        super::select::place(idle, prev, allowed, live, depths, deadline, now)
    }

    /// True when one arrival preempts the occupant.
    #[cfg(test)]
    pub fn should_kick(&self, arrival: u64, occupant: u64) -> bool {
        super::preempt::arrival_kicks(arrival, occupant)
    }

    /// Queue identifier for one CPU with overflow past the bound.
    #[cfg(test)]
    pub fn queue_for(&self, cpu: u32) -> u64 {
        if (cpu as u64) < super::slot::MAX_CPUS {
            return super::slot::local_dsq(cpu);
        }
        super::slot::slot_overflow_dsq()
    }
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_is_125_at_default_period() {
        let d = Daemon::new();
        assert_eq!(d.share_for(0), 125);
        assert_eq!(d.share_for(8000), 250);
    }

    #[test]
    fn admit_holds_950_bound_with_stored_drop_once() {
        let mut d = Daemon::new();
        for pid in 1..=7u32 {
            let got = d.handle_enqueue(pid, 0, 0, 1_000_000);
            assert!(matches!(got, AdmitDecision::Admit { .. }));
        }
        assert_eq!(d.admitted(0), 875);
        let got = d.handle_enqueue(8, 0, 0, 1_000_000);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.rejects, 1);
        assert_eq!(d.parks, 1);
        d.handle_complete(1, 2_000_000, true);
        assert_eq!(d.admitted(0), 750);
        d.handle_complete(1, 2_000_000, true);
        assert_eq!(d.admitted(0), 750);
        let got = d.handle_enqueue(8, 0, 0, 2_000_000);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admits, 8);
    }

    #[test]
    fn stale_cpu_and_depth_drop_stored_share() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(1, 0, 0, 1_000_000);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admitted(0), 125);
        let got = d.handle_enqueue(1, 0, 9999, 2_000_000);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.admitted(0), 0);
        assert_eq!(d.queue_len(), 0);
    }

    #[test]
    fn order_follows_least_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000);
        d.handle_enqueue(2, 4000, 0, 1_000_000);
        let top = d.peek_order().unwrap();
        assert_eq!(top.pid, 2);
        assert_eq!(d.queue_len(), 2);
    }

    #[test]
    fn miss_counts_on_blocking_complete_past_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 4000, 0, 1_000_000);
        d.handle_complete(1, 1_000_000 + 4_000_000 + 1, false);
        assert_eq!(d.misses, 1);
        assert_eq!(d.parks, 1);
    }

    #[test]
    fn wire_and_order_sequences_stay_split() {
        let mut d = Daemon::new();
        assert_eq!(d.note_seq(1), FailAction::ParkFifo);
        assert_eq!(d.wire_last(), 1);
        let order_before = d.next_order();
        let got = d.handle_enqueue(10, 0, 0, 1_000_000);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.wire_last(), 1);
        assert_eq!(d.next_order(), order_before.saturating_add(1));
        assert_eq!(d.note_seq(2), FailAction::ParkFifo);
        assert_eq!(d.wire_last(), 2);
        assert_eq!(d.note_seq(2), FailAction::Resync);
        assert_eq!(d.wire_last(), 2);
        assert_eq!(d.note_seq(10), FailAction::Resync);
        assert_eq!(d.wire_last(), 10);
    }

    #[test]
    fn fail_open_matrix_parks_forward() {
        assert_eq!(fail_open(&FailReason::RingFull), FailAction::ParkFifo);
        assert_eq!(fail_open(&FailReason::SeqGap), FailAction::Resync);
        assert_eq!(fail_open(&FailReason::DaemonLag), FailAction::ParkFifo);
        assert_eq!(fail_open(&FailReason::BadCpu), FailAction::DropShare);
        assert_eq!(fail_open(&FailReason::BadKey), FailAction::HoldKick);
        assert_eq!(PROTO_ENQUEUE, 1);
        assert_eq!(PROTO_ORDER, 2);
        assert_eq!(PROTO_DISPATCH, 3);
        assert_eq!(PROTO_COMPLETE, 4);
        assert_eq!(DISPATCH_BATCH, 16);
    }

    #[test]
    fn placement_and_kick_helpers_wire() {
        let d = Daemon::new();
        assert_eq!(d.pick_cpu(&[1], 0, &[0, 1], &[0, 1], &[0, 0], 100, 0), 1);
        assert!(d.should_kick(10, 20));
        assert_eq!(d.queue_for(0), crate::flow::slot::local_dsq(0));
        assert_eq!(d.queue_for(9999), crate::flow::slot::slot_overflow_dsq());
    }
}
