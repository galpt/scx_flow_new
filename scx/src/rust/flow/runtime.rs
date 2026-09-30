// SPDX-License-Identifier: GPL-2.0
//! Daemon order, admission, protocol for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the daemon order, the admission table, the wire
//! protocol. The daemon keeps one quantized queue, one admitted
//! row per CPU, one hint table. Order follows deadlines solely
//! through the quantized tree. The BPF core parks and notifies.
//! Dispatch moves admitted tasks in daemon order with sequence plus
//! liveness checks and parks stale entries. Order cost stays on the
//! userspace thread within five hundred twelve entries and stays off
//! the BPF hot path. Times stay in the monotonic domain shared with
//! the core. Parks include backpressure drops, ring drops, userspace
//! queue drops. Queue backlog is the channel length and drop rate is
//! the parks delta, so both stay visible with zero wire change.
//! Hints stay derived from task weight keyed by task identifier.
//! Lost completes collect past deadline plus grace.

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
/// Max queued entries tracked before the core parks with no run.
pub const ORDER_DEPTH_MAX: usize = 512;
/// Max moves per dispatch pass. Mirrors the BPF header.
pub const DISPATCH_BATCH: usize = 16;
/// Bound for the userspace event queue at twice order depth.
/// Holds enqueue plus complete pairs per burst. Full queues drop with
/// parks accounting and latest state reconciles on the next notify.
pub const EV_CAP: usize = 1024;
/// Cap for one userspace drain pass at twice order depth.
/// Drains run until empty or cap with remainder deferred to the next
/// poll. Twice depth absorbs one enqueue plus one complete per slot.
pub const DRAIN_CAP: usize = ORDER_DEPTH_MAX * 2;
/// Bound for live task rows matching the hint bound.
/// Fresh identifiers park when full so the map stays capped.
pub const TASKS_CAP: usize = 4096;
/// Grace past deadline before lost complete collection in nanos.
/// Eight periods cover slow wakeups while leaked shares still return.
pub const STALE_GRACE_NS: u64 = 128_000_000;
/// Guard that depth growth needs a position index for removal.
/// Removal scans one key queue within depth, so deeper bounds need an
/// index to stay cheap.
const _: () = assert!(ORDER_DEPTH_MAX <= 512);
/// Guard that reserved wire kinds stay stable for the daemon.
/// Order plus dispatch never emit from the core and hold at the core.
const _: () = assert!(PROTO_ORDER == 2 && PROTO_DISPATCH == 3);
/// Guard that the dispatch batch mirrors the BPF header.
/// Userspace drains use the deeper drain cap while the core moves one
/// per pass.
const _: () = assert!(DISPATCH_BATCH == 16);

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
    /// Parked with the core holding the task and no run.
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
/// share. Release anchors the miss check. Wire sequence pairs the
/// daemon order entry with the core task state for dispatch checks.
/// Order uses deadlines solely with stored shares for admission.
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
    /// Wire sequence from the enqueue notify.
    pub wire_seq: u64,
}

/// Daemon holding the quantized queue plus admission rows.
/// Admitted rows hold one per mille sum per CPU. Tasks hold one
/// stored share each. Adds pair with drops exactly once per admit.
/// Wire sequence tracks notifies while order sequence tracks queued
/// tasks. Disable plus exit notifies drop shares through complete.
/// Task rows stay capped at the task bound. Stale rows collect past
/// deadline plus grace. Queue drops fold into parks plus the drop
/// gauge with zero wire change.
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
    /// Overflow parks from misses, rejects, drops.
    pub parks: u64,
    /// Userspace queue drops folded into parks. Internal gauge with
    /// zero wire change. Parks delta shows drop rate on the wire.
    pub ev_drops: u64,
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
            ev_drops: 0,
        }
    }

    /// Live task row count now held.
    #[cfg(test)]
    pub fn task_len(&self) -> usize {
        self.tasks.len()
    }

    /// Note one userspace queue drop with parks accounting.
    /// Keeps the wire visible parks sum plus an internal drop gauge.
    /// Ring pressure maps to park through the fail open matrix.
    pub fn note_ev_drop(&mut self) {
        let action = fail_open(&FailReason::RingFull);
        debug_assert_eq!(action, FailAction::ParkFifo);
        self.ev_drops = self.ev_drops.saturating_add(1);
        self.parks = self.parks.saturating_add(1);
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

    /// Admitted entries in dispatch order for the core map.
    /// Each row carries pid, wire sequence, deadline, admit CPU.
    /// Parks stay out so rejects park with no run. The core checks
    /// the wire sequence against task state plus CPU affinity and
    /// moves admitted tasks in this order up to the batch bound.
    #[cfg(test)]
    pub fn ordered_entries(&self) -> Vec<(u32, u64, u64, u32)> {
        let mut out = Vec::with_capacity(self.order.len());
        for e in self.order.ordered() {
            if let Some(t) = self.tasks.get(&e.pid)
                && t.share != 0
            {
                out.push((e.pid, t.wire_seq, t.deadline, t.admit_cpu));
            }
        }
        out
    }

    /// Stored row for one pid with empty for unknown identifiers.
    pub fn task(&self, pid: u32) -> Option<&TaskState> {
        self.tasks.get(&pid)
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
    /// once and drop once. Rejects park with no run at the core.
    /// Zero identifiers park at once with no table row. Stale CPUs
    /// drop the stored share then park. Depth overflow drops the
    /// stored share then parks. Table full parks fresh identifiers
    /// with zero stored share so the map stays capped. Order sequence
    /// advances solely on admits while the wire sequence pairs each
    /// row with core task state for dispatch.
    pub fn handle_enqueue(
        &mut self,
        pid: u32,
        hint_us: u32,
        cpu: u32,
        now: u64,
        wire_seq: u64,
    ) -> AdmitDecision {
        if pid == 0 {
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
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
        if !self.tasks.contains_key(&pid) && self.tasks.len() >= TASKS_CAP {
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
                    wire_seq,
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
                wire_seq,
            },
        );
        self.order.insert(pid, deadline, seq);
        self.admits += 1;
        AdmitDecision::Admit { share, cpu }
    }

    /// Handle one complete notify from the core.
    /// Drops the stored share exactly once. Misses count when
    /// monotonic time passes release plus deadline on a blocking
    /// complete. Runtime charge stays in the core total. Zero
    /// identifiers pass through with no state change. Unknown
    /// identifiers pass through after order cleanup, so a lost enqueue
    /// never leaks a share.
    pub fn handle_complete(&mut self, pid: u32, now: u64, runnable: bool) {
        if pid == 0 {
            return;
        }
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

    /// Collect stale rows past deadline plus grace.
    /// Drops stored shares then clears order plus task rows. Lost
    /// completes return shares here so admitted sums never leak.
    /// Callers pass monotonic now and poll at a slow cadence.
    /// Returns removed pids for core map cleanup.
    pub fn gc_stale(&mut self, now: u64) -> Vec<u32> {
        if self.tasks.is_empty() {
            return Vec::new();
        }
        let mut stale = Vec::new();
        for (pid, task) in self.tasks.iter() {
            let limit = task.deadline.saturating_add(STALE_GRACE_NS);
            if task.release != 0 && task.deadline != 0 && now > limit {
                stale.push(*pid);
            }
        }
        for pid in &stale {
            self.drop_stored(*pid);
            self.order.remove(*pid);
            self.tasks.remove(pid);
        }
        stale
    }

    /// Note one observed wire sequence.
    /// In order notifies advance the wire mark. Duplicates,
    /// reorder, forward jumps report resync through the fail open
    /// matrix. Zero stays ignored. The first notify after attach
    /// accepts any sequence as a mid attach edge with zero resync, so
    /// tasks queued before attach never count a false gap. Callers
    /// execute the resync park.
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
            let got = d.handle_enqueue(pid, 0, 0, 1_000_000, pid as u64);
            assert!(matches!(got, AdmitDecision::Admit { .. }));
        }
        assert_eq!(d.admitted(0), 875);
        let got = d.handle_enqueue(8, 0, 0, 1_000_000, 8);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.rejects, 1);
        assert_eq!(d.parks, 1);
        d.handle_complete(1, 2_000_000, true);
        assert_eq!(d.admitted(0), 750);
        d.handle_complete(1, 2_000_000, true);
        assert_eq!(d.admitted(0), 750);
        let got = d.handle_enqueue(8, 0, 0, 2_000_000, 18);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admits, 8);
    }

    #[test]
    fn stale_cpu_and_depth_drop_stored_share() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(1, 0, 0, 1_000_000, 1);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admitted(0), 125);
        let got = d.handle_enqueue(1, 0, 9999, 2_000_000, 2);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.admitted(0), 0);
        assert_eq!(d.queue_len(), 0);
    }

    #[test]
    fn order_follows_least_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000, 11);
        d.handle_enqueue(2, 4000, 0, 1_000_000, 12);
        let top = d.peek_order().unwrap();
        assert_eq!(top.pid, 2);
        assert_eq!(d.queue_len(), 2);
    }

    #[test]
    fn miss_counts_on_blocking_complete_past_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 4000, 0, 1_000_000, 21);
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
        let got = d.handle_enqueue(10, 0, 0, 1_000_000, 5);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.task(10).unwrap().wire_seq, 5);
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
        assert_eq!(ORDER_DEPTH_MAX, 512);
        assert_eq!(DRAIN_CAP, 1024);
        assert_eq!(EV_CAP, 1024);
        assert_eq!(TASKS_CAP, 4096);
        assert_eq!(STALE_GRACE_NS, 128_000_000);
    }

    #[test]
    fn placement_and_kick_helpers_wire() {
        let d = Daemon::new();
        assert_eq!(d.pick_cpu(&[1], 0, &[0, 1], &[0, 1], &[0, 0], 100, 0), 1);
        assert!(d.should_kick(10, 20));
        assert_eq!(d.queue_for(0), crate::flow::slot::local_dsq(0));
        assert_eq!(d.queue_for(9999), crate::flow::slot::slot_overflow_dsq());
    }

    #[test]
    fn task_table_caps_fresh_identifiers() {
        let mut d = Daemon::new();
        for pid in 1..=TASKS_CAP as u32 {
            let _ = d.handle_enqueue(pid + 100000, 32000, 0, 1_000_000, (pid + 100000) as u64);
        }
        assert_eq!(d.task_len(), TASKS_CAP);
        let got = d.handle_enqueue(9999999, 32000, 0, 1_000_000, 9999999);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.task_len(), TASKS_CAP);
    }

    #[test]
    fn stale_rows_collect_past_grace() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(1, 4000, 0, 1_000_000, 31);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admitted(0), 500);
        let late = 1_000_000 + 4_000_000 + STALE_GRACE_NS + 1;
        let removed = d.gc_stale(late);
        assert_eq!(removed, vec![1]);
        assert_eq!(d.admitted(0), 0);
        assert_eq!(d.queue_len(), 0);
        assert_eq!(d.task_len(), 0);
    }

    #[test]
    fn ordered_entries_drive_dispatch_in_veb_order() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000, 101);
        d.handle_enqueue(2, 4000, 0, 1_000_000, 102);
        d.handle_enqueue(3, 16000, 0, 1_000_000, 103);
        let view: Vec<u32> = d.ordered_entries().iter().map(|r| r.0).collect();
        assert_eq!(view, vec![2, 3, 1]);
        let rows = d.ordered_entries();
        assert_eq!(rows[0].1, 102);
        assert_eq!(rows[1].1, 103);
        assert_eq!(rows[2].1, 101);
        for pid in 4..=10u32 {
            let _ = d.handle_enqueue(pid, 0, 0, 1_000_000, 100 + pid as u64);
        }
        let got = d.handle_enqueue(99, 0, 0, 1_000_000, 199);
        assert!(matches!(got, AdmitDecision::Park));
        let view: Vec<u32> = d.ordered_entries().iter().map(|r| r.0).collect();
        assert!(!view.contains(&99));
        assert_eq!(d.task(99).unwrap().share, 0);
    }

    #[test]
    fn gc_returns_removed_for_core_cleanup() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 4000, 0, 1_000_000, 41);
        d.handle_enqueue(2, 32000, 0, 1_000_000, 42);
        let late = 1_000_000 + 4_000_000 + STALE_GRACE_NS + 1;
        let mut removed = d.gc_stale(late);
        removed.sort();
        assert_eq!(removed, vec![1]);
        assert_eq!(
            d.ordered_entries()
                .iter()
                .map(|r| r.0)
                .collect::<Vec<u32>>(),
            vec![2]
        );
    }

    #[test]
    fn queue_drop_folds_into_parks() {
        let mut d = Daemon::new();
        assert_eq!(d.ev_drops, 0);
        d.note_ev_drop();
        assert_eq!(d.ev_drops, 1);
        assert_eq!(d.parks, 1);
    }

    #[test]
    fn zero_identifier_parks_with_no_row() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(0, 0, 0, 1_000_000, 1);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.task_len(), 0);
        assert_eq!(d.queue_len(), 0);
        assert_eq!(d.rejects, 1);
        assert_eq!(d.parks, 1);
        d.handle_complete(0, 2_000_000, false);
        assert_eq!(d.misses, 0);
        assert_eq!(d.task_len(), 0);
    }

    #[test]
    fn keyed_remove_keeps_fresh_key_on_reuse() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(7, 4000, 0, 1_000_000, 71);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.queue_len(), 1);
        d.handle_complete(7, 2_000_000, true);
        assert_eq!(d.queue_len(), 0);
        assert_eq!(d.task_len(), 0);
        d.handle_complete(7, 2_000_000, true);
        assert_eq!(d.queue_len(), 0);
        let got = d.handle_enqueue(7, 32000, 0, 3_000_000, 72);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.queue_len(), 1);
        assert_eq!(d.peek_order().unwrap().pid, 7);
    }

    #[test]
    fn empty_key_clears_tree_bits() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(11, 4000, 0, 1_000_000, 81);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.queue_len(), 1);
        d.handle_complete(11, 2_000_000, true);
        assert_eq!(d.queue_len(), 0);
        assert!(d.peek_order().is_none());
        let got = d.handle_enqueue(12, 4000, 0, 3_000_000, 82);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.peek_order().unwrap().pid, 12);
    }
}
