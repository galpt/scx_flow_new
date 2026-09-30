// SPDX-License-Identifier: GPL-2.0
//! Daemon order plus admission plus protocol for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the served runtime plus the daemon order plus the admission
//! table plus the wire protocol. The daemon keeps one quantized queue
//! plus one admitted row per CPU plus one hint table. The BPF core
//! parks FIFO and notifies. The daemon orders and admits.

use std::collections::HashMap;

use super::cgrp::HintTable;
use super::veb::FlowVeb;

/// Wire kind for enqueue notify from the core.
pub const PROTO_ENQUEUE: u64 = 1;
/// Wire kind for order decision inside the daemon.
pub const PROTO_ORDER: u64 = 2;
/// Wire kind for dispatch execution at the core.
pub const PROTO_DISPATCH: u64 = 3;
/// Wire kind for complete notify from the core.
pub const PROTO_COMPLETE: u64 = 4;
/// First sequence handed to fresh tasks.
pub const SEQ_INIT: u64 = 1;
/// Max queued entries tracked before the core parks FIFO.
pub const ORDER_DEPTH_MAX: usize = 512;
/// Max moves per dispatch pass. Mirrors the BPF header.
pub const DISPATCH_BATCH: usize = 16;

/// Clamp one share into the admitted range.
/// Edge values fall to the near bound.
pub fn clamp_share(w: u32) -> u32 {
    w.clamp(super::slice::WEIGHT_MIN, super::slice::WEIGHT_MAX)
}

/// Advanced runtime after one execution segment.
/// Heavy weights advance slowly and light weights advance fast. Large
/// inputs saturate at the top.
pub fn runtime_advance(vruntime: u64, delta: u64, weight: u32) -> u64 {
    let w = clamp_share(weight) as u64;
    let base = super::slice::WEIGHT_BASE as u64;
    let q = delta / w;
    if q > u64::MAX / base {
        return u64::MAX;
    }
    let adv = (q * base).saturating_add(delta % w * base / w);
    vruntime.saturating_add(adv)
}

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
/// Every fault parks forward with progress preserved.
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
/// share. Release anchors the miss check.
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
    /// Served runtime scaled by weight.
    pub vruntime: u64,
    /// Weight used by the runtime advance.
    pub weight: u32,
}

/// Daemon holding the quantized queue plus admission rows.
/// Admitted rows hold one per mille sum per CPU. Tasks hold one stored
/// share each. Adds pair with drops exactly once per admit.
pub struct Daemon {
    order: FlowVeb,
    hints: HintTable,
    admitted: Vec<u64>,
    tasks: HashMap<u32, TaskState>,
    next_seq: u64,
    last_seq: u64,
    /// Tasks admitted under the use bound.
    pub admits: u64,
    /// Tasks parked on admission reject.
    pub rejects: u64,
    /// Wall completions past release plus deadline.
    pub misses: u64,
    /// Overflow parks from misses plus rejects.
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
            last_seq: 0,
            admits: 0,
            rejects: 0,
            misses: 0,
            parks: 0,
        }
    }

    /// Hint table for cgroup updates.
    pub fn hints_mut(&mut self) -> &mut HintTable {
        &mut self.hints
    }

    /// Admitted per mille sum for one CPU with zero past the bound.
    pub fn admitted(&self, cpu: u32) -> u64 {
        self.admitted.get(cpu as usize).copied().unwrap_or(0)
    }

    /// Queued entry count now held in the tree.
    pub fn queue_len(&self) -> usize {
        self.order.len()
    }

    /// Least queued entry with empty for vacant queues.
    pub fn peek_order(&self) -> Option<super::veb::FlowEntry> {
        self.order.peek_min().cloned()
    }

    /// Share of one hint through the default period on miss.
    /// A two millisecond slice in a sixteen millisecond period takes
    /// one hundred twenty five per mille.
    pub fn share_for(&self, hint_us: u32) -> u64 {
        let period = super::edf::task_period(hint_us);
        super::edf::slice_permillle(period)
    }

    /// Drop the stored share of one task with floor at zero.
    /// Clears the stored value so repeat drops stay empty.
    fn drop_stored(&mut self, pid: u32) {
        let (share, cpu) = match self.tasks.get(&pid) {
            Some(t) => (t.share, t.admit_cpu),
            None => return,
        };
        if share == 0 {
            return;
        }
        if let Some(row) = self.admitted.get_mut(cpu as usize) {
            *row = row.saturating_sub(share);
            if *row > super::edf::ADMIT_PERMILLE * 2 {
                *row = 0;
            }
        }
        if let Some(t) = self.tasks.get_mut(&pid) {
            t.share = 0;
            t.admit_cpu = 0;
        }
    }

    /// Handle one enqueue notify from the core.
    /// Fresh hints flow through the hint table. Stored shares add once
    /// and drop once. Rejects park FIFO at the core.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_enqueue(
        &mut self,
        pid: u32,
        hint_us: u32,
        cpu: u32,
        now: u64,
        weight: u32,
    ) -> AdmitDecision {
        if cpu as u64 >= super::slot::MAX_CPUS {
            self.rejects += 1;
            self.parks += 1;
            return AdmitDecision::Park;
        }
        if self.order.len() >= ORDER_DEPTH_MAX {
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
                    vruntime: 0,
                    weight: clamp_share(weight),
                },
            );
            self.next_seq = self.next_seq.saturating_add(1);
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
        self.last_seq = seq;
        self.tasks.insert(
            pid,
            TaskState {
                release: now,
                deadline,
                share,
                admit_cpu: cpu,
                vruntime: 0,
                weight: clamp_share(weight),
            },
        );
        self.order.insert(pid, deadline, seq);
        self.admits += 1;
        AdmitDecision::Admit { share, cpu }
    }

    /// Handle one complete notify from the core.
    /// Drops the stored share exactly once. Misses count when wall time
    /// passes release plus deadline on a blocking complete.
    pub fn handle_complete(&mut self, pid: u32, now: u64, runnable: bool, delta: u64) {
        let (release, deadline, weight, vruntime) = match self.tasks.get(&pid) {
            Some(t) => (t.release, t.deadline, t.weight, t.vruntime),
            None => {
                self.order.remove(pid);
                return;
            }
        };
        let adv = runtime_advance(vruntime, delta, weight);
        if let Some(t) = self.tasks.get_mut(&pid) {
            t.vruntime = adv;
        }
        self.drop_stored(pid);
        self.order.remove(pid);
        if !runnable && super::edf::missed(release, deadline, now) {
            self.misses += 1;
            self.parks += 1;
        }
        self.tasks.remove(&pid);
    }

    /// Note one observed wire sequence.
    /// Gaps resync through the fail open matrix.
    pub fn note_seq(&mut self, seq: u64) -> FailAction {
        if seq <= self.last_seq && seq != 0 {
            return fail_open(&FailReason::SeqGap);
        }
        self.last_seq = seq;
        FailAction::ParkFifo
    }

    /// Pick one CPU for one task through the shared placement model.
    /// Callers pass live depths in rank order.
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
    pub fn should_kick(&self, arrival: u64, occupant: u64) -> bool {
        super::preempt::arrival_kicks(arrival, occupant)
    }

    /// Queue identifier for one CPU with overflow past the bound.
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
    fn base_weight_advances_raw() {
        assert_eq!(runtime_advance(0, 2_000_000, 128), 2_000_000);
    }

    #[test]
    fn heavy_advances_slow_light_fast() {
        let heavy = runtime_advance(0, 2_000_000, 16_384);
        let light = runtime_advance(0, 2_000_000, 1);
        assert!(heavy < 2_000_000);
        assert!(light > 2_000_000);
    }

    #[test]
    fn huge_inputs_saturate() {
        assert_eq!(runtime_advance(u64::MAX, u64::MAX, 128), u64::MAX);
        assert_eq!(runtime_advance(0, u64::MAX, 1), u64::MAX);
    }

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
            let got = d.handle_enqueue(pid, 0, 0, 1_000_000, 128);
            assert!(matches!(got, AdmitDecision::Admit { .. }));
        }
        assert_eq!(d.admitted(0), 875);
        let got = d.handle_enqueue(8, 0, 0, 1_000_000, 128);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(d.rejects, 1);
        assert_eq!(d.parks, 1);
        d.handle_complete(1, 2_000_000, true, 2_000_000);
        assert_eq!(d.admitted(0), 750);
        d.handle_complete(1, 2_000_000, true, 2_000_000);
        assert_eq!(d.admitted(0), 750);
        let got = d.handle_enqueue(8, 0, 0, 2_000_000, 128);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.admits, 8);
    }

    #[test]
    fn order_follows_least_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000, 128);
        d.handle_enqueue(2, 4000, 0, 1_000_000, 128);
        let top = d.peek_order().unwrap();
        assert_eq!(top.pid, 2);
        assert_eq!(d.queue_len(), 2);
    }

    #[test]
    fn miss_counts_on_blocking_complete_past_deadline() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 4000, 0, 1_000_000, 128);
        d.handle_complete(1, 1_000_000 + 4_000_000 + 1, false, 2_000_000);
        assert_eq!(d.misses, 1);
        assert_eq!(d.parks, 1);
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
