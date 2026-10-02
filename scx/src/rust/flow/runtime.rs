// SPDX-License-Identifier: GPL-2.0
//! Daemon mirror, admission oracle, protocol for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the daemon mirror, the admission oracle, the wire
//! protocol. The daemon keeps one quantized queue, one admitted
//! row per CPU, one hint table as a read only mirror for tests plus
//! observability, plus one head view per low key byte and one owner
//! view per task as oracle for the core hints. Order follows deadlines solely
//! through the quantized tree. The BPF core parks plus admits plus
//! orders synchronously with no roundtrip. Dispatch moves every parked
//! task in least key then deadline order with rejects at the top key
//! last with affinity plus liveness checks and parks stale entries. The head view keeps the earliest
//! deadline then smallest pid per low key byte so picks skip tail walks
//! in the core, while the owner view steers repeat parks toward the
//! previous CPU with mask still checked in the core. Mirror cost stays on the
//! userspace thread within five hundred twelve entries and stays off
//! the BPF hot path. Times stay in the monotonic domain shared with
//! the core. Parks include backpressure drops, ring drops, userspace
//! queue drops. Queue backlog is the channel length and drop rate is
//! the parks delta, so both stay visible with zero wire change. Hints
//! stay derived from task weight keyed by task identifier. Lost
//! completes collect past deadline plus grace for observability solely
//! with no core revoke.

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
/// First sequence handed to fresh tasks as oracle check.
/// Core allocates one sequence per enqueue with the mirror kept for
/// tests solely.
#[cfg(test)]
pub const SEQ_INIT: u64 = 1;
/// Max queued entries tracked before the core parks with no run.
pub const ORDER_DEPTH_MAX: usize = 512;
/// Max moves per dispatch pass. Mirrors the BPF header.
pub const DISPATCH_BATCH: usize = 16;
/// Max key probes per dispatch pass. Mirrors the BPF header.
/// Twenty stays as ABI while ordered fills sixteen per pass so full
/// batches never starve.
pub const DISPATCH_PROBES: usize = 20;
/// Deep backlog shape. Mirrors the BPF header as ABI. Backlog still
/// drains sixteen ordered per pass with the fallback solely on empty
/// plus corrupt plus stale.
pub const DISPATCH_FLOOD_PROBES: usize = 4;
/// Queue depth marking deep backlog. Mirrors the header as ABI.
/// Ordered still drains sixteen per pass past this depth.
pub const DISPATCH_FLOOD_QUEUED: usize = 128;
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
/// Userspace drains use the deeper drain cap while the core moves
/// sixteen per pass.
const _: () = assert!(DISPATCH_BATCH == 16);
/// Guard that the dispatch probes mirror the BPF header.
/// Twenty stays as ABI with sixteen moves filling the batch.
const _: () = assert!(DISPATCH_PROBES == 20);
/// Guard that the flood stall budget mirrors the BPF header.
/// Four plus one hundred twenty eight mark deep backlog shape as ABI
/// with ordered draining sixteen per pass.
const _: () = assert!(DISPATCH_FLOOD_PROBES == 4);
/// Guard that the flood queue bound mirrors the BPF header.
/// Backlog still drains ordered past this depth with the fallback
/// solely on empty plus corrupt plus stale.
const _: () = assert!(DISPATCH_FLOOD_QUEUED == 128);
/// Guard that the flood budget stays inside the probe budget.
/// Ordered fills sixteen per pass as ABI.
const _: () = assert!(DISPATCH_FLOOD_PROBES < DISPATCH_PROBES);
/// Guard that one batch never exceeds the probe budget.
const _: () = assert!(DISPATCH_BATCH <= DISPATCH_PROBES);

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
/// share. Release anchors the miss check. Sequence holds the single
/// enqueue sequence shared with core task state plus the order row
/// for dispatch checks. Order uses deadlines solely with stored
/// shares for admission. Mirror only with the core as authority.
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
    /// Single sequence from the enqueue notify as oracle.
    /// Mirror only with the core as authority.
    #[cfg(test)]
    pub wire_seq: u64,
}

/// Daemon holding the quantized mirror plus admission oracle.
/// Admitted rows hold one per mille sum per CPU. Tasks hold one
/// stored share each. Adds pair with drops exactly once per admit
/// in the mirror. Head holds one earliest pid per low key byte for
/// the core pick hint with overwrite on a new key, mirroring the
/// core slot view. Owner holds the last admit CPU per task for the
/// core placement hint with mask still checked in the core. Single
/// sequence tracks notifies plus queued tasks with no split. Disable
/// plus exit notifies drop shares through complete in the mirror.
/// Task rows stay capped at the task bound with hints cleared on
/// remove so both stay bounded. Stale rows collect past deadline plus
/// grace for observability solely. Queue drops fold into parks plus
/// the drop gauge with zero wire change. Core owns dispatch with the
/// mirror never gating it.
pub struct Daemon {
    pub(crate) order: FlowVeb,
    hints: HintTable,
    admitted: Vec<u64>,
    pub(crate) tasks: HashMap<u32, TaskState>,
    pub(crate) head_hint: HashMap<u32, (u32, u32, u64, u32)>,
    pub(crate) mask_hint: HashMap<u32, u32>,
    exhaust: HashMap<u32, u32>,
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
            head_hint: HashMap::new(),
            mask_hint: HashMap::new(),
            exhaust: HashMap::new(),
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

    /// Cached head pid for one key with deadline plus owner.
    /// Mirror of the core low byte slot view for tests solely. Empty
    /// when the key never parked, when a colliding key evicted the
    /// slot, or when the stored pid left. Admits plus top key rejects
    /// share the same view with the far deadline keeping rejects last.
    /// Stale pids miss through the task check with no core effect. The
    /// head keeps smallest pid best effort while the full scan orders
    /// owned then pid.
    #[cfg(test)]
    pub fn head_for(&self, key: u32) -> Option<(u32, u64, u32)> {
        let (stored_key, pid, deadline, cpu) = self.head_hint.get(&(key & 255)).copied()?;
        if stored_key != key {
            return None;
        }
        let t = self.tasks.get(&pid)?;
        if t.share == 0 && t.deadline != u64::MAX {
            return None;
        }
        if super::veb::quantize(t.deadline) as u32 != key {
            return None;
        }
        if t.deadline != deadline || t.admit_cpu != cpu {
            return None;
        }
        Some((pid, deadline, cpu))
    }

    /// Cached owner CPU for one task with empty for unknown tasks.
    /// Mirror of the core placement view for tests solely. The core
    /// revalidates mask plus live before use with no core effect here.
    #[cfg(test)]
    pub fn hint_for(&self, pid: u32) -> Option<u32> {
        if !self.tasks.contains_key(&pid) {
            return None;
        }
        self.mask_hint.get(&pid).copied()
    }

    /// Pick one CPU with the cached owner view in one place.
    /// The cached owner wins when still in the allowed list and inside
    /// the CPU bound, else the previous CPU wins when still allowed,
    /// else the first allowed wins. Idle stays BPF only with no mirror,
    /// since the idle pick needs the live mask with no replay. The core
    /// takes idle first when the tail is empty and warmth first when
    /// the tail holds work, so this mirror matches the saturated branch
    /// where warmth leads. The core revalidates mask plus live before
    /// use, so a stale view never widens the target class here. Mirror
    /// only with the core as authority.
    #[cfg(test)]
    pub fn place_for(&self, pid: u32, prev: u32, allowed: &[u32]) -> u32 {
        if allowed.is_empty() {
            return prev;
        }
        if let Some(hint) = self.mask_hint.get(&pid)
            && allowed.contains(hint)
            && (*hint as u64) < super::slot::MAX_CPUS
            && self.tasks.contains_key(&pid)
        {
            return *hint;
        }
        if allowed.contains(&prev) {
            return prev;
        }
        allowed[0]
    }

    /// True when the shared tail holds work for tests solely.
    /// Mirrors the core backlog check where an empty tail takes idle
    /// first and a held tail takes warmth first with no extra threshold.
    #[cfg(test)]
    pub fn is_saturated(&self) -> bool {
        self.order.len() != 0
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

    /// Parked entries in dispatch order as oracle rows.
    /// Each row carries pid, sequence, deadline, admit CPU.
    /// Admits sort before top key rejects with the far deadline last.
    /// The core moves every parked task in least key then deadline
    /// order up to the batch bound with affinity plus liveness checks
    /// and the fallback solely on empty plus corrupt plus stale.
    /// Mirror only with the core as authority.
    #[cfg(test)]
    pub fn ordered_entries(&self) -> Vec<(u32, u64, u64, u32)> {
        let mut out = Vec::with_capacity(self.order.len());
        for e in self.order.ordered() {
            if let Some(t) = self.tasks.get(&e.pid) {
                out.push((e.pid, t.wire_seq, t.deadline, t.admit_cpu));
            }
        }
        out
    }

    /// Stored row for one pid with empty for unknown identifiers.
    /// Oracle only with the core as authority.
    #[cfg(test)]
    pub fn task(&self, pid: u32) -> Option<&TaskState> {
        self.tasks.get(&pid)
    }

    /// Last observed sequence for gap observability solely.
    /// Mirror only with the core as authority.
    pub fn wire_last(&self) -> u64 {
        self.wire_last
    }

    /// Mirror counts for observability solely with no core effect.
    /// Lets production logs observe the oracle without gating dispatch.
    pub fn mirror_counts(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.admits,
            self.rejects,
            self.misses,
            self.parks,
            self.ev_drops,
        )
    }

    /// Share of one hint through the default period on miss.
    /// A two millisecond slice in a sixteen millisecond period takes
    /// one hundred twenty five per mille.
    #[cfg(test)]
    pub fn share_for(&self, hint_us: u32) -> u64 {
        let period = super::edf::task_period(hint_us);
        super::edf::slice_permille(period)
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

    /// Handle one enqueue notify as mirror oracle.
    /// Fresh hints flow through the hint table. Stored shares add
    /// once and drop once in the mirror. Rejects park keyed at the top
    /// key with the far deadline plus head plus owner views, so they
    /// drain ordered last with no run. Zero identifiers park at once
    /// with no table row since zero never keys the tree. Stale CPUs
    /// plus depth overflow clear the old row then park keyed at the top.
    /// Table full parks fresh identifiers with no row so the map stays
    /// capped. Admitted plus rejected parks store one head plus one
    /// owner view with no extra counter, so later oracle picks reuse
    /// warmth with mask still checked in the core. The head keeps
    /// smallest pid best effort while the full scan orders owned then
    /// pid. Single sequence pairs each row with core task state plus
    /// the order row with no split. Mirror only with the core as
    /// authority.
    pub fn handle_enqueue(
        &mut self,
        pid: u32,
        hint_us: u32,
        cpu: u32,
        now: u64,
        wire_seq: u64,
    ) -> AdmitDecision {
        if pid == 0 {
            return self.reject_park(pid, wire_seq, cpu, now);
        }
        if cpu as u64 >= super::slot::MAX_CPUS {
            let action = fail_open(&FailReason::BadCpu);
            debug_assert_eq!(action, FailAction::DropShare);
            self.remove_row(pid);
            return self.reject_park(pid, wire_seq, cpu, now);
        }
        if self.order.len() >= ORDER_DEPTH_MAX {
            self.remove_row(pid);
            return self.reject_park(pid, wire_seq, cpu, now);
        }
        if !self.tasks.contains_key(&pid) && self.tasks.len() >= TASKS_CAP {
            return self.reject_park(pid, wire_seq, cpu, now);
        }
        if self.tasks.contains_key(&pid) {
            self.unpublish(pid);
        }
        let hint = if hint_us != 0 {
            hint_us
        } else {
            self.hints.lookup(pid as u64) as u32
        };
        let period = super::edf::task_period(hint);
        let deadline = super::edf::deadline_at(now, period);
        let exhaust = self.exhaust.get(&pid).copied().unwrap_or(0);
        let share = super::edf::slice_permille_for(period, exhaust);
        let held = self.admitted(cpu);
        if share != 0 && !super::edf::admit_ok(held, share) {
            return self.reject_park(pid, wire_seq, cpu, now);
        }
        if share != 0 {
            let row = &mut self.admitted[cpu as usize];
            *row = row.saturating_add(share);
        }
        self.tasks.insert(
            pid,
            TaskState {
                release: now,
                deadline,
                share,
                admit_cpu: cpu,
                #[cfg(test)]
                wire_seq,
            },
        );
        self.order.insert(pid, deadline, wire_seq);
        self.admits += 1;
        self.store_views(pid, deadline, share, cpu);
        AdmitDecision::Admit { share, cpu }
    }

    /// Store one head plus one owner view for the oracle hints.
    /// Head keeps the earliest deadline then smallest pid per low key
    /// byte with overwrite on a new key, mirroring the core slot view.
    /// Owner holds the last admit CPU per task with overwrite. Out of
    /// bound CPUs store nothing, matching the core reject path. Keyed
    /// rejects at the far deadline store the same head plus owner with
    /// the far deadline keeping them last, so dispatch still picks them
    /// by key then deadline. Both stay best effort with validation
    /// before use and clear on remove, so stale views fall back with no
    /// wrong move. The head keeps smallest pid best effort while the
    /// full scan orders owned then pid.
    pub(crate) fn store_views(&mut self, pid: u32, deadline: u64, share: u64, cpu: u32) {
        if (cpu as u64) >= super::slot::MAX_CPUS {
            return;
        }
        self.mask_hint.insert(pid, cpu);
        if deadline == 0 {
            return;
        }
        if share == 0 && deadline != u64::MAX {
            return;
        }
        let key = super::veb::quantize(deadline) as u32;
        let slot = key & 255;
        match self.head_hint.get(&slot).copied() {
            None => {
                self.head_hint.insert(slot, (key, pid, deadline, cpu));
            }
            Some((old_key, old_pid, old_deadline, _)) => {
                if old_key != key
                    || deadline < old_deadline
                    || (deadline == old_deadline && pid < old_pid)
                {
                    self.head_hint.insert(slot, (key, pid, deadline, cpu));
                }
            }
        }
    }

    /// Handle one complete notify as mirror oracle.
    /// Drops the stored share exactly once in the mirror. Misses
    /// count when monotonic time passes release plus deadline on a
    /// blocking complete. A runnable end steps the repeat count toward
    /// eight milliseconds capped there, while a blocking end clears it,
    /// so steady work keeps the base slice with no extra threshold.
    /// Runtime charge stays in the core total. Zero identifiers pass
    /// through with no state change. Unknown identifiers pass through
    /// after order cleanup, so a lost enqueue never leaks a share.
    /// Mirror only.
    pub fn handle_complete(&mut self, pid: u32, now: u64, runnable: bool) {
        if pid == 0 {
            return;
        }
        let (release, deadline) = match self.tasks.get(&pid) {
            Some(t) => (t.release, t.deadline),
            None => {
                self.unpublish(pid);
                return;
            }
        };
        let miss = !runnable && super::edf::missed(release, deadline, now);
        self.remove_row(pid);
        if runnable {
            let cur = self.exhaust.get(&pid).copied().unwrap_or(0);
            if cur < super::slice::QUANTUM_MAX_STEP {
                self.exhaust.insert(pid, cur + 1);
            } else {
                self.exhaust.insert(pid, super::slice::QUANTUM_MAX_STEP);
            }
        } else {
            self.exhaust.remove(&pid);
        }
        if miss {
            self.misses += 1;
            self.parks += 1;
        }
    }

    /// Repeat count for one task with zero for fresh tasks.
    /// Mirror of the core exhaust view for tests solely.
    #[cfg(test)]
    pub fn exhaust_for(&self, pid: u32) -> u32 {
        self.exhaust.get(&pid).copied().unwrap_or(0)
    }

    /// Collect stale rows past deadline plus grace as mirror only.
    /// Drops stored shares then clears order plus task rows. Lost
    /// completes return shares here so admitted sums never leak in
    /// the mirror. Callers pass monotonic now and poll at a slow
    /// cadence. Returns removed pids for observability solely with no
    /// core revoke.
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
            self.remove_row(*pid);
            self.exhaust.remove(pid);
        }
        stale
    }

    /// Note one observed sequence for gap observability solely.
    /// In order notifies advance the mark. Duplicates, reorder,
    /// forward jumps report resync through the fail open matrix with
    /// loss irrelevant to dispatch. Zero stays ignored. The first
    /// notify after attach accepts any sequence as a mid attach edge
    /// with zero resync, so tasks queued before attach never count a
    /// false gap. Mirror only with no core effect.
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
        assert_eq!(d.queue_len(), 1);
        assert_eq!(d.task_len(), 1);
        let t = d.task(1).unwrap();
        assert_eq!(t.share, 0);
        assert_eq!(t.deadline, u64::MAX);
        assert_eq!(super::super::veb::quantize(t.deadline), 65535);
        let mut full = Daemon::new();
        for pid in 1..=(ORDER_DEPTH_MAX as u32) {
            let got = full.handle_enqueue(pid, 4_000_000, 0, 2_000_000, pid as u64 + 100);
            assert!(matches!(got, AdmitDecision::Admit { .. }));
        }
        assert_eq!(full.queue_len(), ORDER_DEPTH_MAX);
        assert_eq!(full.task_len(), ORDER_DEPTH_MAX);
        let got = full.handle_enqueue(1, 4_000_000, 0, 3_000_000, 900);
        assert!(matches!(got, AdmitDecision::Park));
        assert_eq!(full.queue_len(), ORDER_DEPTH_MAX);
        assert_eq!(full.task_len(), ORDER_DEPTH_MAX);
        let t = full.task(1).unwrap();
        assert_eq!(t.share, 0);
        assert_eq!(t.deadline, u64::MAX);
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
    fn wire_and_order_share_single_sequence() {
        let mut d = Daemon::new();
        assert_eq!(d.note_seq(1), FailAction::ParkFifo);
        assert_eq!(d.wire_last(), 1);
        let got = d.handle_enqueue(10, 0, 0, 1_000_000, 5);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.task(10).unwrap().wire_seq, 5);
        assert_eq!(d.wire_last(), 1);
        assert_eq!(d.peek_order().unwrap().seq, 5);
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
        assert_eq!(DISPATCH_PROBES, 20);
        assert_eq!(DISPATCH_FLOOD_PROBES, 4);
        assert_eq!(DISPATCH_FLOOD_QUEUED, 128);
        assert_eq!(ORDER_DEPTH_MAX, 512);
        assert_eq!(DRAIN_CAP, 1024);
        assert_eq!(EV_CAP, 1024);
        assert_eq!(TASKS_CAP, 4096);
        assert_eq!(STALE_GRACE_NS, 128_000_000);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn flood_and_drain_bounds_hold() {
        assert!(DISPATCH_FLOOD_PROBES < DISPATCH_PROBES);
        assert!(DISPATCH_BATCH <= DISPATCH_PROBES);
        assert_eq!(DISPATCH_BATCH, 16);
        assert_eq!(DISPATCH_FLOOD_PROBES, 4);
        assert_eq!(DISPATCH_FLOOD_QUEUED, 128);
        // Ordered fills sixteen per pass with the fallback solely on
        // empty plus corrupt plus stale, so deep backlog still drains
        // in order per pass.
        let slack = DISPATCH_BATCH - DISPATCH_FLOOD_PROBES;
        assert_eq!(slack, 12);
        assert_eq!(DISPATCH_FLOOD_PROBES + (DISPATCH_BATCH >> 2), 8);
        assert!(DISPATCH_FLOOD_QUEUED > DISPATCH_BATCH);
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
        let rows = d.ordered_entries();
        let view: Vec<u32> = rows.iter().map(|r| r.0).collect();
        assert!(view.contains(&99));
        assert_eq!(*view.last().unwrap(), 99);
        let last = rows.last().unwrap();
        assert_eq!(last.0, 99);
        assert_eq!(last.2, u64::MAX);
        assert_eq!(d.task(99).unwrap().share, 0);
        assert_eq!(super::super::veb::quantize(last.2), 65535);
        for r in &rows {
            if d.task(r.0).unwrap().share != 0 {
                continue;
            }
            assert_eq!(r.2, u64::MAX);
        }
        let first_reject = rows
            .iter()
            .position(|r| d.task(r.0).unwrap().share == 0)
            .unwrap();
        for r in &rows[..first_reject] {
            assert_ne!(d.task(r.0).unwrap().share, 0);
        }
    }

    #[test]
    fn top_key_rejects_sort_after_admits() {
        let mut d = Daemon::new();
        for pid in 1..=7u32 {
            let got = d.handle_enqueue(pid, 0, 0, 1_000_000, pid as u64);
            assert!(matches!(got, AdmitDecision::Admit { .. }));
        }
        let got = d.handle_enqueue(8, 0, 0, 1_000_000, 8);
        assert!(matches!(got, AdmitDecision::Park));
        let got = d.handle_enqueue(9, 0, 0, 1_000_000, 9);
        assert!(matches!(got, AdmitDecision::Park));
        let rows = d.ordered_entries();
        assert_eq!(rows.len(), 9);
        let view: Vec<u32> = rows.iter().map(|r| r.0).collect();
        assert_eq!(&view[..7], &[1, 2, 3, 4, 5, 6, 7]);
        assert!(view.ends_with(&[8, 9]));
        for pid in [8, 9] {
            let t = d.task(pid).unwrap();
            assert_eq!(t.share, 0);
            assert_eq!(t.deadline, u64::MAX);
            assert_eq!(t.admit_cpu, 0);
        }
        let head = d.head_for(65535).unwrap();
        assert_eq!(head.0, 8);
        assert_eq!(head.1, u64::MAX);
        assert_eq!(d.hint_for(8), Some(0));
        assert_eq!(d.hint_for(9), Some(0));
    }

    #[test]
    fn gc_returns_removed_for_observability_only() {
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

    #[test]
    fn gate_fail_complete_drops_share_promptly() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(9, 4000, 0, 1_000_000, 91);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert!(d.admitted(0) > 0);
        d.handle_complete(9, 2_000_000, true);
        assert_eq!(d.admitted(0), 0);
        assert_eq!(d.task_len(), 0);
        assert_eq!(d.queue_len(), 0);
        let removed = d.gc_stale(2_000_000);
        assert!(removed.is_empty());
    }

    #[test]
    fn parks_stay_noisy_but_fail_closed() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(5, 4000, 0, 1_000_000, 51);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        d.note_ev_drop();
        d.note_ev_drop();
        assert_eq!(d.ev_drops, 2);
        assert_eq!(d.queue_len(), 1);
        d.handle_complete(5, 2_000_000, true);
        assert_eq!(d.queue_len(), 0);
        assert_eq!(d.task_len(), 0);
    }

    #[test]
    fn head_keeps_earliest_per_key() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(1, 4000, 0, 1_000_000, 61);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        let t = d.task(1).unwrap();
        let key = super::super::veb::quantize(t.deadline) as u32;
        let (pid, deadline, cpu) = d.head_for(key).unwrap();
        assert_eq!(pid, 1);
        assert_eq!(deadline, t.deadline);
        assert_eq!(cpu, 0);
        // Later pid with same key and later deadline keeps the head.
        let got = d.handle_enqueue(2, 4000, 1, 1_000_500, 62);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        let t2 = d.task(2).unwrap();
        let key2 = super::super::veb::quantize(t2.deadline) as u32;
        if key2 == key {
            assert_eq!(d.head_for(key).unwrap().0, 1);
        }
        d.handle_complete(1, 2_000_000, true);
        assert!(d.head_for(key).is_none() || d.head_for(key).unwrap().0 != 1);
    }

    #[test]
    fn head_slot_overwrites_on_colliding_keys() {
        let mut d = Daemon::new();
        let now = 1_000_000u64;
        let got = d.handle_enqueue(1, 0, 0, now, 71);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        let key1 = super::super::veb::quantize(d.task(1).unwrap().deadline) as u32;
        assert_eq!(d.head_for(key1).unwrap().0, 1);
        // Two hundred fifty six keys later shares the low byte slot,
        // so the later admit evicts the earlier head like the core.
        let shift = 256u64 << super::super::veb::QUANT_SHIFT;
        let got = d.handle_enqueue(2, 0, 1, now + shift, 72);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        let key2 = super::super::veb::quantize(d.task(2).unwrap().deadline) as u32;
        assert_eq!(key2, key1 + 256);
        assert_eq!(key2 & 255, key1 & 255);
        assert!(d.head_for(key1).is_none());
        assert_eq!(d.head_for(key2).unwrap().0, 2);
        d.handle_complete(2, now + shift + 1_000_000, true);
        assert!(d.head_for(key2).is_none());
    }

    #[test]
    fn hint_drives_place_with_allowed_check() {
        let mut d = Daemon::new();
        let got = d.handle_enqueue(3, 4000, 2, 1_000_000, 63);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert_eq!(d.hint_for(3), Some(2));
        assert_eq!(d.place_for(3, 0, &[0, 1, 2]), 2);
        assert_eq!(d.place_for(3, 0, &[0, 1]), 0);
        assert_eq!(d.place_for(9, 1, &[0, 1]), 1);
        d.handle_complete(3, 2_000_000, true);
        assert_eq!(d.hint_for(3), None);
        assert_eq!(d.place_for(3, 1, &[0, 1]), 1);
    }

    #[test]
    fn repeat_exhaust_steps_slice_to_eight_ms() {
        let mut d = Daemon::new();
        assert_eq!(d.exhaust_for(1), 0);
        let got = d.handle_enqueue(1, 0, 0, 1_000_000, 71);
        assert!(matches!(got, AdmitDecision::Admit { share: 125, .. }));
        assert_eq!(d.task(1).unwrap().share, 125);
        d.handle_complete(1, 2_000_000, true);
        assert_eq!(d.exhaust_for(1), 1);
        let got = d.handle_enqueue(1, 0, 0, 3_000_000, 72);
        assert!(matches!(got, AdmitDecision::Admit { share: 250, .. }));
        assert_eq!(d.task(1).unwrap().share, 250);
        d.handle_complete(1, 4_000_000, true);
        assert_eq!(d.exhaust_for(1), 2);
        let got = d.handle_enqueue(1, 0, 0, 5_000_000, 73);
        assert!(matches!(got, AdmitDecision::Admit { share: 500, .. }));
        d.handle_complete(1, 6_000_000, true);
        assert_eq!(d.exhaust_for(1), 2);
        let got = d.handle_enqueue(1, 0, 0, 7_000_000, 74);
        assert!(matches!(got, AdmitDecision::Admit { share: 500, .. }));
        d.handle_complete(1, 8_000_000, false);
        assert_eq!(d.exhaust_for(1), 0);
    }

    #[test]
    fn remainder_stays_ordered_while_tree_holds_keys() {
        let mut d = Daemon::new();
        for pid in 1..=20u32 {
            let hint = if pid % 2 == 0 { 4000 } else { 32000 };
            let _ = d.handle_enqueue(pid, hint, 0, 1_000_000, pid as u64 + 200);
        }
        assert_eq!(d.queue_len(), 20);
        let rows = d.ordered_entries();
        assert_eq!(rows.len(), 20);
        let mut last_key = 0u16;
        let mut first_reject = rows.len();
        for (idx, r) in rows.iter().enumerate() {
            let key = super::super::veb::quantize(r.2);
            if idx > 0 {
                assert!(key >= last_key);
            }
            last_key = key;
            if d.task(r.0).unwrap().share == 0 && first_reject == rows.len() {
                first_reject = idx;
            }
        }
        for r in &rows[..first_reject] {
            assert_ne!(d.task(r.0).unwrap().share, 0);
        }
        let batch = rows.len().min(DISPATCH_BATCH);
        assert_eq!(batch, 16);
        let rest = &rows[batch..];
        assert!(!rest.is_empty());
        let mut rest_key = super::super::veb::quantize(rows[batch - 1].2);
        for r in rest {
            let key = super::super::veb::quantize(r.2);
            assert!(key >= rest_key);
            rest_key = key;
        }
    }

    #[test]
    fn fused_pick_move_matches_ordered_view() {
        let mut d = Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000, 201);
        d.handle_enqueue(2, 4000, 0, 1_000_000, 202);
        d.handle_enqueue(3, 16000, 0, 1_000_000, 203);
        let view: Vec<u32> = d.ordered_entries().iter().map(|r| r.0).collect();
        assert_eq!(view, vec![2, 3, 1]);
        let mut seq = Vec::new();
        while let Some(e) = d.order.pop_min() {
            seq.push(e.pid);
        }
        assert_eq!(seq, vec![2, 3, 1]);
    }

    #[test]
    fn saturated_tail_keeps_warmth_first() {
        let mut d = Daemon::new();
        assert!(!d.is_saturated());
        let got = d.handle_enqueue(3, 4000, 2, 1_000_000, 63);
        assert!(matches!(got, AdmitDecision::Admit { .. }));
        assert!(d.is_saturated());
        assert_eq!(d.place_for(3, 0, &[0, 1, 2]), 2);
        assert_eq!(d.place_for(3, 1, &[0, 1, 2]), 2);
        d.handle_complete(3, 2_000_000, true);
        assert!(!d.is_saturated());
    }
}
