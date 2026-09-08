/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Pure scheduling helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Lower bound of a per task estimate in nanos. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanos. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Seed of a per CPU mean in nanos. */
pub const TQ_SEED_NS: u64 = 8_000_000;
/* Floor of a per CPU mean in nanos. */
pub const TQ_MIN_NS: u64 = 500_000;
/* Ceiling of a per CPU mean in nanos. */
pub const TQ_MAX_NS: u64 = 32_000_000;
/* Bound of moved tasks in one pass. */
pub const DISPATCH_BATCH: u32 = 32;
/* Unknown LLC id. Marks an empty table entry. */
pub const LLC_UNKNOWN: u32 = 0xFFFF_FFFF;
/* Base id of the per CPU ordered queues. */
#[cfg(test)]
pub const DSQ_BASE: u64 = 0x4000;
/* Park id for tasks with no allowed CPU. */
#[cfg(test)]
pub const DSQ_PARK: u64 = 0x5000;
/* Bound of peers visited by one steal scan. */
#[cfg(test)]
pub const STEAL_BOUND: usize = 8;
/* Hint used for short estimates. */
#[cfg(test)]
pub const CPUPERF_SHORT: u32 = 1024;
/* Hint used for long estimates. */
#[cfg(test)]
pub const CPUPERF_LONG: u32 = 0;

/*
 * Clamp a per task estimate to the estimate range.
 * The floor keeps the value positive. The ceiling
 * keeps a single long run from shaping later choice.
 */
#[cfg(test)]
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Clamp a per CPU mean to the mean range. The floor
 * keeps short means usable. The ceiling keeps long
 * means bounded.
 */
#[cfg(test)]
pub fn clamp_tq(v: u64) -> u64 {
    v.clamp(TQ_MIN_NS, TQ_MAX_NS)
}

/*
 * Mean of one CPU from sum and count. An empty CPU
 * uses the seed. A populated CPU uses the quotient
 * clamped to the mean range.
 */
#[cfg(test)]
pub fn mean_tq(sum: u64, nr: u64) -> u64 {
    if nr == 0 {
        return TQ_SEED_NS;
    }
    clamp_tq(sum / nr)
}

/*
 * Queue id of one CPU. Returns none for an out of
 * range id, so callers fall back to the park queue.
 */
#[cfg(test)]
pub fn dsq_for_cpu(cpu: u32, max: usize) -> Option<u64> {
    if (cpu as usize) >= max {
        return None;
    }
    if (cpu as u64) >= 1024 {
        return None;
    }
    Some(DSQ_BASE + cpu as u64)
}

/*
 * Hint for one estimate against the mean. Short
 * estimates ask for the high hint. Long estimates
 * restore the low hint. The choice uses only the
 * estimate and the mean.
 */
#[cfg(test)]
pub fn cpuperf_for_est(est: u64, tq: u64) -> u32 {
    if est <= tq {
        CPUPERF_SHORT
    } else {
        CPUPERF_LONG
    }
}

/*
 * True when a stop should restore the low hint. Runnable
 * stops keep their work, so they never restore. Queued
 * work also keeps the hint, so restore runs once per
 * idle change.
 */
#[cfg(test)]
pub fn should_restore_hint(runnable: bool, dsq: u64, local: u64) -> bool {
    if runnable {
        return false;
    }
    if dsq != 0 {
        return false;
    }
    if local != 0 {
        return false;
    }
    true
}

/*
 * Next peer for a steal scan. Returns none with one
 * or no CPUs, so scans end at once with a single CPU
 * and no peers. Returns none for an out of range CPU.
 */
#[cfg(test)]
pub fn next_peer(cpu: u32, nr_cpus: usize) -> Option<u32> {
    if nr_cpus <= 1 {
        return None;
    }
    if (cpu as usize) >= nr_cpus {
        return None;
    }
    Some((cpu + 1) % nr_cpus as u32)
}

/*
 * Bound of a peer scan. Zero with one or no CPUs, so
 * steal scans and rotation end at once with a single
 * CPU. Otherwise capped by the steal bound and by one
 * less than the CPU count.
 */
#[cfg(test)]
pub fn scan_bound(nr_cpus: usize) -> usize {
    if nr_cpus <= 1 {
        return 0;
    }
    (nr_cpus - 1).min(STEAL_BOUND)
}

/*
 * Next steal cursor. The cursor rotates, so repeated
 * scans spread across peers.
 */
#[cfg(test)]
pub fn steal_next(cursor: u32, nr_cpus: usize) -> u32 {
    if nr_cpus == 0 {
        return 0;
    }
    (cursor + 1) % nr_cpus as u32
}

/*
 * Check that an LLC id names a real domain. The
 * unknown value marks an empty entry and fails
 * open with no LLC step.
 */
#[cfg(test)]
pub fn llc_known(id: u32) -> bool {
    id != LLC_UNKNOWN
}

/*
 * Check that the LLC step may run. Needs more than
 * one domain, so single and unknown hosts stay
 * plain with no extra scan.
 */
#[cfg(test)]
pub fn llc_ok(nr: u64) -> bool {
    nr >= 2
}

/*
 * LLC id of one CPU. Unknown ids fail open, so an
 * out of range CPU yields no domain.
 */
#[cfg(test)]
pub fn llc_of(cpu: usize, llc_ids: &[u32]) -> Option<u32> {
    let id = *llc_ids.get(cpu)?;
    if !llc_known(id) {
        return None;
    }
    Some(id)
}

/*
 * Idle CPU in the same LLC as the previous CPU.
 * Skips the second thread of a busy core when the
 * full set marks fully idle cores. Empty full set
 * means no SMT preference. Returns none when no
 * LLC idle CPU is found. Single and unknown hosts
 * return none at once with no scan.
 */
#[cfg(test)]
pub fn pick_llc_idle(
    prev: i32,
    llc_ids: &[u32],
    allowed: &[bool],
    idle: &[bool],
    full: &[bool],
    nr: u64,
) -> Option<u32> {
    if !llc_ok(nr) {
        return None;
    }
    if prev < 0 {
        return None;
    }
    let want = llc_of(prev as usize, llc_ids)?;
    let use_full = !full.is_empty();
    for (cpu, &id) in llc_ids.iter().enumerate() {
        if id != want {
            continue;
        }
        if !may_run_on(cpu as i32, allowed) {
            continue;
        }
        if use_full {
            match full.get(cpu) {
                Some(true) => {}
                _ => continue,
            }
        }
        match idle.get(cpu) {
            Some(true) => return Some(cpu as u32),
            _ => continue,
        }
    }
    None
}

/*
 * First idle CPU in the mask. Models the any idle
 * step. Returns none when no allowed CPU is idle.
 */
#[cfg(test)]
pub fn pick_any_idle(allowed: &[bool], idle: &[bool]) -> Option<u32> {
    for (cpu, &ok) in allowed.iter().enumerate() {
        if !ok {
            continue;
        }
        if let Some(true) = idle.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * Full select model. Mirrors the BPF order of LLC
 * idle, any idle, previous, current and first.
 * Returns none for park use when no CPU allows.
 */
#[cfg(test)]
pub fn select_cpu_model(
    prev: i32,
    cur: i32,
    allowed: &[bool],
    idle: &[bool],
    llc_ids: &[u32],
    full: &[bool],
    nr: u64,
) -> Option<u32> {
    if let Some(c) = pick_llc_idle(prev, llc_ids, allowed, idle, full, nr) {
        return Some(c);
    }
    if let Some(c) = pick_any_idle(allowed, idle) {
        return Some(c);
    }
    if may_run_on(prev, allowed) {
        return Some(prev as u32);
    }
    if may_run_on(cur, allowed) {
        return Some(cur as u32);
    }
    for (cpu, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(cpu as u32);
        }
    }
    None
}

/*
 * Check that a CPU may run a task with the given
 * mask. Mirrors the BPF head and kick guards. A
 * negative CPU fails closed. An out of range CPU
 * fails closed. A missing entry fails closed.
 */
#[cfg(test)]
pub fn may_run_on(cpu: i32, allowed: &[bool]) -> bool {
    if cpu < 0 {
        return false;
    }
    if let Some(&ok) = allowed.get(cpu as usize) {
        return ok;
    }
    false
}

/*
 * Target CPU from the selected CPU. A valid allowed
 * selected CPU wins. Otherwise the first allowed CPU
 * wins. No allowed CPU yields no target for park use.
 * Pinned tasks resolve to the single allowed CPU here.
 */
#[cfg(test)]
pub fn pick_target_cpu(selected: i32, allowed: &[bool]) -> Option<u32> {
    if selected >= 0 {
        if let Some(&ok) = allowed.get(selected as usize) {
            if ok {
                return Some(selected as u32);
            }
        }
    }
    for (i, &ok) in allowed.iter().enumerate() {
        if ok {
            return Some(i as u32);
        }
    }
    None
}

/*
 * Target CPU for a task that cannot move. Mirrors
 * the BPF local path with a mask check. An out of
 * range CPU yields no target for park use. A CPU
 * outside the mask yields no target for park use.
 */
#[cfg(test)]
pub fn stay_target(here: i32, nr_cpus: usize, allowed: &[bool]) -> Option<u32> {
    if here < 0 {
        return None;
    }
    if (here as usize) >= nr_cpus {
        return None;
    }
    if !may_run_on(here, allowed) {
        return None;
    }
    Some(here as u32)
}

/*
 * True when a frequency value is known. Zero means
 * unknown, so callers use a plain fallback and never
 * divide by the value.
 */
#[cfg(test)]
pub fn freq_known(freq_khz: u64) -> bool {
    freq_khz != 0
}

/*
 * True when any entry claims a sibling thread. False
 * means plain hardware with one thread per core, so
 * callers keep plain per CPU behavior.
 */
#[cfg(test)]
pub fn topology_has_smt(smt: &[bool]) -> bool {
    smt.iter().any(|v| *v)
}

/*
 * True when a sibling may be used. Needs sibling
 * hardware and an allowed peer, else plain per CPU
 * choice stays.
 */
#[cfg(test)]
pub fn sibling_ok(has_smt: bool, sibling: i32, allowed: &[bool]) -> bool {
    if !has_smt {
        return false;
    }
    if sibling < 0 {
        return false;
    }
    if let Some(&ok) = allowed.get(sibling as usize) {
        return ok;
    }
    false
}

/*
 * Per CPU mean for tests. Holds the sum and the count
 * of unfinished work including the running task. The
 * mean is the quotient clamped to the mean range with
 * the seed for an empty CPU.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMean {
    /* Sum of clamped estimates of unfinished tasks. */
    pub sum: u64,
    /* Count of unfinished tasks with the running one. */
    pub nr: u64,
}

/*
 * Ordered entry for tests. The estimate orders the
 * queue. The sequence keeps arrival order when
 * estimates match.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedEntry {
    /* Clamped last burst used as the sort key. */
    pub est: u64,
    /* Arrival sequence used for ties. Lower is older. */
    pub seq: u64,
    /* Task id used only to name the entry. */
    pub id: u64,
}

#[cfg(test)]
impl CpuMean {
    /*
     * Empty mean with no work. The mean reads as the
     * seed while empty.
     */
    pub fn empty() -> Self {
        Self { sum: 0, nr: 0 }
    }

    /*
     * Current mean. An empty CPU reads as the seed.
     * A populated CPU reads as the clamped quotient.
     */
    pub fn tq(&self) -> u64 {
        mean_tq(self.sum, self.nr)
    }

    /*
     * Join one task with a fresh estimate. A fresh
     * estimate reads as the current mean, so the join
     * leaves the mean unchanged.
     */
    pub fn join_fresh(&mut self) -> u64 {
        let est = self.tq();
        self.sum = self.sum.saturating_add(est);
        self.nr = self.nr.saturating_add(1);
        est
    }

    /*
     * Join one task with a known estimate. The estimate
     * is clamped first, so out of range values never
     * reach the sum.
     */
    pub fn join(&mut self, est: u64) -> u64 {
        let e = clamp_est(est);
        self.sum = self.sum.saturating_add(e);
        self.nr = self.nr.saturating_add(1);
        e
    }

    /*
     * Leave one task with its estimate. The sum never
     * wraps below zero. The count never wraps below
     * zero.
     */
    pub fn leave(&mut self, est: u64) {
        let e = clamp_est(est);
        self.sum = self.sum.saturating_sub(e);
        self.nr = self.nr.saturating_sub(1);
    }

    /*
     * Replace one estimate with a new value. Used when
     * a runnable task refreshes its last burst. The
     * count stays fixed while the sum tracks the change.
     */
    pub fn replace(&mut self, old: u64, new: u64) {
        let o = clamp_est(old);
        let n = clamp_est(new);
        self.sum = self.sum.saturating_sub(o);
        self.sum = self.sum.saturating_add(n);
    }
}

#[cfg(test)]
impl OrderedEntry {
    /*
     * True when this entry sorts before the other. The
     * smaller estimate wins. Equal estimates keep
     * arrival order with the older sequence first.
     */
    pub fn before(&self, other: &Self) -> bool {
        if self.est != other.est {
            return self.est < other.est;
        }
        self.seq < other.seq
    }
}

/*
 * Insert one entry into an ordered queue. The queue
 * stays sorted by estimate with arrival order for
 * ties. Returns the position of the new entry.
 */
#[cfg(test)]
pub fn ordered_insert(queue: &mut Vec<OrderedEntry>, entry: OrderedEntry) -> usize {
    let mut pos = queue.len();
    for (i, cur) in queue.iter().enumerate() {
        if entry.before(cur) {
            pos = i;
            break;
        }
    }
    queue.insert(pos, entry);
    pos
}

/*
 * Pending task for dispatch models. The mask names
 * allowed CPUs. The exiting flag marks tasks in
 * exit. The live flag marks tasks with a trusted
 * reference. A cleared live flag models a NULL
 * lookup from the pid table. The fail flag models a
 * failed move that must be skipped with progress.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTask {
    /* Allowed CPUs. Index is the CPU. */
    pub allowed: Vec<bool>,
    /* True when the task is exiting. */
    pub exiting: bool,
    /* False models a NULL pid lookup. */
    pub live: bool,
    /* True models a failed queue move. */
    pub fail: bool,
}

/*
 * Drain up to budget tasks for one CPU. The scan
 * visits every queued task in order and moves each
 * live and non exiting task with the CPU in the mask
 * and with no move failure. Bad heads are skipped, so
 * one head never blocks later work. Returns the count
 * moved. A zero return means no movable work was
 * present.
 */
#[cfg(test)]
pub fn drain_model(
    queue: &mut std::collections::VecDeque<PendingTask>,
    cpu: i32,
    budget: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved < budget
            && task.live
            && !task.exiting
            && !task.fail
            && may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
        } else {
            kept.push_back(task);
        }
    }
    *queue = kept;
    moved
}

/*
 * True when one peer head may move to the thief.
 * Mirrors the BPF peer drain head check. Only the
 * head may move. A dead, exiting, or foreign head
 * stays for its owner. A failed move stays with
 * progress. An empty queue yields false.
 */
#[cfg(test)]
pub fn peer_head_ok(thief: i32, head: Option<&PendingTask>) -> bool {
    if let Some(t) = head {
        t.live && !t.exiting && !t.fail && may_run_on(thief, &t.allowed)
    } else {
        false
    }
}

/*
 * Steal up to budget tasks from peers for an idle CPU.
 * The scan visits at most bound peers starting after
 * the cursor with wrap. Only idle callers steal. Each
 * peer offers its head only. A head that is dead,
 * exiting, foreign, or failing moves the scan to the
 * next peer with the head left in place for its owner.
 * The cursor advances by the peers visited. Returns the
 * count moved and the new cursor.
 */
#[cfg(test)]
pub fn steal_model(
    peers: &mut [std::collections::VecDeque<PendingTask>],
    thief: usize,
    cursor: u32,
    budget: u32,
    idle: bool,
) -> (u32, u32) {
    if !idle {
        return (0, cursor);
    }
    if peers.len() <= 1 {
        return (0, cursor);
    }
    if budget == 0 {
        return (0, cursor);
    }
    let mut moved = 0;
    let mut cur = cursor;
    let mut visited = 0;
    let bound = scan_bound(peers.len());
    while visited < bound && moved < budget {
        let next = match next_peer(cur, peers.len()) {
            Some(v) => v,
            None => break,
        };
        cur = next;
        visited += 1;
        if next as usize == thief {
            continue;
        }
        if let Some(q) = peers.get_mut(next as usize) {
            if peer_head_ok(thief as i32, q.front()) {
                q.pop_front();
                moved += 1;
            }
            if moved >= budget {
                break;
            }
        }
    }
    (moved, cur)
}

/*
 * Running view of one CPU for tests. Mirrors the BPF
 * CPU state fields used by the dashboard. Zero pid
 * means idle.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningView {
    /* Estimate of the task now on the CPU. */
    pub est: u64,
    /* Pid now on the CPU. Zero when idle. */
    pub pid: u32,
}

/*
 * Per CPU depth for tests. Each slot counts queued
 * tasks on one CPU across all queues. The sum matches
 * the queued total.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuDepths {
    /* Queued tasks per CPU. Index is the CPU. */
    pub nr: Vec<u64>,
}

#[cfg(test)]
impl RunningView {
    /*
     * Idle view with all fields at zero. Matches the
     * cleared BPF state after stopping.
     */
    pub fn idle() -> Self {
        Self { est: 0, pid: 0 }
    }

    /*
     * True when no task runs on the CPU. The dashboard
     * uses the pid for this check.
     */
    pub fn is_idle(&self) -> bool {
        self.pid == 0
    }

    /*
     * Clear the view to idle. Mirrors the stopping path
     * that clears the BPF running fields at once.
     */
    pub fn clear(&mut self) {
        self.est = 0;
        self.pid = 0;
    }
}

#[cfg(test)]
impl CpuDepths {
    /*
     * Empty depths with all CPUs at zero. Matches the
     * BPF state after init.
     */
    pub fn new(nr_cpus: usize) -> Self {
        Self {
            nr: vec![0; nr_cpus],
        }
    }

    /*
     * Join one task to a CPU. Counts saturate at the
     * top, so a burst of joins never wraps the gauge.
     */
    pub fn join(&mut self, cpu: usize) {
        if let Some(v) = self.nr.get_mut(cpu) {
            *v = v.saturating_add(1);
        }
    }

    /*
     * Leave one task from a CPU. Counts never go below
     * zero, so a double leave stays safe.
     */
    pub fn leave(&mut self, cpu: usize) {
        if let Some(v) = self.nr.get_mut(cpu) {
            *v = v.saturating_sub(1);
        }
    }

    /*
     * Sum of all CPUs. Matches the queued total.
     */
    pub fn sum(&self) -> u64 {
        self.nr.iter().fold(0, |a, &v| a.saturating_add(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn est_clamp_caps_at_one_second() {
        assert_eq!(clamp_est(0), EST_MIN_NS);
        assert_eq!(clamp_est(1), EST_MIN_NS);
        assert_eq!(clamp_est(EST_MAX_NS), EST_MAX_NS);
        assert_eq!(clamp_est(EST_MAX_NS + 1), EST_MAX_NS);
        assert_eq!(clamp_est(u64::MAX), EST_MAX_NS);
    }

    #[test]
    fn est_is_last_burst_with_no_smoothing() {
        let first = clamp_est(1_000_000);
        let second = clamp_est(8_000_000);
        assert_eq!(second, 8_000_000);
        assert_ne!(first, second);
    }

    #[test]
    fn tq_seed_floor_ceiling_match_spec() {
        assert_eq!(TQ_SEED_NS, 8_000_000);
        assert_eq!(TQ_MIN_NS, 500_000);
        assert_eq!(TQ_MAX_NS, 32_000_000);
        assert_eq!(mean_tq(0, 0), TQ_SEED_NS);
        assert_eq!(clamp_tq(0), TQ_MIN_NS);
        assert_eq!(clamp_tq(100), TQ_MIN_NS);
        assert_eq!(clamp_tq(500_000), 500_000);
        assert_eq!(clamp_tq(8_000_000), 8_000_000);
        assert_eq!(clamp_tq(32_000_000), 32_000_000);
        assert_eq!(clamp_tq(40_000_000), 32_000_000);
        assert_eq!(clamp_tq(u64::MAX), 32_000_000);
    }

    #[test]
    fn mean_uses_sum_over_nr() {
        assert_eq!(mean_tq(8_000_000, 1), 8_000_000);
        assert_eq!(mean_tq(16_000_000, 2), 8_000_000);
        assert_eq!(mean_tq(1_000_000, 2), 500_000);
        assert_eq!(mean_tq(100, 2), 500_000);
        assert_eq!(mean_tq(100_000_000, 2), 32_000_000);
        assert_eq!(mean_tq(0, 1), 500_000);
    }

    #[test]
    fn mean_property_stays_in_range() {
        for sum in [0, 1, 500_000, 8_000_000, 64_000_000] {
            for nr in [0, 1, 2, 8] {
                let tq = mean_tq(sum, nr);
                if nr == 0 {
                    assert_eq!(tq, TQ_SEED_NS);
                } else {
                    assert!(tq >= TQ_MIN_NS);
                    assert!(tq <= TQ_MAX_NS);
                }
            }
        }
    }

    #[test]
    fn fresh_join_leaves_mean_unchanged() {
        let mut m = CpuMean::empty();
        assert_eq!(m.tq(), TQ_SEED_NS);
        let e0 = m.join_fresh();
        assert_eq!(e0, TQ_SEED_NS);
        assert_eq!(m.tq(), TQ_SEED_NS);
        let e1 = m.join_fresh();
        assert_eq!(e1, TQ_SEED_NS);
        assert_eq!(m.tq(), TQ_SEED_NS);
        m.leave(e0);
        assert_eq!(m.tq(), TQ_SEED_NS);
        m.leave(e1);
        assert_eq!(m.tq(), TQ_SEED_NS);
        assert_eq!(m.nr, 0);
    }

    #[test]
    fn mean_tracks_join_leave_replace() {
        let mut m = CpuMean::empty();
        let a = m.join(2_000_000);
        assert_eq!(a, 2_000_000);
        assert_eq!(m.tq(), 2_000_000);
        m.join(4_000_000);
        assert_eq!(m.tq(), 3_000_000);
        m.replace(2_000_000, 8_000_000);
        assert_eq!(m.tq(), 6_000_000);
        m.leave(8_000_000);
        assert_eq!(m.tq(), 4_000_000);
        m.leave(4_000_000);
        assert_eq!(m.tq(), TQ_SEED_NS);
    }

    #[test]
    fn mean_saturates_at_bounds() {
        let mut m = CpuMean::empty();
        m.sum = u64::MAX;
        m.nr = 1;
        assert_eq!(m.tq(), TQ_MAX_NS);
        m.sum = 0;
        m.nr = 1;
        assert_eq!(m.tq(), TQ_MIN_NS);
        let mut n = CpuMean::empty();
        n.sum = u64::MAX - 1;
        n.nr = 0;
        n.join(1_000_000);
        assert_eq!(n.sum, u64::MAX);
        assert_eq!(n.nr, 1);
        n.leave(1_000_000);
        assert_eq!(n.sum, u64::MAX - 1_000_000);
        assert_eq!(n.nr, 0);
        let mut q = CpuMean::empty();
        q.sum = 100;
        q.nr = 1;
        q.leave(1_000_000);
        assert_eq!(q.sum, 0);
        assert_eq!(q.nr, 0);
    }

    #[test]
    fn dsq_ids_match_spec() {
        assert_eq!(DSQ_BASE, 0x4000);
        assert_eq!(DSQ_PARK, 0x5000);
        assert_ne!(DSQ_BASE, DSQ_PARK);
        assert_eq!(dsq_for_cpu(0, 8), Some(0x4000));
        assert_eq!(dsq_for_cpu(7, 8), Some(0x4007));
        assert_eq!(dsq_for_cpu(8, 8), None);
        assert_eq!(dsq_for_cpu(1023, 1024), Some(0x43ff));
        assert_eq!(dsq_for_cpu(1024, 2048), None);
    }

    #[test]
    fn ordered_insert_sorts_by_est() {
        let mut q = Vec::new();
        ordered_insert(
            &mut q,
            OrderedEntry {
                est: 8_000_000,
                seq: 0,
                id: 1,
            },
        );
        ordered_insert(
            &mut q,
            OrderedEntry {
                est: 1_000_000,
                seq: 1,
                id: 2,
            },
        );
        ordered_insert(
            &mut q,
            OrderedEntry {
                est: 4_000_000,
                seq: 2,
                id: 3,
            },
        );
        assert_eq!(q[0].id, 2);
        assert_eq!(q[1].id, 3);
        assert_eq!(q[2].id, 1);
    }

    #[test]
    fn ordered_insert_keeps_arrival_order_on_ties() {
        let mut q = Vec::new();
        for i in 0..4 {
            ordered_insert(
                &mut q,
                OrderedEntry {
                    est: 2_000_000,
                    seq: i,
                    id: i,
                },
            );
        }
        assert_eq!(q[0].id, 0);
        assert_eq!(q[1].id, 1);
        assert_eq!(q[2].id, 2);
        assert_eq!(q[3].id, 3);
    }

    #[test]
    fn ordered_property_holds_across_trials() {
        for trial in 0..16u64 {
            let mut q = Vec::new();
            for i in 0..8u64 {
                let est = (trial * 7 + i * 13) % 5 + 1;
                ordered_insert(&mut q, OrderedEntry { est, seq: i, id: i });
            }
            for w in q.windows(2) {
                assert!(!w[1].before(&w[0]));
            }
        }
    }

    #[test]
    fn cpuperf_uses_est_against_tq_only() {
        assert_eq!(cpuperf_for_est(500_000, 8_000_000), CPUPERF_SHORT);
        assert_eq!(cpuperf_for_est(8_000_000, 8_000_000), CPUPERF_SHORT);
        assert_eq!(cpuperf_for_est(8_000_001, 8_000_000), CPUPERF_LONG);
        assert_eq!(cpuperf_for_est(32_000_000, 500_000), CPUPERF_LONG);
        assert_eq!(cpuperf_for_est(1, 500_000), CPUPERF_SHORT);
    }

    #[test]
    fn idle_restore_needs_blocked_and_empty() {
        assert!(should_restore_hint(false, 0, 0));
        assert!(!should_restore_hint(true, 0, 0));
        assert!(!should_restore_hint(false, 1, 0));
        assert!(!should_restore_hint(false, 0, 1));
        assert!(!should_restore_hint(true, 1, 1));
    }

    #[test]
    fn target_prefers_selected_when_allowed() {
        assert_eq!(pick_target_cpu(2, &[true, true, true]), Some(2));
        assert_eq!(pick_target_cpu(0, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(1, &[false, true]), Some(1));
    }

    #[test]
    fn target_falls_back_to_first_when_invalid() {
        assert_eq!(pick_target_cpu(-1, &[false, true, true]), Some(1));
        assert_eq!(pick_target_cpu(5, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(1, &[true, false]), Some(0));
        assert_eq!(pick_target_cpu(-1, &[]), None);
    }

    #[test]
    fn target_none_when_no_allowed() {
        assert_eq!(pick_target_cpu(0, &[false, false]), None);
        assert_eq!(pick_target_cpu(-1, &[false]), None);
    }

    #[test]
    fn target_pinned_resolves_to_single() {
        assert_eq!(pick_target_cpu(2, &[false, false, true]), Some(2));
        assert_eq!(pick_target_cpu(0, &[false, false, true]), Some(2));
        assert_eq!(pick_target_cpu(-1, &[false, true, false]), Some(1));
    }

    #[test]
    fn head_guard_blocks_foreign() {
        let pinned = [false, false, true];
        assert!(!may_run_on(0, &pinned));
        assert!(may_run_on(2, &pinned));
        let narrow = [false, true, true];
        assert!(!may_run_on(0, &narrow));
        assert!(may_run_on(1, &narrow));
        assert!(may_run_on(2, &narrow));
    }

    #[test]
    fn kick_guard_blocks_foreign() {
        let pinned = [false, true, false];
        assert!(may_run_on(1, &pinned));
        assert!(!may_run_on(0, &pinned));
        assert!(!may_run_on(2, &pinned));
        assert!(!may_run_on(-1, &pinned));
    }

    #[test]
    fn stay_local_keeps_task_cpu() {
        let all = [true; 8];
        assert_eq!(stay_target(2, 8, &all), Some(2));
        assert_eq!(stay_target(0, 8, &all), Some(0));
        assert_eq!(stay_target(-1, 8, &all), None);
        assert_eq!(stay_target(99, 8, &all), None);
        assert_eq!(stay_target(7, 8, &all), Some(7));
        assert_eq!(stay_target(8, 8, &all), None);
    }

    #[test]
    fn stay_disallowed_here_parks() {
        /* In range but outside the mask parks. */
        let narrow = [false, false, true];
        assert_eq!(stay_target(0, 3, &narrow), None);
        assert_eq!(stay_target(1, 3, &narrow), None);
        assert_eq!(stay_target(2, 3, &narrow), Some(2));
        /* Live range with an empty mask parks. */
        let empty = [false, false, false];
        assert_eq!(stay_target(0, 3, &empty), None);
        /* A missing entry fails closed. */
        assert_eq!(stay_target(0, 3, &[]), None);
        /* Out of range parks even when allowed. */
        assert_eq!(stay_target(3, 3, &[true, true, true]), None);
    }

    #[test]
    fn empty_mask_parks() {
        let empty = [false, false, false];
        assert_eq!(pick_target_cpu(0, &empty), None);
        assert_eq!(pick_target_cpu(2, &empty), None);
        assert_eq!(pick_target_cpu(-1, &empty), None);
        assert!(!may_run_on(0, &empty));
        assert!(!may_run_on(2, &empty));
        assert_eq!(pick_target_cpu(-1, &[]), None);
        assert!(!may_run_on(0, &[]));
    }

    #[test]
    fn zero_freq_is_unknown_with_fallback() {
        assert!(!freq_known(0));
        assert!(freq_known(1));
        assert!(freq_known(3_800_000));
        assert!(freq_known(u64::MAX));
    }

    #[test]
    fn no_sibling_keeps_plain_per_cpu() {
        assert!(!topology_has_smt(&[false, false, false]));
        assert!(!topology_has_smt(&[]));
        assert!(!topology_has_smt(&[false]));
        assert!(topology_has_smt(&[false, true, false]));
        assert!(topology_has_smt(&[true]));
        let allowed = [true, true, true];
        assert!(!sibling_ok(false, 1, &allowed));
        assert!(!sibling_ok(false, 0, &allowed));
        assert!(sibling_ok(true, 1, &allowed));
        assert!(!sibling_ok(true, 1, &[true, false, true]));
        assert!(!sibling_ok(true, -1, &allowed));
        assert!(!sibling_ok(true, 9, &allowed));
        assert_eq!(pick_target_cpu(0, &[true]), Some(0));
        assert!(may_run_on(0, &[true]));
        assert!(!may_run_on(1, &[true]));
    }

    #[test]
    fn single_cpu_has_no_peers() {
        assert_eq!(next_peer(0, 1), None);
        assert_eq!(next_peer(0, 0), None);
        assert_eq!(next_peer(0, 2), Some(1));
        assert_eq!(next_peer(1, 2), Some(0));
        assert_eq!(next_peer(2, 2), None);
        assert_eq!(scan_bound(0), 0);
        assert_eq!(scan_bound(1), 0);
        assert_eq!(scan_bound(2), 1);
        assert_eq!(scan_bound(8), 7);
        assert_eq!(scan_bound(64), STEAL_BOUND);
        assert_eq!(stay_target(0, 1, &[true]), Some(0));
        assert_eq!(stay_target(0, 1, &[false]), None);
        assert_eq!(stay_target(1, 1, &[true]), None);
        assert_eq!(stay_target(-1, 1, &[true]), None);
        assert_eq!(pick_target_cpu(0, &[true]), Some(0));
        assert_eq!(pick_target_cpu(-1, &[true]), Some(0));
        assert_eq!(pick_target_cpu(5, &[true]), Some(0));
        assert_eq!(pick_target_cpu(0, &[false]), None);
    }

    #[test]
    fn single_cpu_scan_ends_at_once() {
        let mut steps = 0;
        let mut cur = next_peer(0, 1);
        while let Some(n) = cur {
            steps += 1;
            cur = next_peer(n, 1);
        }
        assert_eq!(steps, 0);
        assert_eq!(cur, None);
        let mut seen = 0;
        let mut at = 0;
        let bound = scan_bound(1);
        while seen < bound {
            at = next_peer(at, 1).unwrap_or(0);
            seen += 1;
        }
        assert_eq!(seen, 0);
        assert_eq!(at, 0);
    }

    #[test]
    fn steal_cursor_rotates_across_peers() {
        assert_eq!(steal_next(0, 4), 1);
        assert_eq!(steal_next(3, 4), 0);
        assert_eq!(steal_next(0, 1), 0);
        assert_eq!(steal_next(5, 0), 0);
        let mut cur = 0;
        for want in [1, 2, 3, 0, 1] {
            cur = steal_next(cur, 4);
            assert_eq!(cur, want);
        }
    }

    #[test]
    fn steal_bound_caps_large_hosts() {
        assert_eq!(scan_bound(2), 1);
        assert_eq!(scan_bound(9), 8);
        assert_eq!(scan_bound(16), 8);
        assert_eq!(scan_bound(1024), 8);
    }

    #[test]
    fn llc_ids_match_header() {
        assert!(llc_known(0));
        assert!(llc_known(1));
        assert!(!llc_known(LLC_UNKNOWN));
        assert!(!llc_ok(0));
        assert!(!llc_ok(1));
        assert!(llc_ok(2));
        assert_eq!(llc_of(0, &[0, 1]), Some(0));
        assert_eq!(llc_of(1, &[0, 1]), Some(1));
        assert_eq!(llc_of(2, &[0, 1]), None);
        assert_eq!(llc_of(0, &[LLC_UNKNOWN]), None);
    }

    #[test]
    fn llc_prefers_local_idle_over_remote() {
        let llc = [0, 0, 1, 1];
        let allowed = [true, true, true, true];
        let idle = [false, false, false, true];
        let full: [bool; 0] = [];
        assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle, &full, 2), Some(3));
        let idle2 = [true, false, false, false];
        assert_eq!(pick_llc_idle(2, &llc, &allowed, &idle2, &full, 2), None);
        assert_eq!(pick_any_idle(&allowed, &idle2), Some(0));
        assert_eq!(
            select_cpu_model(2, 0, &allowed, &idle, &llc, &full, 2),
            Some(3)
        );
        let idle3 = [true, false, false, true];
        assert_eq!(
            select_cpu_model(2, 0, &allowed, &idle3, &llc, &full, 2),
            Some(3)
        );
    }

    #[test]
    fn llc_fallback_when_domain_empty_unknown() {
        let llc = [0, 0, 1, 1];
        let allowed = [true, true, true, true];
        let idle = [true, false, false, false];
        let full: [bool; 0] = [];
        assert_eq!(pick_llc_idle(-1, &llc, &allowed, &idle, &full, 2), None);
        assert_eq!(pick_llc_idle(9, &llc, &allowed, &idle, &full, 2), None);
        let unknown = [LLC_UNKNOWN, LLC_UNKNOWN];
        assert_eq!(pick_llc_idle(0, &unknown, &allowed, &idle, &full, 0), None);
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 0), None);
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 1), None);
        assert_eq!(
            select_cpu_model(0, 0, &allowed, &idle, &llc, &full, 0),
            Some(0)
        );
        let empty = [false, false, false, false];
        assert_eq!(select_cpu_model(1, 0, &empty, &idle, &llc, &full, 2), None);
    }

    #[test]
    fn single_llc_matches_plain_order() {
        let single = [0, 0, 0, 0];
        let unknown = [LLC_UNKNOWN, LLC_UNKNOWN, LLC_UNKNOWN];
        let allowed = [true, true, true, true];
        let idle = [false, true, false, false];
        let full: [bool; 0] = [];
        assert!(!llc_ok(1));
        assert_eq!(pick_llc_idle(0, &single, &allowed, &idle, &full, 1), None);
        let got = select_cpu_model(0, 0, &allowed, &idle, &single, &full, 1);
        let exp = select_cpu_model(0, 0, &allowed, &idle, &unknown, &full, 0);
        assert_eq!(got, exp);
        assert_eq!(got, Some(1));
        let busy = [false, false, false, false];
        let got2 = select_cpu_model(2, 1, &allowed, &busy, &single, &full, 1);
        let exp2 = select_cpu_model(2, 1, &allowed, &busy, &unknown, &full, 0);
        assert_eq!(got2, exp2);
        assert_eq!(got2, Some(2));
    }

    #[test]
    fn llc_skips_smt_sibling_when_marked() {
        let llc = [0, 0, 0];
        let allowed = [true, true, true];
        let idle = [false, true, true];
        let full = [false, false, true];
        assert_eq!(pick_llc_idle(0, &llc, &allowed, &idle, &full, 2), Some(2));
        let idle_only_smt = [false, true, false];
        assert_eq!(
            pick_llc_idle(0, &llc, &allowed, &idle_only_smt, &full, 2),
            None
        );
        assert_eq!(
            select_cpu_model(0, 0, &allowed, &idle_only_smt, &llc, &full, 2),
            Some(1)
        );
    }

    #[test]
    fn dispatch_skips_dead_head() {
        /* Dead head models a NULL pid lookup. */
        let dead = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: false,
            fail: false,
        };
        /* Good tasks allow the asking CPU. */
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::from([dead.clone(), good.clone(), good.clone(), good.clone()]);
        let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert_eq!(moved, 3);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0], dead);
    }

    #[test]
    fn dispatch_skips_failed_move_with_progress() {
        /* Failed head models a denied queue move. */
        let failed = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: true,
        };
        /* Good tasks allow the asking CPU. */
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::from([failed.clone(), good.clone(), good.clone()]);
        let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(moved > 0);
        assert_eq!(moved, 2);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0], failed);
    }

    #[test]
    fn dispatch_batch_drains_within_passes() {
        let good = PendingTask {
            allowed: vec![true; 16],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::new();
        for _ in 0..64 {
            queue.push_back(good.clone());
        }
        let first = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert_eq!(first, 32);
        assert_eq!(queue.len(), 32);
        let second = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert_eq!(second, 32);
        assert!(queue.is_empty());
    }

    #[test]
    fn dispatch_park_skips_exiting_head() {
        /* Exiting head models a task in exit. */
        let exiting = PendingTask {
            allowed: vec![true, true],
            exiting: true,
            live: true,
            fail: false,
        };
        /* Foreign head allows only the other CPU. */
        let foreign = PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        };
        /* Good tasks allow the asking CPU. */
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue =
            VecDeque::from([exiting.clone(), foreign.clone(), good.clone(), good.clone()]);
        let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(moved > 0);
        assert_eq!(moved, 2);
        assert_eq!(queue.len(), 2);
        assert_eq!(queue[0], exiting);
        assert_eq!(queue[1], foreign);
    }

    #[test]
    fn progress_guarantee_moves_past_all_bad_heads() {
        /* Every bad shape sits at the head at once. */
        let dead = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: false,
            fail: false,
        };
        let exiting = PendingTask {
            allowed: vec![true, true],
            exiting: true,
            live: true,
            fail: false,
        };
        let foreign = PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let failed = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: true,
        };
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::from([
            dead.clone(),
            exiting.clone(),
            foreign.clone(),
            failed.clone(),
            good.clone(),
        ]);
        let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(moved > 0);
        assert_eq!(moved, 1);
        assert_eq!(queue.len(), 4);
    }

    #[test]
    fn progress_guarantee_property_holds() {
        /* Any movable task behind bad heads must move. */
        for trial in 0..32 {
            let mut queue = VecDeque::new();
            let bad = trial % 4;
            for i in 0..8 {
                let task = if i < 3 {
                    match (bad + i) % 4 {
                        0 => PendingTask {
                            allowed: vec![true, true],
                            exiting: false,
                            live: false,
                            fail: false,
                        },
                        1 => PendingTask {
                            allowed: vec![true, true],
                            exiting: true,
                            live: true,
                            fail: false,
                        },
                        2 => PendingTask {
                            allowed: vec![false, true],
                            exiting: false,
                            live: true,
                            fail: false,
                        },
                        _ => PendingTask {
                            allowed: vec![true, true],
                            exiting: false,
                            live: true,
                            fail: true,
                        },
                    }
                } else {
                    PendingTask {
                        allowed: vec![true, true],
                        exiting: false,
                        live: true,
                        fail: false,
                    }
                };
                queue.push_back(task);
            }
            let moved = drain_model(&mut queue, 0, 8);
            assert!(moved > 0);
            assert_eq!(moved, 5);
        }
    }

    #[test]
    fn progress_guarantee_zero_means_no_movable_work() {
        /* No movable work yields zero without failure. */
        let dead = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: false,
            fail: false,
        };
        let foreign = PendingTask {
            allowed: vec![false, false],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::from([dead.clone(), foreign.clone()]);
        let moved = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert_eq!(moved, 0);
        assert_eq!(queue.len(), 2);
        /* Adding one movable task restores progress. */
        queue.push_back(PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        });
        let moved2 = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(moved2 > 0);
        assert_eq!(moved2, 1);
    }

    #[test]
    fn incident_idle_cpu_progress_with_bad_heads() {
        /* Foreign tasks pin to the busy CPU. */
        let mut mask = vec![false; 16];
        mask[15] = true;
        let foreign = PendingTask {
            allowed: mask,
            exiting: false,
            live: true,
            fail: false,
        };
        /* Exiting tasks never run here. */
        let exiting = PendingTask {
            allowed: vec![true; 16],
            exiting: true,
            live: true,
            fail: false,
        };
        /* Dead tasks model a NULL pid lookup. */
        let dead = PendingTask {
            allowed: vec![true; 16],
            exiting: false,
            live: false,
            fail: false,
        };
        /* Failed tasks model a denied queue move. */
        let failed = PendingTask {
            allowed: vec![true; 16],
            exiting: false,
            live: true,
            fail: true,
        };
        /* Good tasks allow the idle CPU. */
        let good = PendingTask {
            allowed: vec![true; 16],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut queue = VecDeque::new();
        queue.push_back(exiting.clone());
        queue.push_back(foreign.clone());
        queue.push_back(dead.clone());
        queue.push_back(failed.clone());
        for _ in 0..40 {
            queue.push_back(good.clone());
        }
        assert_eq!(queue.len(), 44);
        /* First pass moves a full batch past bad heads. */
        let first = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(first > 0);
        assert_eq!(first, 32);
        assert_eq!(queue.len(), 12);
        assert_eq!(queue[0], exiting);
        assert_eq!(queue[1], foreign);
        assert_eq!(queue[2], dead);
        assert_eq!(queue[3], failed);
        /* Second pass drains the rest past bad heads. */
        let second = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(second > 0);
        assert_eq!(second, 8);
        assert_eq!(queue.len(), 4);
        /* Bad heads stay but never block new work. */
        queue.push_back(good.clone());
        queue.push_back(good.clone());
        let third = drain_model(&mut queue, 0, DISPATCH_BATCH);
        assert!(third > 0);
        assert_eq!(third, 2);
        assert_eq!(queue.len(), 4);
        assert_eq!(queue[0], exiting);
        assert_eq!(queue[1], foreign);
        assert_eq!(queue[2], dead);
        assert_eq!(queue[3], failed);
    }

    #[test]
    fn incident_steal_keeps_progress_with_bad_heads() {
        let good = PendingTask {
            allowed: vec![true, true, true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let bad = PendingTask {
            allowed: vec![false, false, false, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut peers: Vec<VecDeque<PendingTask>> = vec![
            VecDeque::new(),
            VecDeque::from([bad.clone(), good.clone()]),
            VecDeque::from([good.clone()]),
        ];
        let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
        assert!(moved > 0);
        assert_eq!(moved, 1);
        assert_eq!(peers[1].len(), 2);
    }

    #[test]
    fn steal_only_when_idle_and_bounded() {
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut peers: Vec<VecDeque<PendingTask>> = vec![
            VecDeque::new(),
            VecDeque::from([good.clone(), good.clone()]),
        ];
        let (busy, _) = steal_model(&mut peers.clone(), 0, 0, 8, false);
        assert_eq!(busy, 0);
        let (idle, next) = steal_model(&mut peers, 0, 0, 8, true);
        assert!(idle > 0);
        assert_eq!(idle, 1);
        assert_eq!(next, 1);
        let mut wide: Vec<VecDeque<PendingTask>> = vec![VecDeque::new(); 16];
        for q in wide.iter_mut().skip(1) {
            q.push_back(good.clone());
        }
        let (capped, _) = steal_model(&mut wide, 0, 0, 32, true);
        assert!(capped > 0);
        assert!(capped <= 8);
    }

    #[test]
    fn steal_checks_mask_and_skips_bad_heads() {
        let foreign = PendingTask {
            allowed: vec![false, false],
            exiting: false,
            live: true,
            fail: false,
        };
        let exiting = PendingTask {
            allowed: vec![true, true],
            exiting: true,
            live: true,
            fail: false,
        };
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        let mut peers: Vec<VecDeque<PendingTask>> = vec![
            VecDeque::new(),
            VecDeque::from([foreign.clone(), exiting.clone(), good.clone()]),
            VecDeque::from([good.clone()]),
        ];
        let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
        assert!(moved > 0);
        assert_eq!(moved, 1);
        assert_eq!(peers[1].len(), 3);
    }

    #[test]
    fn peer_drain_explicit_mask_skips_foreign_head() {
        /* Foreign head stays while good work waits. */
        let foreign = PendingTask {
            allowed: vec![false, true],
            exiting: false,
            live: true,
            fail: false,
        };
        /* Good head allows the thief. */
        let good = PendingTask {
            allowed: vec![true, true],
            exiting: false,
            live: true,
            fail: false,
        };
        assert!(!peer_head_ok(0, Some(&foreign)));
        assert!(peer_head_ok(0, Some(&good)));
        assert!(peer_head_ok(1, Some(&foreign)));
        assert!(!peer_head_ok(0, None));
        let mut peers: Vec<VecDeque<PendingTask>> = vec![
            VecDeque::new(),
            VecDeque::from([foreign.clone(), good.clone()]),
            VecDeque::from([good.clone()]),
        ];
        let (moved, _) = steal_model(&mut peers, 0, 0, 8, true);
        assert_eq!(moved, 1);
        assert_eq!(peers[1].len(), 2);
        assert_eq!(peers[2].len(), 0);
    }

    #[test]
    fn cleared_running_view_reads_idle() {
        let mut view = RunningView { est: 100, pid: 7 };
        assert!(!view.is_idle());
        view.clear();
        assert_eq!(view, RunningView::idle());
        assert!(view.is_idle());
    }

    #[test]
    fn depths_balance_across_join_leave() {
        let mut d = CpuDepths::new(4);
        d.join(0);
        d.join(0);
        d.join(1);
        assert_eq!(d.sum(), 3);
        d.leave(0);
        assert_eq!(d.sum(), 2);
        d.leave(0);
        d.leave(1);
        assert_eq!(d.sum(), 0);
        d.leave(0);
        assert_eq!(d.sum(), 0);
    }

    #[test]
    fn depths_saturate_at_bounds() {
        let mut d = CpuDepths::new(1);
        d.nr[0] = u64::MAX;
        d.join(0);
        assert_eq!(d.nr[0], u64::MAX);
        d.nr[0] = 0;
        d.leave(0);
        assert_eq!(d.nr[0], 0);
    }

    #[test]
    fn pinned_single_cpu_never_leaves() {
        let pinned = [false, false, true, false];
        for sel in [-1, 0, 1, 2, 3, 5, 99] {
            assert_eq!(pick_target_cpu(sel, &pinned), Some(2));
        }
        assert!(may_run_on(2, &pinned));
        assert!(!may_run_on(0, &pinned));
        assert!(!may_run_on(1, &pinned));
        assert!(!may_run_on(3, &pinned));
        assert!(!may_run_on(-1, &pinned));
        assert!(!may_run_on(99, &pinned));
    }

    #[test]
    fn narrow_mask_keeps_within_mask() {
        let narrow = [false, false, true, true, false];
        assert_eq!(pick_target_cpu(3, &narrow), Some(3));
        assert_eq!(pick_target_cpu(2, &narrow), Some(2));
        assert_eq!(pick_target_cpu(0, &narrow), Some(2));
        assert_eq!(pick_target_cpu(4, &narrow), Some(2));
        assert_eq!(pick_target_cpu(-1, &narrow), Some(2));
        assert_eq!(pick_target_cpu(99, &narrow), Some(2));
        assert!(may_run_on(2, &narrow));
        assert!(may_run_on(3, &narrow));
        assert!(!may_run_on(0, &narrow));
        assert!(!may_run_on(4, &narrow));
    }
}
