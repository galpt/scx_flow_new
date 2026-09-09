/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Deadline and queue helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Bound of moved tasks in one pass. */
pub const DISPATCH_BATCH: u32 = 32;
/* Owner value for tasks with no accounting. */
#[cfg(test)]
pub const OWNER_NONE: u32 = 0xFFFF_FFFF;
/* Batch window for sticky batching in nanos. */
#[cfg(test)]
pub const BATCH_EPS_NS: u64 = 96_000;
/* Grace after deadline in nanos for accounting. */
#[cfg(test)]
pub const GRACE_NS: u64 = 50_000;
/* Base id of the per-CPU ordered queues. */
#[cfg(test)]
pub const DSQ_BASE: u64 = 0x4000;
/* Park id for tasks with no allowed CPU. */
#[cfg(test)]
pub const DSQ_PARK: u64 = 0x5000;

/*
 * True when the first time is before the second with
 * wrap safety. The signed diff keeps order across the
 * u64 wrap with no extra branch.
 */
#[cfg(test)]
pub fn time_before(a: u64, b: u64) -> bool {
    (a.wrapping_sub(b) as i64) < 0
}

/*
 * Clamp virtual time to a bounded lag behind the
 * frontier. The floor is the frontier minus one slice
 * with wrap. A lagging value moves forward to the
 * floor with a clamp count. A fresh value stays.
 */
#[cfg(test)]
pub fn clamp_vruntime(v: u64, frontier: u64, slice: u64) -> u64 {
    let floor = frontier.wrapping_sub(slice);
    if time_before(v, floor) {
        floor
    } else {
        v
    }
}

/*
 * True when virtual time was clamped forward. Needs a
 * lag beyond one slice, so only sleepers count.
 */
#[cfg(test)]
pub fn was_clamped(v: u64, frontier: u64, slice: u64) -> bool {
    clamp_vruntime(v, frontier, slice) != v
}

/*
 * Deadline from clamped virtual time and scaled
 * estimate. The sum wraps with the clock with no
 * extra check, so order stays correct across wrap.
 */
#[cfg(test)]
pub fn deadline(clamped_v: u64, scaled: u64) -> u64 {
    clamped_v.wrapping_add(scaled)
}

/*
 * Advance virtual time by scaled runtime. The sum
 * wraps with the clock, so long runs stay ordered
 * across wrap with no extra check.
 */
#[cfg(test)]
pub fn vruntime_add(v: u64, delta: u64) -> u64 {
    v.wrapping_add(delta)
}

/*
 * Max of two virtual times with wrap safety. The later
 * time wins, so the frontier never moves backward
 * while work stays queued.
 */
#[cfg(test)]
pub fn frontier_max(old: u64, next: u64) -> u64 {
    if time_before(old, next) {
        next
    } else {
        old
    }
}

/*
 * Frontier for an idle CPU from the waking virtual
 * time. The waking value bounds the reset with no
 * zero use, so a new arrival never inherits stale
 * time while queued work never moves backward.
 */
#[cfg(test)]
pub fn frontier_idle(waking_v: u64) -> u64 {
    waking_v
}

/*
 * True when two deadlines fall in one batch window.
 * The window is tiny against the mean floor, so a
 * batch keeps cache warmth with no fair loss. Wrap
 * safe with unsigned distance and no signed negate.
 */
#[cfg(test)]
pub fn batch_within(a: u64, b: u64) -> bool {
    a.abs_diff(b) <= BATCH_EPS_NS
}

/*
 * True when now is still within grace past deadline.
 * Grace is tiny against the least period, so late
 * accounting stays prompt with no kill. The harness
 * cancels, the scheduler never kills. Wrap safe with
 * no extra branch beyond the before check.
 */
#[cfg(test)]
pub fn grace_ok(now: u64, deadline_val: u64) -> bool {
    let limit = deadline_val.wrapping_add(GRACE_NS);
    if now == limit {
        return true;
    }
    time_before(now, limit)
}

/*
 * Full EDF insert model. Clamps the virtual time to a
 * bounded lag, scales the estimate, and adds the
 * deadline with wrap. Returns the clamped time, the
 * deadline, and the clamp flag for counts.
 */
#[cfg(test)]
pub fn edf_insert(v: u64, frontier: u64, slice: u64, est: u64, weight: u32) -> (u64, u64, bool) {
    let clamped = clamp_vruntime(v, frontier, slice);
    let flag = clamped != v;
    let scaled = crate::flow_mean::scale_by_weight(crate::flow_mean::clamp_est(est), weight);
    let dl = deadline(clamped, scaled);
    (clamped, dl, flag)
}

/*
 * Frontier step for a stop. A runnable stop or queued
 * work keeps the max, so time never moves backward
 * while work stays queued. An idle block resets to the
 * waking virtual time with no zero use. The insert
 * deadline and this step compose in order with the
 * deadline first and the frontier next, so one insert
 * plus one stop moves both forward at once.
 */
#[cfg(test)]
pub fn frontier_step(old: u64, new_v: u64, runnable: bool, queued: u64) -> u64 {
    if !runnable && queued == 0 {
        frontier_idle(new_v)
    } else {
        frontier_max(old, new_v)
    }
}

/*
 * Combined insert plus frontier step for tests. Runs
 * the insert model then advances virtual time by the
 * scaled estimate and steps the frontier, so callers
 * see the clamped time plus the deadline plus the next
 * frontier at once with no extra path. Mirrors the BPF
 * order of enqueue then stopping with no new path.
 */
#[cfg(test)]
pub fn edf_insert_and_step(
    v: u64,
    frontier: u64,
    slice: u64,
    est: u64,
    weight: u32,
    runnable: bool,
    queued: u64,
) -> (u64, u64, u64, bool) {
    let (clamped, dl, flag) = edf_insert(v, frontier, slice, est, weight);
    let scaled = crate::flow_mean::scale_by_weight(crate::flow_mean::clamp_est(est), weight);
    let next_v = vruntime_add(clamped, scaled);
    let next_frontier = frontier_step(frontier, next_v, runnable, queued);
    (clamped, dl, next_frontier, flag)
}

/*
 * True when an overload should shed to park. Needs a
 * target queue at one full batch, so only excess
 * sheds while the owner stays fair. The shed keeps
 * the target frontier with owner none and no kill
 * and no Pi use. Park keeps order by deadline.
 */
#[cfg(test)]
pub fn should_shed(queue_len: u64) -> bool {
    queue_len >= DISPATCH_BATCH as u64
}

/*
 * Idle frontier with a zero guard. Zero never wins,
 * so a waking value of zero keeps the old frontier.
 * A nonzero waking value bounds the reset with no
 * stale zero use. Mirrors the BPF idle guard.
 */
#[cfg(test)]
pub fn frontier_idle_guarded(old: u64, waking_v: u64) -> u64 {
    if waking_v == 0 {
        old
    } else {
        frontier_idle(waking_v)
    }
}

/*
 * Idle frontier with grace and zero guard. Runnable
 * stops keep the max, so time never moves backward
 * while work stays queued. Queued work keeps the max
 * with the same bound. An idle stop with zero keeps
 * the old frontier with no stale zero use. An idle
 * stop past grace keeps the max for prompt account.
 * An idle stop within grace resets to waking time.
 * Mirrors the BPF stopping path with no new path.
 */
#[cfg(test)]
pub fn frontier_idle_grace_step(
    old: u64,
    waking_v: u64,
    deadline: u64,
    now: u64,
    runnable: bool,
    dsq: u64,
    local: u64,
) -> u64 {
    if runnable {
        return frontier_max(old, waking_v);
    }
    if dsq != 0 || local != 0 {
        return frontier_max(old, waking_v);
    }
    if waking_v == 0 {
        return old;
    }
    if deadline != 0 && !grace_ok(now, deadline) {
        return frontier_max(old, waking_v);
    }
    frontier_idle(waking_v)
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
 * True when a mean replace may run. Needs distinct
 * clamped estimates, so equal bursts skip the sum and
 * mean write at once.
 */
#[cfg(test)]
pub fn should_replace(old: u64, new: u64) -> bool {
    crate::flow_mean::clamp_est(old) != crate::flow_mean::clamp_est(new)
}

/*
 * Ordered entry for tests. The deadline orders the
 * queue. The sequence keeps arrival order when
 * deadlines match.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderedEntry {
    /* Clamped virtual time plus scaled estimate. */
    pub deadline: u64,
    /* Arrival sequence used for ties. Lower is older. */
    pub seq: u64,
    /* Task id used only to name the entry. */
    pub id: u64,
}

#[cfg(test)]
impl OrderedEntry {
    /*
     * True when this entry sorts before the other. The
     * smaller deadline wins. Equal deadlines keep
     * arrival order with the older sequence first.
     */
    pub fn before(&self, other: &Self) -> bool {
        if self.deadline != other.deadline {
            return time_before(self.deadline, other.deadline);
        }
        self.seq < other.seq
    }
}

/*
 * Insert one entry into an ordered queue. The queue
 * stays sorted by deadline with arrival order for
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
 * Drain up to budget tasks for one CPU. The scan
 * visits every queued task in order and moves each
 * live task with the CPU in the mask and with no
 * move failure. Exiting tasks move when allowed, so
 * they run to exit on the owner or on a thief. Dead,
 * foreign, and failed heads are skipped, so one head
 * never blocks later work. Returns the count moved.
 * A zero return means no movable work was present.
 */
#[cfg(test)]
pub fn drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    budget: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved < budget
            && task.live
            && !task.fail
            && crate::flow_select::may_run_on(cpu, &task.allowed);
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
 * Own budget with one slot reserved for park. When
 * the gate is set and park holds work, own keeps one
 * slot free so park always drains one task per pass.
 * The total stays at batch with donor depth at two
 * and steal bound at eight. The gate keeps revert
 * exact, so zero restores 4.2.0 order. Always reserve
 * would also work, gate documents the shed link. The
 * BPF side uses one cached park read with a branchless
 * subtract, this test form keeps the same conditional
 * result with no behavior change.
 */
#[cfg(test)]
pub fn own_budget_for_dispatch(budget: u32, park_queued: u64, iedf: bool) -> u32 {
    if iedf && park_queued > 0 && budget > 0 {
        budget - 1
    } else {
        budget
    }
}

/*
 * Dispatch own then park with the park reserve. Drains
 * own with the reserved budget, then drains park with
 * the rest, so park moves one task per pass even when
 * own stays saturated. The total never exceeds budget.
 * Mirrors the BPF dispatch order with no new path.
 */
#[cfg(test)]
pub fn dispatch_own_park_model(
    own: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    park: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    budget: u32,
    iedf: bool,
) -> (u32, u32) {
    let own_budget = own_budget_for_dispatch(budget, park.len() as u64, iedf);
    let moved_own = drain_model(own, cpu, own_budget);
    let moved_park = if (park.len() as u64) > 0 && moved_own < budget {
        drain_model(park, cpu, budget - moved_own)
    } else {
        0
    };
    (moved_own, moved_park)
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
 * Per-CPU depth for tests. Each slot counts queued
 * tasks on one CPU across all queues. The sum matches
 * the queued total.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuDepths {
    /* Queued tasks per-CPU. Index is the CPU. */
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
