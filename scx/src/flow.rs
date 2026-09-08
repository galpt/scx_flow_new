/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Pure scheduling helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Base id of the per cpu queues. */
#[cfg(test)]
pub const DSQ_BASE: u64 = 0x1000;
/* Stride between the queues of one cpu. */
#[cfg(test)]
pub const DSQ_STRIDE: u64 = 3;
/* Count of queues kept for each cpu. */
#[cfg(test)]
pub const NQUEUES: u32 = 3;
/* Base id of the park queues, one per queue. */
#[cfg(test)]
pub const PARK_BASE: u64 = 0x1000 + 1024 * 3;
/* Floor of the first queue quantum in nanoseconds. */
pub const QUANTUM_MIN0_NS: u64 = 500_000;
/* Ceiling of the first queue quantum in nanoseconds. */
pub const QUANTUM_MAX0_NS: u64 = 4_000_000;
/* Seed of the first queue quantum in nanoseconds. */
pub const QUANTUM_SEED0_NS: u64 = 1_000_000;
/* Floor of the second queue quantum in nanoseconds. */
pub const QUANTUM_MIN1_NS: u64 = 1_000_000;
/* Ceiling of the second queue quantum in nanoseconds. */
pub const QUANTUM_MAX1_NS: u64 = 8_000_000;
/* Seed of the second queue quantum in nanoseconds. */
pub const QUANTUM_SEED1_NS: u64 = 2_000_000;
/* Floor of the third queue quantum in nanoseconds. */
pub const QUANTUM_MIN2_NS: u64 = 4_000_000;
/* Ceiling of the third queue quantum in nanoseconds. */
pub const QUANTUM_MAX2_NS: u64 = 32_000_000;
/* Seed of the third queue quantum in nanoseconds. */
pub const QUANTUM_SEED2_NS: u64 = 8_000_000;
/* Lower bound of a per task estimate in nanoseconds. */
#[cfg(test)]
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanoseconds. */
#[cfg(test)]
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Head age that lifts a queue past strict order. */
#[cfg(test)]
pub const PROMOTE_AGE_NS: u64 = 500_000_000;
/* Bound of the remote scan in one dispatch pass. */
pub const STEAL_SCAN_MAX: u32 = 64;
/* Bound of the moved tasks in one dispatch pass. */
pub const DISPATCH_BATCH: u32 = 32;

/*
 * Queue id of a cpu and queue pair. The layout is base
 * plus cpu times stride plus queue, so the owning cpu
 * and the queue decode with plain arithmetic.
 */
#[cfg(test)]
pub fn dsq_id(cpu: u32, queue: u32) -> u64 {
    DSQ_BASE + cpu as u64 * DSQ_STRIDE + queue as u64
}

/*
 * Queue id of a park queue. The park holds tasks with
 * no allowed cpu. One park queue exists per queue.
 */
#[cfg(test)]
pub fn park_id(queue: u32) -> u64 {
    PARK_BASE + queue as u64
}

/* Check that a queue index names a real queue. */
#[cfg(test)]
pub fn queue_ok(queue: u32) -> bool {
    queue < NQUEUES
}

/*
 * Check that an id names a park queue. Park ids sit in
 * a fixed range past all per cpu queues.
 */
#[cfg(test)]
pub fn is_park(id: u64) -> bool {
    id >= PARK_BASE && id < PARK_BASE + NQUEUES as u64
}

/* Decode the owning cpu from a per cpu queue id. */
#[cfg(test)]
pub fn dsq_cpu(id: u64) -> u32 {
    if is_park(id) {
        return 0;
    }
    if id < DSQ_BASE {
        return 0;
    }
    ((id - DSQ_BASE) / DSQ_STRIDE) as u32
}

/*
 * Decode the queue index from a queue id. Park ids
 * decode to the park queue. Per cpu ids decode with
 * plain arithmetic. Unknown ids fall back to zero.
 */
#[cfg(test)]
pub fn dsq_queue(id: u64) -> u32 {
    if is_park(id) {
        return (id - PARK_BASE) as u32;
    }
    if id < DSQ_BASE {
        return 0;
    }
    ((id - DSQ_BASE) % DSQ_STRIDE) as u32
}

/* Floor of one queue quantum in nanoseconds. */
pub fn quantum_min(queue: u32) -> u64 {
    match queue {
        1 => QUANTUM_MIN1_NS,
        2 => QUANTUM_MIN2_NS,
        _ => QUANTUM_MIN0_NS,
    }
}

/* Ceiling of one queue quantum in nanoseconds. */
pub fn quantum_max(queue: u32) -> u64 {
    match queue {
        1 => QUANTUM_MAX1_NS,
        2 => QUANTUM_MAX2_NS,
        _ => QUANTUM_MAX0_NS,
    }
}

/* Seed of one queue quantum in nanoseconds. */
pub fn quantum_seed(queue: u32) -> u64 {
    match queue {
        1 => QUANTUM_SEED1_NS,
        2 => QUANTUM_SEED2_NS,
        _ => QUANTUM_SEED0_NS,
    }
}

/*
 * Clamp a quantum of one queue to the queue range. Low
 * values rise to the floor. High values fall to the
 * ceiling.
 */
pub fn clamp_quantum(queue: u32, v: u64) -> u64 {
    v.clamp(quantum_min(queue), quantum_max(queue))
}

/*
 * Clamp a per task estimate to the estimate range. The
 * floor keeps the value positive. The ceiling keeps one
 * long run from shaping later choice.
 */
#[cfg(test)]
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Seed quantum of one queue. The seed sits inside the
 * queue range, so the clamp keeps it unchanged while
 * it guards later values.
 */
pub fn seed_quantum(queue: u32) -> u64 {
    clamp_quantum(queue, quantum_seed(queue))
}

/*
 * Mean quantum of one queue over accounted tasks. An
 * empty set keeps the last value. A zero last value
 * falls back to the seed, so the result is never zero.
 */
#[cfg(test)]
pub fn mean_quantum(queue: u32, sum: u64, nr: u64, last: u64) -> u64 {
    if nr == 0 {
        if last == 0 {
            return seed_quantum(queue);
        }
        return clamp_quantum(queue, last);
    }
    clamp_quantum(queue, sum / nr)
}

/*
 * Live quantum of one queue from its mean. A zero mean
 * falls back to the seed, so grants track the live
 * mean while the result stays in range.
 */
pub fn live_quantum(queue: u32, mean: u64) -> u64 {
    if mean == 0 {
        return seed_quantum(queue);
    }
    clamp_quantum(queue, mean)
}

/*
 * Slice grant of one queue from its mean. The grant
 * follows the live mean only, so the slice is fixed
 * for the queue at grant time.
 */
#[cfg(test)]
pub fn slice_for_queue(queue: u32, mean: u64) -> u64 {
    live_quantum(queue, mean)
}

/*
 * Queue of a new or unknown task. New tasks start at
 * the first queue, so short bursts drain first.
 */
#[cfg(test)]
pub fn queue_for_new() -> u32 {
    0
}

/*
 * Check that a burst burned the full slice. A zero
 * slice never counts as burned, so a missing grant
 * holds the queue.
 */
#[cfg(test)]
pub fn burned(slice: u64, delta: u64) -> bool {
    if slice == 0 {
        return false;
    }
    delta >= slice
}

/*
 * Next queue after a run. A runnable task that burned
 * the full slice moves down one queue. All other tasks
 * hold the queue. The last queue holds as well.
 */
#[cfg(test)]
pub fn next_on_burn(queue: u32, runnable: bool, is_burned: bool) -> u32 {
    if !runnable {
        return queue;
    }
    if !is_burned {
        return queue;
    }
    if queue + 1 < NQUEUES {
        return queue + 1;
    }
    queue
}

/*
 * Check that a head age earns a move up. Ages at or
 * past the bound earn the reward. Younger ages hold.
 */
#[cfg(test)]
pub fn should_promote(age: u64) -> bool {
    age >= PROMOTE_AGE_NS
}

/*
 * Next queue after the age check. An aged queue moves
 * up one queue. All other queues hold. The first queue
 * holds as well.
 */
#[cfg(test)]
pub fn promote_if_aged(queue: u32, age: u64) -> u32 {
    if !should_promote(age) {
        return queue;
    }
    if queue == 0 {
        return queue;
    }
    queue - 1
}

/*
 * Resolve the next queue with promotion first. An aged
 * head earns one step up and skips the burn check. A
 * runnable burn moves down one queue. All other tasks
 * hold. The flags report the move for counters.
 */
#[cfg(test)]
pub fn resolve_queue(
    current: u32,
    runnable: bool,
    is_burned: bool,
    head_age: u64,
) -> (u32, bool, bool) {
    if should_promote(head_age) && current > 0 {
        return (current - 1, true, false);
    }
    let next = next_on_burn(current, runnable, is_burned);
    if next > current {
        return (next, false, true);
    }
    (current, false, false)
}

/*
 * Pick the next queue to serve. Aged non empty queues
 * come first by oldest age. Other queues follow strict
 * order. Empty queues never win. No queued task yields
 * no pick.
 */
#[cfg(test)]
pub fn pick_dispatch(queued: [bool; 3], head_age: [u64; 3]) -> Option<usize> {
    let mut best_aged: Option<usize> = None;
    let mut best_age: u64 = 0;
    for (q, &is_q) in queued.iter().enumerate() {
        if !is_q {
            continue;
        }
        let age = head_age[q];
        if !should_promote(age) {
            continue;
        }
        match best_aged {
            None => {
                best_aged = Some(q);
                best_age = age;
            }
            Some(_) => {
                if age > best_age {
                    best_aged = Some(q);
                    best_age = age;
                }
            }
        }
    }
    if let Some(q) = best_aged {
        return Some(q);
    }
    (0..3).find(|&q| queued[q])
}

/*
 * Check that a steal candidate may run here. The peer
 * mask must include the stealing cpu. Missing masks
 * fail closed and skip the steal.
 */
#[cfg(test)]
pub fn steal_ok(peer_mask: &[bool], cpu: u32) -> bool {
    match peer_mask.get(cpu as usize) {
        Some(&v) => v,
        None => false,
    }
}

/*
 * Target cpu from the selected cpu. A valid allowed
 * selected cpu wins. Otherwise the first allowed cpu
 * wins. No allowed cpu yields no target for park use.
 * Pinned tasks resolve to the single allowed cpu here.
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
 * Age of the head of the busy period. A zero stamp
 * means the set is empty, so the age is zero. Later
 * time values give a forward age with saturation.
 */
pub fn head_age(now: u64, head_at: u64) -> u64 {
    if head_at == 0 {
        return 0;
    }
    now.saturating_sub(head_at)
}

/*
 * Age of the most recent arrival. A zero stamp means
 * the set is empty, so the age is zero. Later time
 * values give a forward age with saturation.
 */
#[cfg(test)]
pub fn tail_age(now: u64, tail_at: u64) -> u64 {
    if tail_at == 0 {
        return 0;
    }
    now.saturating_sub(tail_at)
}

/*
 * Per queue mean state. The count holds accounted tasks
 * in the queue. The sum holds clamped estimates with
 * saturation. The mean holds the live quantum with keep
 * last. The queue selects the range for the clamp.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub struct QueueState {
    /* Accounted task count in the queue. */
    pub nr: u64,
    /* Sum of clamped estimates in the queue. */
    pub sum: u64,
    /* Live mean quantum of the queue. */
    pub mean: u64,
    /* Queue index that selects the range. */
    pub queue: u32,
}

#[cfg(test)]
impl QueueState {
    /*
     * Empty state of one queue seeded at the queue seed.
     * The count starts at zero and the mean starts
     * clamped.
     */
    pub fn new(queue: u32) -> Self {
        let q = if queue_ok(queue) { queue } else { 0 };
        Self {
            nr: 0,
            sum: 0,
            mean: seed_quantum(q),
            queue: q,
        }
    }

    /*
     * Recompute the mean. An empty set keeps the last
     * value, so the quantum is never zero.
     */
    pub fn recompute(&mut self) {
        self.mean = mean_quantum(self.queue, self.sum, self.nr, self.mean);
    }

    /*
     * Add one estimate to the queue. The sum saturates
     * at the top, so a burst cannot wrap the value.
     */
    pub fn add(&mut self, est: u64) {
        let e = if est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(est)
        };
        self.nr = self.nr.saturating_add(1);
        self.sum = self.sum.saturating_add(e);
        self.recompute();
    }

    /*
     * Remove one estimate from the queue. The count and
     * the sum never go below zero. An empty set keeps
     * the last mean.
     */
    pub fn remove(&mut self, est: u64) {
        let e = if est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(est)
        };
        if self.nr > 0 {
            self.nr -= 1;
        }
        self.sum = self.sum.saturating_sub(e);
        self.recompute();
    }

    /*
     * Refresh one estimate in place. The count stays
     * fixed and the sum swaps the old estimate for the
     * new one. Used when a runnable requeue keeps the
     * queue, so no double count occurs.
     */
    pub fn refresh(&mut self, old_est: u64, new_est: u64) {
        let o = if old_est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(old_est)
        };
        let n = if new_est == 0 {
            clamp_est(EST_MIN_NS)
        } else {
            clamp_est(new_est)
        };
        if o == n {
            return;
        }
        self.sum = self.sum.saturating_sub(o).saturating_add(n);
        self.recompute();
    }
}

#[cfg(test)]
impl Default for QueueState {
    /* Default state matches the empty first queue. */
    fn default() -> Self {
        Self::new(0)
    }
}

/*
 * Per cpu depth table. Each slot counts accounted tasks
 * for one cpu across all queues. The sum of the slots
 * matches the queued total when no task waits in park.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(test)]
pub struct CpuDepths {
    /* One count per cpu. Index is the cpu id. */
    pub counts: Vec<u64>,
}

#[cfg(test)]
impl CpuDepths {
    /*
     * Empty table for a fixed cpu count. All slots
     * start at zero.
     */
    pub fn new(nr_cpus: usize) -> Self {
        Self {
            counts: vec![0; nr_cpus],
        }
    }

    /*
     * Add one task to a cpu. Out of range ids are a no
     * op, so park tasks leave the table alone.
     */
    pub fn inc(&mut self, cpu: u32) {
        if let Some(v) = self.counts.get_mut(cpu as usize) {
            *v = v.saturating_add(1);
        }
    }

    /*
     * Remove one task from a cpu. Counts never go below
     * zero. Out of range ids are a no op.
     */
    pub fn dec(&mut self, cpu: u32) {
        if let Some(v) = self.counts.get_mut(cpu as usize) {
            *v = v.saturating_sub(1);
        }
    }

    /*
     * Move one task between cpus. A same cpu move is a
     * no op. Out of range ids leave the table alone.
     */
    pub fn shift(&mut self, old_cpu: u32, new_cpu: u32) {
        if old_cpu == new_cpu {
            return;
        }
        self.dec(old_cpu);
        self.inc(new_cpu);
    }

    /*
     * Sum of all per cpu slots. Matches the queued
     * total when the park is empty.
     */
    pub fn sum(&self) -> u64 {
        self.counts.iter().copied().sum()
    }

    /*
     * Depth of one cpu. Out of range ids read as zero.
     */
    pub fn get(&self, cpu: u32) -> u64 {
        self.counts.get(cpu as usize).copied().unwrap_or(0)
    }
}

/*
 * Running view of one cpu for tests. Mirrors the BPF
 * cpu state fields used by the dashboard. Zero pid
 * means idle.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningView {
    /* Estimate of the task now on the cpu. */
    pub est: u64,
    /* Pid now on the cpu. Zero when idle. */
    pub pid: u32,
    /* Queue of the task now on the cpu. */
    pub queue: u32,
}

#[cfg(test)]
impl RunningView {
    /*
     * Idle view with all fields at zero. Matches the
     * cleared BPF state after stopping.
     */
    pub fn idle() -> Self {
        Self {
            est: 0,
            pid: 0,
            queue: 0,
        }
    }

    /*
     * True when no task runs on the cpu. The dashboard
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
        self.queue = 0;
    }
}

/*
 * Slot for a demotion move. The source queue owns the
 * count, so the first two slots stay reachable and the
 * bottom slot stays at zero by design.
 */
#[cfg(test)]
pub fn demotion_slot(source: u32) -> usize {
    source as usize
}

/*
 * Slot for a promotion move. The source queue owns the
 * count, so the last two slots stay reachable and the
 * first slot stays at zero by design.
 */
#[cfg(test)]
pub fn promotion_slot(source: u32) -> usize {
    source as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn dsq_ids_follow_base_stride_layout() {
        assert_eq!(dsq_id(0, 0), 0x1000);
        assert_eq!(dsq_id(0, 1), 0x1001);
        assert_eq!(dsq_id(0, 2), 0x1002);
        assert_eq!(dsq_id(1, 0), 0x1003);
        assert_eq!(dsq_id(1, 1), 0x1004);
        assert_eq!(dsq_id(1, 2), 0x1005);
        assert_eq!(DSQ_STRIDE, 3);
        assert_eq!(NQUEUES, 3);
    }

    #[test]
    fn dsq_ids_round_trip_through_decode() {
        for cpu in [0, 1, 7, 64] {
            for q in [0, 1, 2] {
                let id = dsq_id(cpu, q);
                assert_eq!(dsq_cpu(id), cpu);
                assert_eq!(dsq_queue(id), q);
                assert!(!is_park(id));
            }
        }
    }

    #[test]
    fn park_ids_decode_to_park_queue() {
        for q in [0, 1, 2] {
            let id = park_id(q);
            assert!(is_park(id));
            assert_eq!(dsq_queue(id), q);
        }
        assert!(!is_park(dsq_id(0, 0)));
        assert!(!is_park(dsq_id(3, 2)));
    }

    #[test]
    fn park_base_sits_past_all_cpu_queues() {
        let last = dsq_id(1023, 2);
        assert!(last < PARK_BASE);
        assert_eq!(PARK_BASE, 0x1000 + 1024 * 3);
        assert_eq!(park_id(0), PARK_BASE);
    }

    #[test]
    fn dsq_decode_guards_underflow() {
        assert_eq!(dsq_cpu(0), 0);
        assert_eq!(dsq_cpu(DSQ_BASE - 1), 0);
        assert_eq!(dsq_queue(0), 0);
    }

    #[test]
    fn quantum_ranges_match_spec() {
        assert_eq!(QUANTUM_MIN0_NS, 500_000);
        assert_eq!(QUANTUM_MAX0_NS, 4_000_000);
        assert_eq!(QUANTUM_SEED0_NS, 1_000_000);
        assert_eq!(QUANTUM_MIN1_NS, 1_000_000);
        assert_eq!(QUANTUM_MAX1_NS, 8_000_000);
        assert_eq!(QUANTUM_SEED1_NS, 2_000_000);
        assert_eq!(QUANTUM_MIN2_NS, 4_000_000);
        assert_eq!(QUANTUM_MAX2_NS, 32_000_000);
        assert_eq!(QUANTUM_SEED2_NS, 8_000_000);
    }

    #[test]
    fn quantum_clamp_holds_each_range() {
        assert_eq!(clamp_quantum(0, 0), QUANTUM_MIN0_NS);
        assert_eq!(clamp_quantum(0, u64::MAX), QUANTUM_MAX0_NS);
        assert_eq!(clamp_quantum(1, 0), QUANTUM_MIN1_NS);
        assert_eq!(clamp_quantum(1, u64::MAX), QUANTUM_MAX1_NS);
        assert_eq!(clamp_quantum(2, 0), QUANTUM_MIN2_NS);
        assert_eq!(clamp_quantum(2, u64::MAX), QUANTUM_MAX2_NS);
        assert_eq!(clamp_quantum(0, 1_000_000), 1_000_000);
        assert_eq!(clamp_quantum(1, 2_000_000), 2_000_000);
        assert_eq!(clamp_quantum(2, 8_000_000), 8_000_000);
    }

    #[test]
    fn quantum_seed_sits_in_range() {
        assert_eq!(seed_quantum(0), 1_000_000);
        assert_eq!(seed_quantum(1), 2_000_000);
        assert_eq!(seed_quantum(2), 8_000_000);
    }

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
    fn new_tasks_start_at_first_queue() {
        assert_eq!(queue_for_new(), 0);
    }

    #[test]
    fn mean_empty_keeps_last_per_queue() {
        let last0 = 1_000_000;
        assert_eq!(mean_quantum(0, 0, 0, last0), last0);
        let last1 = 2_000_000;
        assert_eq!(mean_quantum(1, 0, 0, last1), last1);
        let last2 = 8_000_000;
        assert_eq!(mean_quantum(2, 0, 0, last2), last2);
    }

    #[test]
    fn mean_empty_zero_falls_back_to_seed() {
        assert_eq!(mean_quantum(0, 0, 0, 0), 1_000_000);
        assert_eq!(mean_quantum(1, 0, 0, 0), 2_000_000);
        assert_eq!(mean_quantum(2, 0, 0, 0), 8_000_000);
    }

    #[test]
    fn mean_divides_and_clamps_per_queue() {
        assert_eq!(mean_quantum(0, 2_000_000, 2, 1_000_000), 1_000_000);
        assert_eq!(mean_quantum(0, 100, 2, 1_000_000), QUANTUM_MIN0_NS);
        assert_eq!(mean_quantum(0, 100_000_000, 1, 1_000_000), QUANTUM_MAX0_NS);
        assert_eq!(mean_quantum(1, 100, 1, 2_000_000), QUANTUM_MIN1_NS);
        assert_eq!(mean_quantum(2, 1, 1, 8_000_000), QUANTUM_MIN2_NS);
    }

    #[test]
    fn live_quantum_tracks_mean_per_queue() {
        assert_eq!(live_quantum(0, 1_000_000), 1_000_000);
        assert_eq!(live_quantum(1, 2_000_000), 2_000_000);
        assert_eq!(live_quantum(2, 8_000_000), 8_000_000);
    }

    #[test]
    fn live_quantum_clamps_and_falls_back() {
        assert_eq!(live_quantum(0, 100), QUANTUM_MIN0_NS);
        assert_eq!(live_quantum(0, 100_000_000), QUANTUM_MAX0_NS);
        assert_eq!(live_quantum(0, 0), 1_000_000);
        assert_eq!(live_quantum(1, 0), 2_000_000);
        assert_eq!(live_quantum(2, 0), 8_000_000);
    }

    #[test]
    fn granted_slice_stays_in_queue_range() {
        for q in [0, 1, 2] {
            for mean in [quantum_min(q), seed_quantum(q)] {
                let slice = slice_for_queue(q, mean);
                assert!(slice >= quantum_min(q));
                assert!(slice <= quantum_max(q));
            }
        }
    }

    #[test]
    fn queue_add_recomputes_live_mean() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 1_000_000);
        assert_eq!(s.mean, 1_000_000);
        s.add(3_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.mean, 2_000_000);
    }

    #[test]
    fn queue_remove_saturates_at_zero() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        s.remove(5_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        assert_eq!(s.mean, 1_000_000);
    }

    #[test]
    fn queue_remove_empty_keeps_last() {
        let mut s = QueueState::new(1);
        let last = s.mean;
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        assert_eq!(s.mean, last);
    }

    #[test]
    fn queue_sum_saturates_at_top() {
        let mut s = QueueState::new(0);
        s.sum = u64::MAX - 10;
        s.nr = 1;
        s.add(100);
        assert_eq!(s.sum, u64::MAX);
        assert_eq!(s.mean, QUANTUM_MAX0_NS);
    }

    #[test]
    fn queue_nr_saturates_at_top() {
        let mut s = QueueState::new(0);
        s.nr = u64::MAX;
        s.sum = u64::MAX;
        s.add(1_000_000);
        assert_eq!(s.nr, u64::MAX);
        assert_eq!(s.sum, u64::MAX);
    }

    #[test]
    fn refresh_keeps_count_stable() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        s.refresh(1_000_000, 2_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 2_000_000);
        assert_eq!(s.mean, 2_000_000);
    }

    #[test]
    fn refresh_same_value_is_noop() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        s.refresh(1_000_000, 1_000_000);
        assert_eq!(s.nr, 1);
        assert_eq!(s.sum, 1_000_000);
    }

    #[test]
    fn refresh_balance_holds_sum() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        s.add(3_000_000);
        assert_eq!(s.sum, 4_000_000);
        s.refresh(1_000_000, 2_000_000);
        assert_eq!(s.nr, 2);
        assert_eq!(s.sum, 5_000_000);
        assert_eq!(s.mean, 2_500_000);
    }

    #[test]
    fn release_is_idempotent() {
        let mut s = QueueState::new(0);
        s.add(1_000_000);
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
        s.remove(1_000_000);
        assert_eq!(s.nr, 0);
        assert_eq!(s.sum, 0);
    }

    #[test]
    fn demotion_moves_down_one_on_full_burn() {
        assert_eq!(next_on_burn(0, true, true), 1);
        assert_eq!(next_on_burn(1, true, true), 2);
        assert_eq!(next_on_burn(2, true, true), 2);
    }

    #[test]
    fn demotion_holds_on_block_or_short_run() {
        assert_eq!(next_on_burn(0, false, true), 0);
        assert_eq!(next_on_burn(1, false, true), 1);
        assert_eq!(next_on_burn(0, true, false), 0);
        assert_eq!(next_on_burn(1, true, false), 1);
        assert_eq!(next_on_burn(2, false, false), 2);
    }

    #[test]
    fn demotion_burn_boundary_holds_below_slice() {
        let slice = 2_000_000;
        assert!(!burned(slice, slice - 1));
        assert!(burned(slice, slice));
        assert!(burned(slice, slice + 1));
        assert!(!burned(0, 0));
        assert!(!burned(0, 1_000_000));
        assert_eq!(next_on_burn(0, true, false), 0);
        assert_eq!(next_on_burn(0, true, true), 1);
    }

    #[test]
    fn demotion_property_holds_or_moves_one() {
        for q in [0, 1, 2] {
            for runnable in [false, true] {
                for delta in [0, 500_000, 2_000_000] {
                    let slice = 2_000_000;
                    let is_burned = burned(slice, delta);
                    let next = next_on_burn(q, runnable, is_burned);
                    assert!(next == q || next == q + 1);
                    if q == 2 {
                        assert_eq!(next, 2);
                    }
                    if !runnable || !is_burned {
                        assert_eq!(next, q);
                    }
                }
            }
        }
    }

    #[test]
    fn promotion_age_boundary_needs_full_wait() {
        assert_eq!(PROMOTE_AGE_NS, 500_000_000);
        assert!(!should_promote(PROMOTE_AGE_NS - 1));
        assert!(should_promote(PROMOTE_AGE_NS));
        assert!(should_promote(PROMOTE_AGE_NS + 1));
        assert_eq!(promote_if_aged(2, PROMOTE_AGE_NS - 1), 2);
        assert_eq!(promote_if_aged(2, PROMOTE_AGE_NS), 1);
        assert_eq!(promote_if_aged(1, PROMOTE_AGE_NS), 0);
        assert_eq!(promote_if_aged(0, PROMOTE_AGE_NS), 0);
    }

    #[test]
    fn promotion_rewards_one_step_only() {
        assert_eq!(promote_if_aged(2, u64::MAX), 1);
        assert_eq!(promote_if_aged(1, u64::MAX), 0);
        assert_eq!(promote_if_aged(0, u64::MAX), 0);
        assert_eq!(promote_if_aged(2, 0), 2);
    }

    #[test]
    fn promotion_property_age_boundary_sweeps() {
        for age in [
            0,
            1,
            PROMOTE_AGE_NS - 1,
            PROMOTE_AGE_NS,
            PROMOTE_AGE_NS + 1,
            u64::MAX,
        ] {
            for q in [0, 1, 2] {
                let next = promote_if_aged(q, age);
                if age < PROMOTE_AGE_NS || q == 0 {
                    assert_eq!(next, q);
                } else {
                    assert_eq!(next, q - 1);
                }
            }
        }
    }

    #[test]
    fn resolve_prefers_promotion_over_burn() {
        let r = resolve_queue(2, true, true, PROMOTE_AGE_NS);
        let (next, promoted, demoted) = r;
        assert_eq!(next, 1);
        assert!(promoted);
        assert!(!demoted);
        let (next, promoted, demoted) = resolve_queue(1, true, true, 0);
        assert_eq!(next, 2);
        assert!(!promoted);
        assert!(demoted);
        let (next, promoted, demoted) = resolve_queue(1, false, false, 0);
        assert_eq!(next, 1);
        assert!(!promoted);
        assert!(!demoted);
    }

    #[test]
    fn fifo_order_survives_varied_estimates() {
        let mut lane: VecDeque<u64> = VecDeque::new();
        let arrivals = [5_000_000, 100, 1_000_000, 50];
        for &id in &arrivals {
            lane.push_back(id);
        }
        let mut served = Vec::new();
        while let Some(id) = lane.pop_front() {
            served.push(id);
        }
        assert_eq!(served, arrivals);
    }

    #[test]
    fn fifo_property_holds_across_trials() {
        for trial in 0..32 {
            let mut lane: VecDeque<u64> = VecDeque::new();
            let mut arrivals = Vec::new();
            for i in 0..8 {
                let id = trial * 100 + i;
                arrivals.push(id);
                lane.push_back(id);
            }
            for &want in &arrivals {
                assert_eq!(lane.pop_front(), Some(want));
            }
            assert!(lane.is_empty());
        }
    }

    #[test]
    fn fifo_target_ignores_estimate_spread() {
        let (a, _, _) = resolve_queue(1, true, false, 0);
        let (b, _, _) = resolve_queue(1, true, false, 0);
        assert_eq!(a, b);
        assert_eq!(a, 1);
    }

    #[test]
    fn dispatch_prefers_strict_order_when_young() {
        let ages = [10, 20, 30];
        assert_eq!(pick_dispatch([true, true, true], ages), Some(0));
        assert_eq!(pick_dispatch([false, true, true], ages), Some(1));
        assert_eq!(pick_dispatch([false, false, true], ages), Some(2));
        assert_eq!(pick_dispatch([false, false, false], ages), None);
    }

    #[test]
    fn dispatch_aging_override_lifts_old_queue() {
        let ages = [10, 20, PROMOTE_AGE_NS + 10];
        assert_eq!(pick_dispatch([true, true, true], ages), Some(2));
        let ages = [10, PROMOTE_AGE_NS + 5, PROMOTE_AGE_NS];
        assert_eq!(pick_dispatch([true, true, false], ages), Some(1));
    }

    #[test]
    fn starvation_fairness_oldest_aged_wins() {
        let ages = [PROMOTE_AGE_NS + 100, PROMOTE_AGE_NS, 0];
        assert_eq!(pick_dispatch([true, true, false], ages), Some(0));
        let ages = [PROMOTE_AGE_NS, PROMOTE_AGE_NS + 100, 0];
        assert_eq!(pick_dispatch([true, true, false], ages), Some(1));
    }

    #[test]
    fn starvation_fairness_property_aged_beats_young() {
        for young in [0, 1, 100, PROMOTE_AGE_NS - 1] {
            let ages = [young, young, PROMOTE_AGE_NS];
            assert_eq!(pick_dispatch([true, true, true], ages), Some(2));
            let ages = [young, young, young];
            assert_eq!(pick_dispatch([true, true, true], ages), Some(0));
        }
    }

    #[test]
    fn depth_balance_matches_queued_total() {
        let s0 = QueueState::new(0);
        let s1 = QueueState::new(1);
        let s2 = QueueState::new(2);
        let mut states = [s0, s1, s2];
        let mut d = CpuDepths::new(4);
        states[0].add(1_000_000);
        d.inc(0);
        states[1].add(2_000_000);
        d.inc(1);
        let total: u64 = states.iter().map(|s| s.nr).sum();
        assert_eq!(total, d.sum());
        states[0].remove(1_000_000);
        d.dec(0);
        let total: u64 = states.iter().map(|s| s.nr).sum();
        assert_eq!(total, d.sum());
        assert_eq!(d.get(1), 1);
    }

    #[test]
    fn depth_shift_keeps_total_stable() {
        let mut d = CpuDepths::new(4);
        d.inc(0);
        d.inc(1);
        assert_eq!(d.sum(), 2);
        d.shift(0, 2);
        assert_eq!(d.sum(), 2);
        assert_eq!(d.get(0), 0);
        assert_eq!(d.get(2), 1);
    }

    #[test]
    fn depth_out_of_range_is_noop() {
        let mut d = CpuDepths::new(2);
        d.inc(9);
        d.dec(9);
        assert_eq!(d.sum(), 0);
        assert_eq!(d.get(9), 0);
    }

    #[test]
    fn head_age_tracks_busy_start() {
        assert_eq!(head_age(1000, 0), 0);
        assert_eq!(head_age(1000, 400), 600);
        assert_eq!(head_age(100, 400), 0);
    }

    #[test]
    fn tail_age_tracks_recent_arrival() {
        assert_eq!(tail_age(1000, 0), 0);
        assert_eq!(tail_age(1000, 900), 100);
        assert_eq!(tail_age(100, 900), 0);
    }

    #[test]
    fn steal_split_totals_scan_max() {
        assert_eq!(STEAL_SCAN_MAX, 64);
        assert_eq!(DISPATCH_BATCH, 32);
    }

    #[test]
    fn steal_guard_needs_allowed_cpu() {
        assert!(steal_ok(&[true, false], 0));
        assert!(!steal_ok(&[true, false], 1));
        assert!(!steal_ok(&[], 0));
        assert!(!steal_ok(&[true], 5));
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
    fn default_state_matches_first_queue() {
        assert_eq!(QueueState::default(), QueueState::new(0));
    }

    /* Batch continues past one failed queue. */
    #[test]
    fn dispatch_continues_past_failed_queue() {
        let ages = [10, 20, 30];
        let first = pick_dispatch([true, true, true], ages);
        assert_eq!(first, Some(0));
        let next = pick_dispatch([false, true, true], ages);
        assert_eq!(next, Some(1));
        let last = pick_dispatch([false, false, true], ages);
        assert_eq!(last, Some(2));
        let empty = pick_dispatch([false, false, false], ages);
        assert_eq!(empty, None);
    }

    /* Move counters index by source queue. */
    #[test]
    fn counters_index_by_source_queue() {
        assert_eq!(demotion_slot(0), 0);
        assert_eq!(demotion_slot(1), 1);
        assert_eq!(promotion_slot(1), 1);
        assert_eq!(promotion_slot(2), 2);
        let r = resolve_queue(0, true, true, 0);
        assert_eq!(r, (1, false, true));
        assert_eq!(demotion_slot(0), 0);
        let r = resolve_queue(2, true, false, PROMOTE_AGE_NS);
        assert_eq!(r, (1, true, false));
        assert_eq!(promotion_slot(2), 2);
    }

    /* Cleared running view reads as idle. */
    #[test]
    fn cleared_running_view_reads_idle() {
        let mut view = RunningView {
            est: 100,
            pid: 7,
            queue: 1,
        };
        assert!(!view.is_idle());
        view.clear();
        assert_eq!(view, RunningView::idle());
        assert!(view.is_idle());
    }
}
