/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Placement and steal helpers for the flow scheduler.
 * The functions mirror the BPF side so behavior stays
 * the same on both sides of the boundary.
 */

/* Unknown LLC id. Marks an empty table entry. */
pub const LLC_UNKNOWN: u32 = 0xFFFF_FFFF;
/* Compile time CPU bound. Mirrors the BPF header. */
#[cfg(test)]
pub const MAX_CPUS: u32 = 1024;
/* Bound of peers visited by one steal scan. */
#[cfg(test)]
pub const STEAL_BOUND: usize = 8;
/* Least donor depth that allows a steal. */
#[cfg(test)]
pub const STEAL_MIN_DEPTH: u64 = 2;

/*
 * Queue id of one CPU. Returns none for an out of
 * range id, so callers fall back to the park queue.
 */
#[cfg(test)]
pub fn dsq_for_cpu(cpu: u32, max: usize) -> Option<u64> {
    if (cpu as usize) >= max {
        return None;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return None;
    }
    Some(crate::flow_edf::DSQ_BASE + cpu as u64)
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
    /* Negative check stays explicit with no behavior */
    /* change, since the table lookup already fails */
    /* closed for out of range ids. */
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
 * mask. Mirrors the BPF live plus range plus mask
 * check. A negative CPU fails closed. A CPU at or
 * past 1024 fails closed as test only bound. Live
 * CPUs are modelled by the mask length in tests, so
 * callers keep the mask sized to live CPUs. A missing
 * entry fails closed.
 */
#[cfg(test)]
pub fn may_run_on(cpu: i32, allowed: &[bool]) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    if let Some(&ok) = allowed.get(cpu as usize) {
        return ok;
    }
    false
}

/*
 * Check that a CPU is live for tests. Needs a CPU at
 * zero or past zero and below live count and below
 * 1024, so out of range CPUs fail closed with no
 * queue use. Mirrors the BPF live check with no mask.
 */
#[cfg(test)]
pub fn cpu_live(cpu: i32, nr_cpus: usize) -> bool {
    if cpu < 0 {
        return false;
    }
    if (cpu as u64) >= MAX_CPUS as u64 {
        return false;
    }
    (cpu as usize) < nr_cpus
}

/*
 * Check that a CPU is live and allowed for tests.
 * Needs a live CPU with the mask set, so dead CPUs
 * and foreign CPUs fail closed at once. Mirrors the
 * BPF live plus range plus mask check in one call.
 */
#[cfg(test)]
pub fn may_run_on_live(cpu: i32, allowed: &[bool], nr_cpus: usize) -> bool {
    if !cpu_live(cpu, nr_cpus) {
        return false;
    }
    may_run_on(cpu, allowed)
}

/*
 * True when the prior CPU may be reused at once.
 * Needs an allowed prior CPU that is idle, so busy
 * priors never preempt and only quiet reuse counts.
 * The negative check stays explicit with no behavior
 * change, since the mask check already fails closed.
 */
#[cfg(test)]
pub fn sticky_prior_ok(prev: i32, allowed: &[bool], idle: &[bool]) -> bool {
    if !may_run_on(prev, allowed) {
        return false;
    }
    if prev < 0 {
        return false;
    }
    matches!(idle.get(prev as usize), Some(true))
}

/*
 * True when a batch may stay on the prior CPU. Needs
 * an allowed prior with a known deadline within the
 * batch window of the prior frontier. Fresh tasks
 * with no deadline skip batch at once. The window
 * is tiny past the mean floor, so a batch keeps
 * warmth with no fair loss. The negative check stays
 * explicit with no behavior change, since the mask
 * check already fails closed.
 */
#[cfg(test)]
pub fn sticky_batch_ok(prev: i32, allowed: &[bool], deadline: u64, frontier: u64) -> bool {
    if deadline == 0 {
        return false;
    }
    if !may_run_on(prev, allowed) {
        return false;
    }
    if prev < 0 {
        return false;
    }
    crate::flow_edf::batch_within(deadline, frontier)
}

/*
 * True when a donor queue may lose one task. Needs at
 * least two queued tasks, so thin donors keep their
 * last task for the owner. The test form assumes the
 * sticky gate is set. The gated form mirrors the BPF
 * guard with sticky only, so the IEDF flag keeps no
 * guard after the 4.2.0 revert.
 */
#[cfg(test)]
pub fn donor_ok(depth: u64) -> bool {
    depth >= STEAL_MIN_DEPTH
}

/*
 * True when a donor may lose one task with gates.
 * Needs the sticky gate plus depth at two or more, so
 * thin donors keep their last task for the owner. The
 * IEDF flag keeps no guard in BPF after the 4.2.0
 * revert for the 1M verifier limit, so it stays ignored
 * here to keep callers stable.
 */
#[cfg(test)]
pub fn donor_ok_gated(depth: u64, sticky: bool, iedf: bool) -> bool {
    let _ = iedf;
    if !sticky {
        return true;
    }
    donor_ok(depth)
}

/*
 * Full select model with sticky prior plus batch reuse.
 * Mirrors the BPF order of idle prior, batch prior,
 * LLC idle, any idle, previous, current and first.
 * Batch needs a known deadline near the frontier with
 * the gate set, so fresh tasks skip batch at once.
 * Returns none for park use when no CPU allows.
 */
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn select_sticky_model(
    prev: i32,
    cur: i32,
    allowed: &[bool],
    idle: &[bool],
    llc_ids: &[u32],
    full: &[bool],
    nr: u64,
    deadline: u64,
    frontier: u64,
    iedf: bool,
) -> (Option<u32>, bool) {
    if sticky_prior_ok(prev, allowed, idle) {
        return (Some(prev as u32), true);
    }
    if iedf && sticky_batch_ok(prev, allowed, deadline, frontier) {
        return (Some(prev as u32), false);
    }
    (
        select_cpu_model(prev, cur, allowed, idle, llc_ids, full, nr),
        false,
    )
}

/*
 * True when a kick may run. Needs a queue that held
 * at most one task after insert, so first arrivals
 * wake idle targets while queued work stays quiet.
 */
#[cfg(test)]
pub fn may_kick(queue_len: u64) -> bool {
    queue_len <= 1
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
 * callers keep plain per-CPU behavior.
 */
#[cfg(test)]
pub fn topology_has_smt(smt: &[bool]) -> bool {
    smt.iter().any(|v| *v)
}

/*
 * True when a sibling may be used. Needs sibling
 * hardware and an allowed peer, else plain per-CPU
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
 * True when one peer task may move to the thief.
 * Mirrors the BPF peer drain task check. A live and
 * allowed task with no move failure may move. Exiting
 * tasks may move when allowed, so they run to exit.
 * A dead, foreign, or failed task stays, so the scan
 * moves past it with progress. An empty queue yields
 * false.
 */
#[cfg(test)]
pub fn peer_head_ok(thief: i32, head: Option<&PendingTask>) -> bool {
    if let Some(t) = head {
        t.live && !t.fail && may_run_on(thief, &t.allowed)
    } else {
        false
    }
}

/*
 * Steal up to budget tasks from peers for an idle CPU.
 * The scan visits at most bound peers starting after
 * the cursor with wrap. Only idle callers steal. Each
 * peer is scanned in order past dead, foreign, and
 * failed heads, so movable work behind a bad head is
 * rescued. Exiting tasks move when allowed, so they
 * run to exit on the owner or on a thief. The cursor
 * advances by the peers visited. Returns the count
 * moved and the new cursor.
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
            let mut pos = None;
            for (idx, task) in q.iter().enumerate() {
                if peer_head_ok(thief as i32, Some(task)) {
                    pos = Some(idx);
                    break;
                }
            }
            if let Some(idx) = pos {
                q.remove(idx);
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
 * True when a CPU may steal after draining own and
 * park. An idle CPU with no moved work steals past
 * unmovable leftovers, so only unmovable work never
 * blocks a steal. A busy CPU with moved work steals
 * only when both queues are empty.
 */
#[cfg(test)]
pub fn may_steal(own_left: u64, park_left: u64, moved: u32) -> bool {
    if moved == 0 {
        return true;
    }
    own_left == 0 && park_left == 0
}
