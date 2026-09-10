/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Group helpers for the flow scheduler.
 * Two groups split CPUs by id halves with extra
 * to hog. Light holds short waits. Hog holds burn.
 * The classifier uses burn only with a 32ms window.
 * Demote needs 16ms burn or one 4ms burst. Promote
 * needs 4ms low for 64 wins near 2s. Cold tasks join
 * light. The 4x gap keeps flips rare.
 */

/* Count of groups. Fixed at two with no knob. */
#[cfg(test)]
pub const NGROUPS: u64 = 2;
/* Light group id for short waits. */
#[cfg(test)]
pub const GROUP_LIGHT: u8 = 0;
/* Hog group id for burn. */
#[cfg(test)]
pub const GROUP_HOG: u8 = 1;
/* Park id of the light group. */
#[cfg(test)]
pub const PARK_LIGHT: u64 = 0x5000;
/* Park id of the hog group. */
#[cfg(test)]
pub const PARK_HOG: u64 = 0x5001;
/* Window length in nanos at 32ms. */
#[cfg(test)]
pub const WIN_NS: u64 = 32_000_000;
/* Window burn in nanos at 16ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURN_NS: u64 = 16_000_000;
/* Single burst in nanos at 4ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURST_NS: u64 = 4_000_000;
/* Window burn in nanos below 4ms for promote. */
#[cfg(test)]
pub const PROMOTE_BURN_NS: u64 = 4_000_000;
/* Low windows needed for one promote near 2s. */
#[cfg(test)]
pub const PROMOTE_WINS: u8 = 64;
/* Extra deadline in nanos at 8ms for pinned hog. */
#[cfg(test)]
pub const PINNED_INFLATE_NS: u64 = 8_000_000;
/* Perf hint of light at max. */
#[cfg(test)]
pub const PERF_LIGHT: u32 = 1024;
/* Perf hint of hog at half. */
#[cfg(test)]
pub const PERF_HOG: u32 = 512;

/*
 * Group of one CPU by id halves with extra to hog.
 * One or no CPUs keeps all light. Otherwise the low
 * half is light and the high half is hog, so an odd
 * count gives the extra CPU to hog.
 */
#[cfg(test)]
pub fn group_of_cpu(cpu: u32, nr: usize) -> u8 {
    if nr <= 1 {
        return GROUP_LIGHT;
    }
    if (cpu as usize) < nr / 2 {
        return GROUP_LIGHT;
    }
    GROUP_HOG
}

/*
 * Park id of one group with light as default. Hog
 * uses 0x5001. Any other value uses 0x5000.
 */
#[cfg(test)]
pub fn park_for_group(group: u8) -> u64 {
    if group == GROUP_HOG {
        PARK_HOG
    } else {
        PARK_LIGHT
    }
}

/*
 * Perf hint of one group with light at max. Hog
 * uses half. Any other value uses max.
 */
#[cfg(test)]
pub fn perf_for_group(group: u8) -> u32 {
    if group == GROUP_HOG {
        PERF_HOG
    } else {
        PERF_LIGHT
    }
}

/*
 * True when one window of 32ms has passed. Zero
 * start means no window yet, so the check fails
 * closed and the caller starts a fresh window.
 */
#[cfg(test)]
pub fn win_ready(now: u64, win_start: u64) -> bool {
    if win_start == 0 {
        return false;
    }
    now.wrapping_sub(win_start) >= WIN_NS
}

/*
 * True when window burn reaches 16ms for demote.
 * The 4x gap above the 4ms promote line keeps
 * flips rare with no extra state.
 */
#[cfg(test)]
pub fn burn_hot(burn: u32) -> bool {
    (burn as u64) >= DEMOTE_BURN_NS
}

/*
 * True when one burst reaches 4ms for demote. A
 * single long burst moves to hog at once with no
 * wait for the window end.
 */
#[cfg(test)]
pub fn burst_hot(delta: u64) -> bool {
    delta >= DEMOTE_BURST_NS
}

/*
 * True when window burn stays below 4ms for
 * promote. Only low windows move the streak
 * forward toward 64 wins near 2s.
 */
#[cfg(test)]
pub fn burn_low(burn: u32) -> bool {
    (burn as u64) < PROMOTE_BURN_NS
}

/*
 * Deadline with pinned hog extra of 8ms. The sum
 * wraps with the clock, so order stays correct
 * across wrap with no extra check.
 */
#[cfg(test)]
pub fn inflate_deadline(dl: u64) -> u64 {
    dl.wrapping_add(PINNED_INFLATE_NS)
}

/*
 * Task window state for tests. Mirrors the BPF
 * task fields used by the classifier. Group holds
 * 0 for light and 1 for hog. Low runs counts low
 * windows toward 64. Burn holds window burn.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupState {
    /* Group id. 0 is light. 1 is hog. */
    pub group: u8,
    /* Window start in nanos. Zero means none. */
    pub win_start: u64,
    /* Window burn in nanos. */
    pub burn: u32,
    /* Low windows in a row toward promote. */
    pub low_runs: u8,
}

#[cfg(test)]
impl GroupState {
    /*
     * Cold state with light plus no window. Fresh
     * tasks join light so short waits stay quick.
     */
    pub fn cold() -> Self {
        Self {
            group: GROUP_LIGHT,
            win_start: 0,
            burn: 0,
            low_runs: 0,
        }
    }

    /*
     * True when the group id is hog. Any other
     * value reads as light with no trap.
     */
    pub fn is_hog(&self) -> bool {
        self.group == GROUP_HOG
    }
}

/*
 * Add one burst to window burn with cap. The sum
 * caps at max, so long runs stay hot with no wrap
 * to low and no extra branch in callers.
 */
#[cfg(test)]
pub fn burn_add(burn: u32, delta: u64) -> u32 {
    let sum = (burn as u64).saturating_add(delta);
    if sum > u32::MAX as u64 {
        u32::MAX
    } else {
        sum as u32
    }
}

/*
 * One classifier step for tests. Mirrors the BPF
 * stopping path with burn only. Adds the burst to
 * burn, then checks burst demote, then window end.
 * A 4ms burst moves light to hog at once. A 16ms
 * window moves light to hog at the window end. A
 * low window below 4ms moves the streak forward.
 * Middle burn breaks the streak with no move. A
 * hog needs 64 low wins near 2s to return to
 * light. Returns true for demote plus true for
 * promote when each move runs.
 */
#[cfg(test)]
pub fn classify_step(st: &mut GroupState, now: u64, delta: u64) -> (bool, bool) {
    if st.group != GROUP_LIGHT && st.group != GROUP_HOG {
        st.group = GROUP_LIGHT;
    }
    st.burn = burn_add(st.burn, delta);
    let mut demoted = false;
    let mut promoted = false;
    if burst_hot(delta) {
        if st.group == GROUP_LIGHT {
            st.group = GROUP_HOG;
            st.low_runs = 0;
            st.win_start = now;
            st.burn = 0;
            demoted = true;
            return (demoted, promoted);
        }
        st.low_runs = 0;
        return (demoted, promoted);
    }
    if st.win_start == 0 {
        st.win_start = now;
        return (demoted, promoted);
    }
    if !win_ready(now, st.win_start) {
        return (demoted, promoted);
    }
    if burn_hot(st.burn) {
        if st.group == GROUP_LIGHT {
            st.group = GROUP_HOG;
            st.low_runs = 0;
            demoted = true;
        } else {
            st.low_runs = 0;
        }
        st.win_start = now;
        st.burn = 0;
        return (demoted, promoted);
    }
    if burn_low(st.burn) {
        if st.group == GROUP_HOG {
            let next = st.low_runs.saturating_add(1);
            st.low_runs = next;
            if next >= PROMOTE_WINS {
                st.group = GROUP_LIGHT;
                st.low_runs = 0;
                promoted = true;
            }
        } else if st.low_runs < PROMOTE_WINS {
            st.low_runs = st.low_runs.saturating_add(1);
        }
        st.win_start = now;
        st.burn = 0;
        return (demoted, promoted);
    }
    st.low_runs = 0;
    st.win_start = now;
    st.burn = 0;
    (demoted, promoted)
}

/*
 * Group task for dispatch models. The mask names
 * allowed CPUs. The live flag marks a trusted pid
 * lookup. The fail flag models a failed move. Group
 * holds 0 for light and 1 for hog.
 */
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupTask {
    /* Allowed CPUs. Index is the CPU. */
    pub allowed: Vec<bool>,
    /* False models a NULL pid lookup. */
    pub live: bool,
    /* True models a failed queue move. */
    pub fail: bool,
    /* Group id. 0 is light. 1 is hog. */
    pub group: u8,
}

/*
 * True when one group task may move to the thief.
 * Needs a live task with no move failure plus the
 * CPU in the mask plus the same group. Pinned
 * single tasks with one allowed CPU may cross with
 * an inflated deadline, so the caller checks that
 * path before this strict check. Exiting tasks use
 * the same rule with no extra path.
 */
#[cfg(test)]
pub fn group_task_ok(thief: i32, thief_group: u8, task: &GroupTask) -> bool {
    if !task.live || task.fail {
        return false;
    }
    if task.group != thief_group {
        return false;
    }
    crate::flow_select::may_run_on(thief, &task.allowed)
}

/*
 * Drain up to budget group tasks for one CPU. The
 * scan keeps order and moves each task that passes
 * the strict group check. Dead, foreign, failed,
 * and cross group heads stay, so one head never
 * blocks later work. Returns moved plus skipped
 * where skipped counts cross group heads.
 */
#[cfg(test)]
pub fn group_drain_model(
    queue: &mut std::collections::VecDeque<GroupTask>,
    cpu: i32,
    thief_group: u8,
    budget: u32,
) -> (u32, u32) {
    let mut moved = 0;
    let mut skipped = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let same = task.group == thief_group;
        let ok = moved < budget
            && task.live
            && !task.fail
            && same
            && crate::flow_select::may_run_on(cpu, &task.allowed);
        if ok {
            moved += 1;
        } else {
            if task.live
                && !task.fail
                && !same
                && crate::flow_select::may_run_on(cpu, &task.allowed)
            {
                skipped += 1;
            }
            kept.push_back(task);
        }
    }
    *queue = kept;
    (moved, skipped)
}

/*
 * First allowed CPU in one group for tests. Scans
 * in id order and returns the first live CPU that
 * allows the task. Returns none when no allowed
 * CPU lives in the group.
 */
#[cfg(test)]
pub fn first_in_group(allowed: &[bool], group: u8, nr: usize) -> Option<u32> {
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != group {
            continue;
        }
        if let Some(true) = allowed.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}
