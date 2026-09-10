/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Group helpers for the flow scheduler.
 * Two groups split CPUs by id halves with extra
 * to hog. Light holds short waits. Hog holds burn.
 * The classifier uses burn with a 32ms window plus
 * wake hits. Demote needs 16ms burn or one burst at
 * 4ms quiet down to 1ms floor during flood. Promote
 * needs 4ms low for 64 wins near 2s or 8 short blocks
 * below 1ms with low burn. Cold tasks join
 * light. The 4x gap keeps flips rare. A per CPU table
 * holds live groups when ready, else halves applies.
 */

/* Count of groups. Fixed at two with no knob. */
#[cfg(test)]
pub const NGROUPS: u64 = 2;
/* Light group id for short waits. */
pub const GROUP_LIGHT: u8 = 0;
/* Hog group id for burn. */
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
/* Quiet case of the adaptive check with depth 0. */
#[cfg(test)]
pub const DEMOTE_BURST_NS: u64 = 4_000_000;
/* Mild burst in nanos at 2ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURST_MID_NS: u64 = 2_000_000;
/* Floor burst in nanos at 1ms for demote. */
#[cfg(test)]
pub const DEMOTE_BURST_FLOOR_NS: u64 = 1_000_000;
/* Window burn in nanos below 4ms for promote. */
#[cfg(test)]
pub const PROMOTE_BURN_NS: u64 = 4_000_000;
/* Low windows needed for one promote near 2s. */
#[cfg(test)]
pub const PROMOTE_WINS: u8 = 64;
/* Extra deadline in nanos at 8ms for pinned hog. */
#[cfg(test)]
pub const PINNED_INFLATE_NS: u64 = 8_000_000;
/* Short block in nanos below 1ms for wake. */
#[cfg(test)]
pub const WAKE_SHORT_NS: u64 = 1_000_000;
/* Short blocks needed for one fast promote. */
#[cfg(test)]
pub const PROMOTE_WAKE_HITS: u16 = 8;
/* Spread in percent above 10pct for hetero. */
pub const HETERO_SPREAD_PCT: u64 = 10;
/* Length of the per CPU group table. */
pub const GROUP_TABLE_LEN: usize = 1024;
/* Perf hint of light at max. */
#[cfg(test)]
pub const PERF_LIGHT: u32 = 1024;
/* Perf hint of hog at max. */
#[cfg(test)]
pub const PERF_HOG: u32 = 1024;

/*
 * Group of one CPU by id halves with extra to hog.
 * Halves is the fallback when the table is not ready.
 * One or no CPUs keeps all light. Otherwise the low
 * half is light and the high half is hog, so an odd
 * count gives the extra CPU to hog.
 */
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
 * Live group of one CPU from table plus halves fallback.
 * Reads the table when ready holds groups, else halves.
 * Bad values fall back to halves with no trap. Mirrors
 * the BPF live helper for snapshot use.
 */
pub fn group_live(cpu: u32, nr: usize, table: &[u8], ready: u8) -> u8 {
    if ready != 0 && (cpu as usize) < nr && (cpu as usize) < table.len() {
        let g = table[cpu as usize];
        if g == GROUP_HOG {
            return GROUP_HOG;
        }
        if g == GROUP_LIGHT {
            return GROUP_LIGHT;
        }
    }
    group_of_cpu(cpu, nr)
}

/*
 * True when values spread past 10pct. Needs max past
 * min by more than 10pct of max, so uniform hosts stay
 * plain. Empty plus single plus zero max stays false.
 */
pub fn spread_exceeds(vals: &[u64]) -> bool {
    if vals.len() < 2 {
        return false;
    }
    let mut min = u64::MAX;
    let mut max = 0u64;
    for &v in vals {
        if v < min {
            min = v;
        }
        if v > max {
            max = v;
        }
    }
    if max == 0 {
        return false;
    }
    (max - min) as u128 * 100 > max as u128 * HETERO_SPREAD_PCT as u128
}

/*
 * True when capacity or frequency spreads past 10pct.
 * Either signal marks hetero, so one-sided skew still
 * seeds the table. Short slices clamp to live CPUs.
 */
pub fn hetero_needed(caps: &[u64], freqs: &[u64]) -> bool {
    spread_exceeds(caps) || spread_exceeds(freqs)
}

/*
 * Assign groups by sorted interleave. Sorts live CPUs
 * by capacity plus frequency plus id, then assigns even
 * slots to light and odd slots to hog. The order spreads
 * fast CPUs across both groups with no knob. Halves is
 * the fallback when the table is not ready. Single CPU
 * keeps all light.
 */
pub fn assign_sorted_interleave(caps: &[u64], freqs: &[u64], nr: usize) -> Vec<u8> {
    let mut idx: Vec<usize> = (0..nr).collect();
    idx.sort_by(|&a, &b| {
        let ca = caps.get(a).copied().unwrap_or(0);
        let cb = caps.get(b).copied().unwrap_or(0);
        cb.cmp(&ca)
            .then_with(|| {
                let fa = freqs.get(a).copied().unwrap_or(0);
                let fb = freqs.get(b).copied().unwrap_or(0);
                fb.cmp(&fa)
            })
            .then_with(|| a.cmp(&b))
    });
    let mut out = vec![GROUP_LIGHT; nr];
    for (pos, cpu) in idx.iter().enumerate() {
        if nr > 1 && pos % 2 == 1 {
            out[*cpu] = GROUP_HOG;
        } else {
            out[*cpu] = GROUP_LIGHT;
        }
    }
    out
}

/*
 * Seed the per CPU group table plus ready flag. Returns
 * interleaved groups with ready set when hetero holds.
 * Returns halves with ready cleared when hosts look
 * uniform, so the BPF side plus snapshot stay on halves.
 */
pub fn seed_groups(caps: &[u64], freqs: &[u64], nr: usize) -> ([u8; GROUP_TABLE_LEN], u8) {
    let mut table = [GROUP_LIGHT; GROUP_TABLE_LEN];
    if nr <= 1 {
        return (table, 0);
    }
    let n = nr.min(GROUP_TABLE_LEN);
    let live_caps: Vec<u64> = (0..n).map(|i| caps.get(i).copied().unwrap_or(0)).collect();
    let live_freqs: Vec<u64> = (0..n).map(|i| freqs.get(i).copied().unwrap_or(0)).collect();
    if !hetero_needed(&live_caps, &live_freqs) {
        return (table, 0);
    }
    let assign = assign_sorted_interleave(&live_caps, &live_freqs, n);
    for (cpu, g) in assign.iter().enumerate() {
        table[cpu] = *g;
    }
    (table, 1)
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
 * Perf hint of one group with single policy at max.
 * Light plus hog use max. Any other value uses max.
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
 * wait for the window end. Quiet case with depth 0.
 */
#[cfg(test)]
pub fn burst_hot(delta: u64) -> bool {
    delta >= DEMOTE_BURST_NS
}

/*
 * Allowance from light depth with flood backpressure.
 * Depth sums queued tasks in light per CPU queues
 * capped at 4. Table is depth 0 to 1 to 4ms, depth 2
 * to 3 to 2ms, depth 4 plus to 1ms. Quiet keeps 4ms
 * so solo bursts still move fast alone. Mild pressure
 * steps down to 2ms so rising flood reacts sooner yet
 * stays clear of one slice chatter. Deep flood pins at
 * 1ms, so per task worst case is one slice during
 * flood. Recomputed per stop with no new task field,
 * so task stays at 48B. Halves matches dispatch view
 * with no table cost in the stop path.
 */
#[cfg(test)]
pub fn burst_allowance(depth: u64) -> u64 {
    if depth >= 4 {
        DEMOTE_BURST_FLOOR_NS
    } else if depth >= 2 {
        DEMOTE_BURST_MID_NS
    } else {
        DEMOTE_BURST_NS
    }
}

/*
 * True when one burst reaches the allowance for
 * demote. The caller passes the allowance for the
 * current light depth, so flood lowers the line to
 * the floor with no extra state.
 */
#[cfg(test)]
pub fn burst_hot_at(delta: u64, allow: u64) -> bool {
    delta >= allow
}

/*
 * Light depth from per CPU queued counts capped at 4.
 * Sums queued tasks over light CPUs in halves order
 * with early stop at 4. Halves matches the BPF depth
 * with no table use. Missing entries count as zero,
 * so short slices stay quiet with no trap.
 */
#[cfg(test)]
pub fn light_depth(queued: &[u64], nr: usize) -> u64 {
    let mut depth = 0u64;
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != GROUP_LIGHT {
            continue;
        }
        depth = depth.saturating_add(queued.get(cpu).copied().unwrap_or(0));
        if depth >= 4 {
            depth = 4;
            break;
        }
    }
    depth
}

/*
 * Hog depth from per CPU queued counts capped at 4.
 * Sums queued tasks over hog CPUs in halves order
 * with early stop at 4. Halves matches the BPF view
 * with no table use. Missing entries count as zero,
 * so short slices stay quiet with no trap. Display
 * only with no burst use.
 */
#[cfg(test)]
pub fn hog_depth(queued: &[u64], nr: usize) -> u64 {
    let mut depth = 0u64;
    for cpu in 0..nr {
        if group_of_cpu(cpu as u32, nr) != GROUP_HOG {
            continue;
        }
        depth = depth.saturating_add(queued.get(cpu).copied().unwrap_or(0));
        if depth >= 4 {
            depth = 4;
            break;
        }
    }
    depth
}

/*
 * Both depths from per CPU queued counts capped at 4.
 * Single pass over halves order with early stop when
 * both hit 4. Mirrors the BPF refresh with one pass
 * and bounded cost. Missing entries count as zero.
 */
#[cfg(test)]
pub fn group_depths(queued: &[u64], nr: usize) -> (u64, u64) {
    let mut light = 0u64;
    let mut hog = 0u64;
    for cpu in 0..nr {
        let n = queued.get(cpu).copied().unwrap_or(0);
        if group_of_cpu(cpu as u32, nr) == GROUP_LIGHT {
            light = light.saturating_add(n);
            if light >= 4 {
                light = 4;
            }
        } else {
            hog = hog.saturating_add(n);
            if hog >= 4 {
                hog = 4;
            }
        }
        if light >= 4 && hog >= 4 {
            break;
        }
    }
    (light, hog)
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
 * True when one block is short below 1ms for wake.
 * Short blocks count toward fast promote with low
 * burn, so brief waits return to light quickly.
 */
#[cfg(test)]
pub fn wake_short(delta: u64) -> bool {
    delta < WAKE_SHORT_NS
}

/*
 * True when wake hits reach 8 for fast promote.
 * Eight qualifying short blocks move hog to light
 * at once with no wait for 64 wins.
 */
#[cfg(test)]
pub fn wake_ready(hits: u16) -> bool {
    (hits as u64) >= PROMOTE_WAKE_HITS as u64
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
 * windows toward 64. Burn holds window burn. Wake
 * hits counts short blocks toward 8 at off 46.
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
    /* Short blocks in a row toward fast promote. */
    pub wake_hits: u16,
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
            wake_hits: 0,
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
 * stopping path with burn plus wake at quiet depth.
 * Quiet wrapper around the depth step with depth 0,
 * so lone bursts keep the 4ms line with no pressure.
 * See the depth step for the full move table.
 */
#[cfg(test)]
pub fn classify_step(st: &mut GroupState, now: u64, delta: u64) -> (bool, bool) {
    classify_step_depth(st, now, delta, 0)
}

/*
 * One classifier step with light depth for tests.
 * Mirrors the BPF stopping path with burn plus wake.
 * Adds the burst to burn, then checks the allowance
 * for the depth, then wake fast promote, then window
 * end. Allowance is 4ms at depth 0 to 1, 2ms at depth
 * 2 to 3, 1ms at depth 4 plus. Eight short blocks
 * below 1ms with low burn move hog to light at once.
 * A 16ms window moves light to hog at the window end.
 * A low window below 4ms moves the streak forward.
 * Middle burn breaks the streak with no move. Middle
 * window keeps wake hits with no reset. A hog needs
 * 64 low wins near 2s or 8 short hits to return to
 * light. Allowance is recomputed per stop with no new
 * task field, so task stays at 48B. Returns true for
 * demote plus true for promote when each move runs.
 */
#[cfg(test)]
pub fn classify_step_depth(st: &mut GroupState, now: u64, delta: u64, depth: u64) -> (bool, bool) {
    if st.group != GROUP_LIGHT && st.group != GROUP_HOG {
        st.group = GROUP_LIGHT;
    }
    st.burn = burn_add(st.burn, delta);
    let mut demoted = false;
    let mut promoted = false;
    if burst_hot_at(delta, burst_allowance(depth)) {
        st.wake_hits = 0;
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
    if wake_short(delta) {
        if st.group == GROUP_HOG {
            if burn_low(st.burn) {
                let next = st.wake_hits.saturating_add(1);
                st.wake_hits = next;
                if wake_ready(next) {
                    st.group = GROUP_LIGHT;
                    st.low_runs = 0;
                    st.wake_hits = 0;
                    st.win_start = now;
                    st.burn = 0;
                    promoted = true;
                    return (demoted, promoted);
                }
            } else {
                st.wake_hits = 0;
            }
        } else {
            st.wake_hits = 0;
        }
    }
    if st.win_start == 0 {
        st.win_start = now;
        return (demoted, promoted);
    }
    if !win_ready(now, st.win_start) {
        return (demoted, promoted);
    }
    if burn_hot(st.burn) {
        st.wake_hits = 0;
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
                st.wake_hits = 0;
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
    st.wake_hits = 0;
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
    let g = if task.group == GROUP_HOG {
        GROUP_HOG
    } else {
        GROUP_LIGHT
    };
    if g != thief_group {
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
 * where skipped counts cross group heads on mask
 * pass. The model documents Tier 0 with both drains
 * plus merged skip. BPF Tier 2 uses park only
 * immediate halves due to verifier jump plus BSS
 * bounds with peer donor only.
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
        let g = if task.group == GROUP_HOG {
            GROUP_HOG
        } else {
            GROUP_LIGHT
        };
        let same = g == thief_group;
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
 * allows the task. Halves is the fallback. Returns
 * none when no allowed CPU lives in the group.
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

/*
 * First allowed CPU in one live group for tests.
 * Scans in id order with the table when ready, else
 * halves. Returns none when no allowed CPU lives in
 * the group.
 */
#[cfg(test)]
pub fn first_in_group_live(
    allowed: &[bool],
    group: u8,
    nr: usize,
    table: &[u8],
    ready: u8,
) -> Option<u32> {
    for cpu in 0..nr {
        if group_live(cpu as u32, nr, table, ready) != group {
            continue;
        }
        if let Some(true) = allowed.get(cpu) {
            return Some(cpu as u32);
        }
    }
    None
}
