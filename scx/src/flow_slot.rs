// SPDX-License-Identifier: GPL-2.0
/*
 * Slot store helpers
 *
 * Holds the sharded FIFO slot helpers that mirror the BPF header so behavior
 * stays the same on both sides of the boundary. Two groups shard 512 slot
 * queues plus 2 overflow tails with FIFO only and no knob. The probe maps a
 * deadline to a bucket, rotation spreads drains, rescue covers the other
 * group, defer counts capped drains with work left, and the kick chain keeps
 * idle owners moving.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/* Tasks moved by one slot trip at most. Fixed at 4 with no knob. */
pub const SLOT_D: u32 = 4;
/* Tasks moved by one dispatch pass at most. Fixed at 32 with no knob. */
pub const SLOT_BUDGET: u32 = 32;
/* Base id of the sharded slot queues. */
#[cfg(test)]
pub const SLOT_BASE: u64 = 0x6000;
/* Slots per group. One group holds 256 buckets. */
#[cfg(test)]
pub const SLOT_PER_GROUP: u64 = 256;
/* Groups sharded by the store. Light and hog only. */
#[cfg(test)]
pub const SLOT_NGROUPS: u64 = 2;
/* Slot queues in both groups. */
#[cfg(test)]
pub const SLOT_N: u64 = 512;
/* Base id of the group overflow tails. */
#[cfg(test)]
pub const SLOT_OVERFLOW_BASE: u64 = 0x6200;
/* Overflow tails, one per group. */
#[cfg(test)]
pub const SLOT_OVERFLOW_N: u64 = 2;
/* Slot width in nanos near 64us. */
#[cfg(test)]
pub const WHEEL_SLOT_NS: u64 = 64_000;
/* Near slots covered by buckets. */
#[cfg(test)]
pub const WHEEL_DIM: u64 = 256;
/* Slots covered by the probe. */
#[cfg(test)]
pub const WHEEL_TOTAL: u64 = 65536;
/* Horizon in nanos near 4.19s in vruntime. */
#[cfg(test)]
pub const WHEEL_HORIZON_NS: u64 = 64_000 * 65536;
/* Low 16 bits cleared by the quantise step. */
#[cfg(test)]
pub const WHEEL_QUANT_LO: u64 = 0xFFFF;
/* Tokens held per CPU for the sleeper boost. */
#[cfg(test)]
pub const TOKEN_MAX: u32 = 255;

/*
 * Deadline with the low 16 bits cleared near 64us
 * down. Clearing moves early only, so order never
 * moves late with at most 65535ns of earliness.
 */
#[cfg(test)]
pub fn qdl_round_down(dl: u64) -> u64 {
    dl & !WHEEL_QUANT_LO
}

/*
 * True when one deadline lands inside the horizon.
 * Overdue counts as inside with slot zero, so late
 * work runs at once. Past the horizon counts as
 * outside with a tail pin.
 */
#[cfg(test)]
pub fn in_horizon(dl: u64, frontier: u64) -> bool {
    crate::flow_edf::time_before(dl, frontier) || dl.wrapping_sub(frontier) < WHEEL_HORIZON_NS
}

/*
 * Probe of one deadline into quantised deadline,
 * slot, error, and overflow. Overdue keeps the
 * rounded deadline with slot zero and no overflow.
 * Inside keeps the rounded deadline with the slot
 * from the rounded distance shifted by 16. Outside
 * pins to the tail with the last slot and overflow
 * set. Error holds deadline minus rounded deadline
 * in 0 to 65535. Mirrors the BPF probe with one
 * horizon test and no double read.
 */
#[cfg(test)]
pub fn wheel_probe(dl: u64, frontier: u64) -> (u64, u64, u64, bool) {
    let err = dl & WHEEL_QUANT_LO;
    let overdue = crate::flow_edf::time_before(dl, frontier);
    let inside = overdue || dl.wrapping_sub(frontier) < WHEEL_HORIZON_NS;
    if !inside {
        let tail = frontier.wrapping_add(WHEEL_HORIZON_NS).wrapping_sub(1);
        return (qdl_round_down(tail), WHEEL_TOTAL - 1, err, true);
    }
    let qdl = qdl_round_down(dl);
    if crate::flow_edf::time_before(qdl, frontier) {
        return (qdl, 0, err, false);
    }
    let mut s = qdl.wrapping_sub(frontier) >> 16;
    if s >= WHEEL_TOTAL {
        s = WHEEL_TOTAL - 1;
    }
    (qdl, s, err, false)
}

/*
 * True when one sleeper may spend one token for a
 * boost. Needs a clamped lag with a live token, an
 * estimate at or below one slice, burn below 4ms,
 * and quant error at or below 64us, so the boost
 * stays bounded with no late move. Mirrors the BPF
 * conjunct in gate order.
 */
#[cfg(test)]
pub fn token_eligible(clamped: bool, tok: u32, est: u64, burn: u32, err: u64) -> bool {
    clamped
        && tok != 0
        && est <= crate::flow_slice::SLICE_NS
        && (burn as u64) < crate::flow_group::PROMOTE_BURN_NS
        && err <= WHEEL_SLOT_NS
}

/*
 * Bucket of one quantised deadline near 64us. Holds
 * the low 8 slot bits, so 256 buckets each cover one
 * near slot with past 16ms resting in overflow.
 */
#[cfg(test)]
pub fn slot_bucket(qdl: u64) -> u64 {
    (qdl >> 16) & 0xFF
}

/*
 * FIFO id of one group bucket with light as default.
 * Holds base plus group times 256 plus bucket, so two
 * groups shard 512 queues with no share. Bad group
 * falls to light with no trap, bucket keeps masked
 * form. FIFO only, never vtime.
 */
#[cfg(test)]
pub fn slot_dsq(group: u8, bucket: u64) -> u64 {
    let g = if group == crate::flow_group::GROUP_HOG {
        1
    } else {
        0
    };
    SLOT_BASE + g * 256 + (bucket & 0xFF)
}

/*
 * FIFO id of one group overflow with light as
 * default. Holds overflow base plus group, so two
 * tails keep arrival order per group with no share.
 * Bad group falls to light with no trap. FIFO only,
 * never vtime.
 */
#[cfg(test)]
pub fn slot_overflow_dsq(group: u8) -> u64 {
    if group == crate::flow_group::GROUP_HOG {
        SLOT_OVERFLOW_BASE + 1
    } else {
        SLOT_OVERFLOW_BASE
    }
}

/*
 * Cap of one slot trip at D under the dispatch
 * budget. Returns the min of budget and 4, so one
 * bucket or overflow moves at most 4 with the shared
 * loop and no K loop. Mirrors the BPF drain cap.
 */
#[cfg(test)]
pub fn slot_cap(budget: u32) -> u32 {
    budget.min(SLOT_D)
}

/*
 * Next bucket of one slot cursor with wrap. Holds
 * cur plus one truncated to u8, so 255 wraps to zero
 * with no branch. Mirrors the BPF rotation step.
 */
#[cfg(test)]
pub fn slot_next(cur: u8) -> u8 {
    cur.wrapping_add(1)
}

/*
 * Bucket ahead of one slot base with wrap. Holds
 * base plus off plus one truncated to u8, so the
 * window stays distinct from own with no branch.
 * Off runs zero to one for two fill buckets at D
 * each. Mirrors the BPF fill step.
 */
#[cfg(test)]
pub fn slot_add(base: u8, off: u32) -> u8 {
    base.wrapping_add(off as u8).wrapping_add(1)
}

/*
 * Four trip queue ids for one dispatch. Trip 0 owns
 * the cursor bucket to budget, trip 1 owns the group
 * overflow at D, trips 2 to 3 own the two fill ahead
 * buckets at D each. Mirrors the BPF k-trip ids with
 * no drain use.
 */
#[cfg(test)]
pub fn trip_dsqs(cur: u8, group: u8) -> [u64; 4] {
    [
        slot_dsq(group, cur as u64),
        slot_overflow_dsq(group),
        slot_dsq(group, slot_add(cur, 0) as u64),
        slot_dsq(group, slot_add(cur, 1) as u64),
    ]
}

/*
 * Rescue queue id for one dispatch. Holds the other
 * group cursor bucket, so every dispatch visits the
 * far group with no empty gate. Mirrors the BPF
 * rescue id with no drain use.
 */
#[cfg(test)]
pub fn rescue_dsq(cur: u8, group: u8) -> u64 {
    let other = if group == crate::flow_group::GROUP_HOG {
        crate::flow_group::GROUP_LIGHT
    } else {
        crate::flow_group::GROUP_HOG
    };
    slot_dsq(other, cur as u64)
}

/*
 * Next cursor after one dispatch. A capped own
 * leftover with work still queued retries the same
 * bucket next dispatch, so hot work drains with no
 * 256 wrap delay. Any other case advances with no
 * pin, so unmovable-only leftover never strands the
 * rotation. Mirrors the BPF capped retain.
 */
#[cfg(test)]
pub fn rotation_step(cur: u8, own_left: bool, own_capped: bool) -> u8 {
    if own_left && own_capped {
        cur
    } else {
        slot_next(cur)
    }
}

/*
 * Drain up to a cap from one FIFO queue for one CPU.
 * The scan visits every queued task in arrival order
 * and moves each live task with the CPU in the mask
 * and with no move failure. Dead, foreign, and failed
 * tasks are skipped with progress, so one bad head
 * never blocks later work. Base carries moved so far
 * with the cap kept whole, so the stop reads one sum
 * like the BPF shared body. Returns the count moved.
 * A zero return means no movable work was present.
 */
#[cfg(test)]
pub fn slot_drain_model(
    queue: &mut std::collections::VecDeque<crate::flow_select::PendingTask>,
    cpu: i32,
    cap: u32,
    base: u32,
) -> u32 {
    let mut moved = 0;
    let mut kept = std::collections::VecDeque::new();
    for task in queue.drain(..) {
        let ok = moved + base < cap
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
 * True when one dispatch counts a defer. Needs moves
 * at or past D with work left in the window or far
 * marks beyond it, so saturated buckets report back
 * pressure with one count. Mirrors the BPF defer
 * gate with no drain use.
 */
#[cfg(test)]
pub fn defer_ok(moved: u32, window_left: bool, far_left: bool) -> bool {
    moved >= SLOT_D && (window_left || far_left)
}

/*
 * Kick step for one dispatch with the sweep count.
 * A window or far leftover with any move kicks at
 * once for progress. A zero-move dispatch with a far
 * mark kicks until the sweep bound at 255, so
 * unmovable-only far work stops polling with no
 * infinite loop. Any move resets the sweep with no
 * extra pass. Returns whether to kick and the next
 * sweep count. Mirrors the BPF safety net.
 */
#[cfg(test)]
pub fn kick_step(moved: u32, window_left: bool, far_left: bool, sweep: u8) -> (bool, u8) {
    if moved > 0 && (window_left || far_left) {
        return (true, 0);
    }
    if moved == 0 && far_left && sweep < 255 {
        return (true, sweep + 1);
    }
    if moved > 0 {
        return (false, 0);
    }
    (false, sweep)
}
