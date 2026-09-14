// SPDX-License-Identifier: GPL-2.0
/*
 * Slot store helpers
 *
 * Holds the per CPU FIFO slot helpers that mirror the BPF header so behavior
 * stays the same on both sides of the boundary. Each CPU holds two queues
 * plus 2 overflow tails with FIFO only and no knob. The probe maps a
 * deadline to near or overflow, pinned tasks rest in overflow, dispatch
 * drains own plus overflow plus peer steal, defer counts capped drains with
 * work left, and the kick chain keeps idle owners moving.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/* Tasks moved by one slot trip at most. Fixed at 4 with no knob. */
pub const SLOT_D: u32 = 4;
/* Tasks moved by one dispatch pass at most. Fixed at 32 with no knob. */
pub const SLOT_BUDGET: u32 = 32;
/* Own bucket cap at budget minus one. Fixed at 31 with no knob. */
#[cfg(test)]
pub const SLOT_OWN_CAP: u32 = 31;
/* Consecutive retains before force advance. Fixed at 3. */
#[cfg(test)]
pub const RETAIN_MAX: u8 = 3;
/* Zero-move sweep bound. Fixed at 256 with no knob. */
#[cfg(test)]
pub const SWEEP_MAX: u16 = 256;
/* Base id of the sharded slot queues. */
#[cfg(test)]
pub const SLOT_BASE: u64 = 0x6000;
/* Slots per group. One group holds 256 buckets. Kept for old drain compat. */
#[cfg(test)]
pub const SLOT_PER_GROUP: u64 = 256;
/* Groups sharded by the store. Light and hog only. Kept for compat. */
#[cfg(test)]
pub const SLOT_NGROUPS: u64 = 2;
/* Slot queues in both groups. Kept for old init compat. */
#[cfg(test)]
pub const SLOT_N: u64 = 512;
/* Base id of the group overflow tails. Relocated to 0x6800 with no share. */
#[cfg(test)]
pub const SLOT_OVERFLOW_BASE: u64 = 0x6800;
/* Overflow tails, one per group. */
#[cfg(test)]
pub const SLOT_OVERFLOW_N: u64 = 2;
/* Queues per CPU. One light plus one hog with no share. */
#[cfg(test)]
pub const SLOT_PER_CPU: u64 = 2;
/* Max DSQs at 1024 CPUs. Holds 2 times 1024 plus 2 with no share. */
#[cfg(test)]
pub const SLOT_MAX_DSQS: u64 = 2050;
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
 * FIFO id of one CPU group with light as default.
 * Holds base plus cpu times two plus group, so two
 * per CPU keep light and hog apart with no share.
 * Bad group falls to light with no trap. FIFO only,
 * never vtime. Mirrors the BPF per CPU helper.
 */
#[cfg(test)]
pub fn slot_cpu_dsq(cpu: u32, group: u8) -> u64 {
    let g = if group == crate::flow_group::GROUP_HOG {
        1
    } else {
        0
    };
    SLOT_BASE + cpu as u64 * 2 + g
}

/*
 * Count of DSQs for one host with per CPU plus
 * overflow. Holds two times nr plus two, so eight
 * CPUs need eighteen queues with 2050 max at 1024
 * CPUs and no share. Mirrors the BPF count helper.
 */
#[cfg(test)]
pub fn slot_nr_dsqs(nr: u64) -> u64 {
    nr * 2 + 2
}

/*
 * Least donor depth for one steal with idle empty
 * fast path. Holds one when idle empty, else two,
 * so idle owners collect the last task with no
 * strand. Mirrors the BPF steal need helper.
 */
#[cfg(test)]
pub fn steal_need(idle_empty: bool) -> u64 {
    if idle_empty {
        1
    } else {
        crate::flow_select::STEAL_MIN_DEPTH
    }
}

/*
 * DSQ id for one per CPU insert with pinned
 * overflow. Pinned tasks rest in the group overflow
 * tail with no per CPU use, so every owner dispatch
 * visits them in the window with mask wins and no
 * rotation need. Migratable tasks keep the per CPU
 * queue or the horizon tail. Mirrors the BPF per
 * CPU branch with the same group fallback.
 */
#[cfg(test)]
pub fn insert_cpu_dsq(cpu: u32, group: u8, slot: u64, pinned: bool) -> u64 {
    if pinned {
        return slot_overflow_dsq(group);
    }
    if slot >= WHEEL_DIM {
        return slot_overflow_dsq(group);
    }
    slot_cpu_dsq(cpu, group)
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
 * Own bucket cap at budget minus one. Holds 31 with
 * budget 32, so one slot stays for overflow, fill,
 * other overflow, and rescue with no strand on a hot
 * own bucket. Zero stays zero. Mirrors the BPF own
 * cap reserve.
 */
#[cfg(test)]
pub fn slot_own_cap(budget: u32) -> u32 {
    budget.saturating_sub(1)
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
 * Five trip queue ids for one dispatch. Trip 0 owns
 * the cursor bucket at budget minus one, trip 1 owns
 * the group overflow at D, trips 2 to 3 own the two
 * fill ahead buckets at D each, trip 4 owns the other
 * group overflow at D. Mirrors the BPF k-trip ids with
 * no drain use. Trip 4 keeps a hog far tail drainable
 * on an all-light host with mask wins.
 */
#[cfg(test)]
pub fn trip_dsqs(cur: u8, group: u8) -> [u64; 5] {
    let other = if group == crate::flow_group::GROUP_HOG {
        crate::flow_group::GROUP_LIGHT
    } else {
        crate::flow_group::GROUP_HOG
    };
    [
        slot_dsq(group, cur as u64),
        slot_overflow_dsq(group),
        slot_dsq(group, slot_add(cur, 0) as u64),
        slot_dsq(group, slot_add(cur, 1) as u64),
        slot_overflow_dsq(other),
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
 * DSQ id for one insert with pinned overflow. Pinned
 * tasks rest in the group overflow tail with no bucket
 * use, so every owner dispatch visits them in the window
 * with mask wins and no rotation or far need. Migratable
 * tasks keep the probed bucket or horizon tail. Mirrors
 * the BPF pinned branch with the same group fallback.
 */
#[cfg(test)]
pub fn insert_dsq(group: u8, bucket: u64, slot: u64, pinned: bool) -> u64 {
    if pinned {
        return slot_overflow_dsq(group);
    }
    if slot >= WHEEL_DIM {
        return slot_overflow_dsq(group);
    }
    slot_dsq(group, bucket)
}

/*
 * Next cursor after one dispatch. A capped own
 * leftover with work still queued retries the same
 * bucket next dispatch, so hot work drains with no
 * 1024 wrap delay. Any other case advances with no
 * pin, so unmovable-only leftover never strands the
 * rotation. Single step form with retains at zero.
 * See the bounded step for the BPF mirror with the
 * force advance after three retains.
 */
#[cfg(test)]
pub fn rotation_step(cur: u8, own_left: bool, own_capped: bool) -> u8 {
    rotation_step_bounded(cur, own_left, own_capped, 0).0
}

/*
 * Bounded retain step with the retain count. Holds
 * the bucket while capped leftover stays queued and
 * retains stay below three, else advances with no pin
 * and resets the count. Force advance past three keeps
 * hot buckets bounded, so every bucket gets a visit
 * within 1024 dispatches. Mirrors the BPF retain with
 * the same bound and refill to zero on advance.
 */
#[cfg(test)]
pub fn rotation_step_bounded(cur: u8, own_left: bool, own_capped: bool, retains: u8) -> (u8, u8) {
    if own_left && own_capped && retains < RETAIN_MAX {
        (cur, retains + 1)
    } else {
        (slot_next(cur), 0)
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
 * at or past D with work left in the window, so a
 * saturated bucket reports back pressure with one
 * count. Far marks feed stats only and never gate a
 * defer, so the kick net fires on true window work
 * with no storm. Mirrors the BPF defer gate with no
 * drain use. The far flag stays for call compat and
 * is ignored.
 */
#[cfg(test)]
pub fn defer_ok(moved: u32, window_left: bool, _far_left: bool) -> bool {
    moved >= SLOT_D && window_left
}

/*
 * Kick step for one dispatch with the sweep count.
 * A far jump with any move kicks at once via the far
 * path, so late work still chains with no window. A
 * zero-move dispatch with window work kicks until the
 * sweep bound at 256, so unmovable-only window work
 * stops polling with no infinite loop. Any move resets
 * the sweep with no extra pass. Moves with window but
 * no far ride the next natural dispatch with no kick,
 * since the loop already visited every task and the CPU
 * runs the moved work before the next pass. Far marks
 * feed the far path only, so steady state stays quiet
 * with kicks per dispatch well below one. Returns
 * whether to kick and the next sweep count. Mirrors the
 * BPF safety net with no window progress kick. The far
 * flag stays for call compat and is ignored here, far
 * kicks live in kick_far_ok only.
 */
#[cfg(test)]
pub fn kick_step(moved: u32, window_left: bool, _far_left: bool, sweep: u16) -> (bool, u16) {
    if moved == 0 && window_left && sweep < SWEEP_MAX {
        return (true, sweep + 1);
    }
    if moved > 0 {
        return (false, 0);
    }
    (false, sweep)
}

/*
 * Next own bucket ahead with queued work when idle.
 * Scans 256 ahead from cur inclusive with exact
 * truth and no mark use, so stale marks add no
 * force. Returns the first bucket ahead with work,
 * else none, so the caller jumps only on far work.
 * Bound 256 covers every bucket in one pass, so
 * boot 15 and 61 drain within 3 hops with no walk
 * and late 61 still jumps on the next idle pass.
 * Mirrors the BPF far scan with the same order.
 */
#[cfg(test)]
pub fn far_next(cur: u8, occupied: &[bool; 256]) -> Option<u8> {
    for off in 0..256u32 {
        if off >= 256 {
            break;
        }
        let b = cur.wrapping_add(off as u8);
        if occupied[b as usize] {
            return Some(b);
        }
    }
    None
}

/*
 * True when one far progress kick fires. Needs any
 * move with an idle far jump, so late 61 still chains
 * after 15 drains with no window. Window alone never
 * kicks with moves, it rides the next natural dispatch,
 * so the kick net fires on far jumps only with no
 * storm. Mirrors the BPF far kick with the same gate.
 * The window flag stays for call compat and is ignored.
 */
#[cfg(test)]
pub fn kick_far_ok(moved: u32, _window_left: bool, far_jump: bool) -> bool {
    moved > 0 && far_jump
}

/* Hints kept per group for the last near insert. */
#[cfg(test)]
pub const SLOT_HINT_N: u64 = 2;

/*
 * True when one hint bucket holds work. Hit jumps
 * with no full scan, miss falls back to the window
 * gate plus the full scan with no hide, so a stale
 * hint costs one read with no stall. Mirrors the
 * BPF hint fast path with the same check.
 */
#[cfg(test)]
pub fn hint_hit(hint: u8, occupied: &[bool; 256]) -> bool {
    occupied[hint as usize]
}

/*
 * True when one window holds work for the far gate.
 * Window holds own overflow plus two fill ahead plus
 * rescue plus other overflow, so trips drain it with
 * no far need and far work waits at most two turns.
 * True skips the 256 scan, false runs the full scan
 * with no hide. Mirrors the BPF window gate.
 */
#[cfg(test)]
pub fn window_has_work(own_over: bool, f0: bool, f1: bool, rescue: bool, other_over: bool) -> bool {
    own_over || f0 || f1 || rescue || other_over
}
