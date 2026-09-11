/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Delay plus granule plus rate helpers for the flow
 * scheduler. The functions mirror the BPF header so
 * behavior stays the same on both sides of the
 * boundary. Units stay in 32us with no space with
 * integer math only and no float use.
 */

/* One delay unit in nanos at 32us. */
#[cfg(test)]
pub const DELAY_UNIT_NS: u64 = 32_000;
/* Max delay in units at 250 near 8ms. */
#[cfg(test)]
pub const DELAY_MAX: u64 = 250;
/* Armed delay in units at 16 near 512us. */
pub const DELAY_ARM: u64 = 16;
/* Stand delay in units at 8 near 256us. */
pub const DELAY_STAND: u64 = 8;
/* Window length in updates at 8. */
#[cfg(test)]
pub const DELAY_WIN_LEN: u64 = 8;
/* Granule floor in nanos at 64us. */
#[cfg(test)]
pub const GRANULE_FLOOR_NS: u64 = 64_000;
/* Rate bit in the cursor top bit. */
#[cfg(test)]
pub const CURSOR_RATE_BIT: u32 = 0x8000_0000;
/* Stand bit in cursor bit10 with peer in 0 to 9. */
pub const CURSOR_STAND_BIT: u32 = 0x0000_0400;
/* Storm bit in cursor bit11 for one extra kick. */
#[cfg(test)]
pub const CURSOR_STORM_BIT: u32 = 0x0000_0800;
/* Cursor peer mask without rate plus stand plus storm. */
#[cfg(test)]
pub const CURSOR_MASK: u32 = 0x7fff_f3ff;
/* Storm delay line at 62 for two queued. */
#[cfg(test)]
pub const STORM_DELAY_WIN: u64 = 62;

/*
 * Sample in 32us units from queued count. One queued
 * is 31 units, half slice arms at 16. Cap is 250 at
 * 8ms with integer math only.
 */
#[cfg(test)]
pub fn delay_from_queued(queued: u64) -> u8 {
    if queued >= 8 {
        return 250;
    }
    let v = (queued * 125) / 4;
    if v > 250 { 250 } else { v as u8 }
}

/*
 * Decay one step by 1/8 with integer math only.
 * Holds peaks across windows for hysteresis.
 */
#[cfg(test)]
pub fn delay_decay(old: u8) -> u8 {
    let o = old as u32;
    (o - o / 8) as u8
}

/*
 * True when the delay window is armed at 16. 16 is
 * 512us in 32us units near half slice.
 */
pub fn delay_armed(win: u8) -> bool {
    (win as u64) >= DELAY_ARM
}

/*
 * True when delay is armed with hysteresis. Arms
 * at 16, then holds while win stays at or past
 * stand at 8 with the latched flag. Persists
 * across idle with no decay sans traffic. Delay
 * shows stale when idle, see dashboard. Next
 * running decays at 1/8 per window.
 */
pub fn delay_armed_latched(win: u8, held: bool) -> bool {
    if delay_armed(win) {
        return true;
    }
    if held && (win as u64) >= DELAY_STAND {
        return true;
    }
    false
}

/*
 * True when the stand latch is held in bit10.
 * Bits 0 to 9 hold peer, bit10 holds stand, bit11
 * holds storm, top holds rate, so rotation masks all
 * three flags.
 */
pub fn stand_held(cursor: u32) -> bool {
    (cursor & CURSOR_STAND_BIT) != 0
}

/*
 * True when the storm slot is held in bit11.
 * Storm allows one extra kick per slice, so max is
 * two per slice per CPU with rate plus storm.
 */
#[cfg(test)]
pub fn storm_held(cursor: u32) -> bool {
    (cursor & CURSOR_STORM_BIT) != 0
}

/*
 * Max of two delay samples with cap at 250.
 * Win plus cur are dual writer max, count is
 * running only. Lost race drops at most one
 * sample with no count skew, decay intact.
 */
#[cfg(test)]
pub fn delay_max(a: u8, b: u8) -> u8 {
    let m = if a > b { a } else { b };
    if (m as u64) > DELAY_MAX { 250 } else { m }
}

/*
 * Close one window of 8 with decay plus max. Decays
 * the old max by 1/8 then keeps the max with the
 * current window max with cap at 250.
 */
#[cfg(test)]
pub fn delay_close(win: u8, cur: u8) -> u8 {
    let o = win as u32;
    let d = o - o / 8;
    let m = if d > cur as u32 { d } else { cur as u32 };
    if m > 250 { 250 } else { m as u8 }
}

/*
 * Push one sample through the window. Tracks the max
 * in the current window, then closes each 8 updates
 * with decay. Fast arm on a high sample, slow fall
 * by 1/8 per window for hysteresis. Integer only.
 * Running owns this path. Enqueue uses stamp only
 * with no count, so 8 means 8 runnings with no
 * double count. Persists across idle with no decay.
 */
#[cfg(test)]
pub fn delay_push(win: u8, cur: u8, cnt: u16, sample: u8) -> (u8, u8, u16) {
    let sample = if (sample as u64) > DELAY_MAX {
        250
    } else {
        sample
    };
    let nwin = delay_max(win, sample);
    let ncur = delay_max(cur, sample);
    let ncnt = cnt.wrapping_add(1);
    if (ncnt as u64) >= DELAY_WIN_LEN {
        let closed = delay_close(nwin, ncur);
        return (closed, 0, 0);
    }
    (nwin, ncur, ncnt)
}

/*
 * Granule in nanos quarter slice with 64us floor.
 * Base is slice times 1024 over weight quartered
 * with floor at 64us, so heavy keeps short and
 * light keeps long with no trap on zero input.
 * Short heavy is stricter, tempering deadline
 * lead. Net easiness is deadline math, not gran.
 * Quarter bounds theft near 25% of a slice.
 * Floor covers IPI plus switch cost, no thrash.
 * Uses woken weight only, see deserved.
 */
#[cfg(test)]
pub fn granule_for_weight(weight: u32, slice: u64) -> u64 {
    if weight == 0 {
        let gran = slice / 4;
        if gran < GRANULE_FLOOR_NS {
            return GRANULE_FLOOR_NS;
        }
        return gran;
    }
    if slice == 0 {
        return GRANULE_FLOOR_NS;
    }
    let base = ((slice as u128 * 1024) / weight as u128) as u64;
    let gran = base / 4;
    if gran < GRANULE_FLOOR_NS {
        return GRANULE_FLOOR_NS;
    }
    gran
}

/*
 * Cursor peer without rate plus stand plus storm.
 */
#[cfg(test)]
pub fn cursor_val(cursor: u32) -> u32 {
    cursor & CURSOR_MASK
}

/*
 * Store peer plus keep rate plus stand plus storm.
 * Masks the peer, so rotation keeps order with no
 * extra state. Dispatch CAS keeps fresh flags, model
 * is sequential form, timing only.
 */
#[cfg(test)]
pub fn cursor_store(peer: u32, old: u32) -> u32 {
    (peer & CURSOR_MASK) | (old & (CURSOR_RATE_BIT | CURSOR_STAND_BIT | CURSOR_STORM_BIT))
}

/*
 * Set the stand latch plus keep peer plus rate plus
 * storm.
 */
#[cfg(test)]
pub fn stand_set(cursor: u32) -> u32 {
    cursor | CURSOR_STAND_BIT
}

/*
 * Clear the stand latch plus keep peer plus rate plus
 * storm.
 */
#[cfg(test)]
pub fn stand_clear(cursor: u32) -> u32 {
    cursor & !CURSOR_STAND_BIT
}

/*
 * Set the storm slot plus keep peer plus rate plus
 * stand.
 */
#[cfg(test)]
pub fn storm_set(cursor: u32) -> u32 {
    cursor | CURSOR_STORM_BIT
}

/*
 * Clear the storm slot plus keep peer plus rate plus
 * stand.
 */
#[cfg(test)]
pub fn storm_clear(cursor: u32) -> u32 {
    cursor & !CURSOR_STORM_BIT
}

/*
 * True when the rate bit is clear for one kick.
 * Read only, so claim below does the atomic set.
 * Storm holds the second kick, see storm claim.
 */
#[cfg(test)]
pub fn rate_clear(cursor: u32) -> bool {
    (cursor & CURSOR_RATE_BIT) == 0
}

/*
 * Set the rate bit after one kick.
 */
#[cfg(test)]
pub fn rate_set(cursor: u32) -> u32 {
    cursor | CURSOR_RATE_BIT
}

/*
 * Atomically set rate and report prior clear. One
 * winner per slice with no check then set. Models
 * the BPF fetch_or claim in enqueue. Storm adds one
 * extra, so max is two per slice.
 */
#[cfg(test)]
pub fn rate_claim(cursor: &mut u32) -> bool {
    let old = *cursor;
    *cursor |= CURSOR_RATE_BIT;
    rate_clear(old)
}

/*
 * True when the storm slot is clear for a second kick.
 * Read only, so claim below does the atomic set.
 */
#[cfg(test)]
pub fn storm_clear_for_kick(cursor: u32) -> bool {
    (cursor & CURSOR_STORM_BIT) == 0
}

/*
 * Atomically set storm and report prior clear. One
 * extra winner per slice with no check then set.
 * Max is two per slice per CPU with rate plus storm.
 */
#[cfg(test)]
pub fn storm_claim(cursor: &mut u32) -> bool {
    let old = *cursor;
    *cursor |= CURSOR_STORM_BIT;
    storm_clear_for_kick(old)
}

/*
 * Stamp one sample with max only and no count.
 * Enqueue stamps, running owns count plus close,
 * so 8 means 8 runnings with no double count.
 * Dual max drops at most one sample, no skew,
 * decay intact. See delay_max bound.
 */
#[cfg(test)]
pub fn delay_stamp(win: u8, cur: u8, sample: u8) -> (u8, u8) {
    let sample = if (sample as u64) > DELAY_MAX {
        250
    } else {
        sample
    };
    (delay_max(win, sample), delay_max(cur, sample))
}

/*
 * True when woken deadline beats frontier plus gran.
 * Frontier is the service floor, so beating it by
 * granule proves earliness with no occupant state.
 * Granule uses woken weight only, occupant weight
 * stays out after the frontier compare fix.
 */
#[cfg(test)]
pub fn deserved(woken_dl: u64, frontier: u64, granule: u64) -> bool {
    (woken_dl.wrapping_sub(frontier.wrapping_add(granule)) as i64) < 0
}

/*
 * True when woken deadline beats frontier plus half
 * granule. Twice as strict as deserved, so only very
 * early wakeups pass. Uses woken weight only with no
 * floor on the half, storm only with no thrash.
 */
#[cfg(test)]
pub fn storm_deserved(woken_dl: u64, frontier: u64, granule: u64) -> bool {
    (woken_dl.wrapping_sub(frontier.wrapping_add(granule >> 1)) as i64) < 0
}

/*
 * True when delay shows storm at two queued. 62 is
 * delay from two queued, so storm needs at least two
 * queued with no extra state.
 */
#[cfg(test)]
pub fn storm_delay(win: u8) -> bool {
    (win as u64) >= STORM_DELAY_WIN
}

/*
 * True when a storm second kick may run. Needs storm
 * delay at 62 plus twice deserved with half granule.
 * Rate plus storm cap at two per slice per CPU with
 * atomic storm claim. First kick uses rate, second
 * uses storm, both clear per slice.
 */
#[cfg(test)]
pub fn storm_ok(win: u8, woken_dl: u64, frontier: u64, granule: u64) -> bool {
    if !storm_delay(win) {
        return false;
    }
    storm_deserved(woken_dl, frontier, granule)
}

/*
 * True when all five preempt gates pass. Armed plus
 * deserved plus same group plus mask plus rate clear
 * with fail closed on any clear. Branch order is armed
 * plus deserved plus group plus mask plus rate, rate
 * last as the atomic claim. Each fail counts total plus
 * its reason at 200B. Disarmed plus rate plus isolation
 * no longer share one count.
 */
#[cfg(test)]
pub fn preempt_ok(
    armed: bool,
    is_deserved: bool,
    is_rate_clear: bool,
    same_group: bool,
    mask_ok: bool,
) -> bool {
    armed && is_deserved && is_rate_clear && same_group && mask_ok
}

/*
 * Skip reason in branch order armed plus deserved plus
 * group plus mask plus rate. Returns none when all gates
 * pass, else the first failing gate. Mirrors the BPF
 * sequential checks in enqueue with rate last as the
 * atomic claim. Total plus reason both count at 200B.
 * Zero means kick, one to five name the reason in order.
 */
#[cfg(test)]
pub fn skip_reason(
    armed: bool,
    is_deserved: bool,
    same_group: bool,
    mask_ok: bool,
    is_rate_clear: bool,
) -> Option<u8> {
    if !armed {
        return Some(1);
    }
    if !is_deserved {
        return Some(2);
    }
    if !same_group {
        return Some(3);
    }
    if !mask_ok {
        return Some(4);
    }
    if !is_rate_clear {
        return Some(5);
    }
    None
}

/*
 * Name of one skip reason for dominance logs. Zero is
 * kick with no skip, one to five follow branch order.
 */
#[cfg(test)]
pub fn skip_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "kick",
        1 => "armed",
        2 => "deserved",
        3 => "group",
        4 => "mask",
        5 => "rate",
        _ => "unknown",
    }
}
