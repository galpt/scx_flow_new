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
/* Armed delay in units at 62 near 1984us. */
pub const DELAY_ARM: u64 = 62;
/* Stand delay in units at 31 near 1ms. */
pub const DELAY_STAND: u64 = 31;
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
/* Cursor peer mask without rate plus stand. */
#[cfg(test)]
pub const CURSOR_MASK: u32 = 0x7fff_fbff;

/*
 * Sample in 32us units from queued count. One slice
 * is 31 units, two slices arm at 62. Cap is 250 at
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
 * True when the delay window is armed at 62. 62 is
 * 1984us in 32us units near two slices.
 */
pub fn delay_armed(win: u8) -> bool {
    (win as u64) >= DELAY_ARM
}

/*
 * True when delay is armed with hysteresis. Arms
 * at 62, then holds while win stays at or past
 * stand at 31 with the latched flag.
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
 * Bits 0 to 9 hold peer, bit10 holds stand, top
 * holds rate, so rotation masks both flags.
 */
pub fn stand_held(cursor: u32) -> bool {
    (cursor & CURSOR_STAND_BIT) != 0
}

/*
 * Max of two delay samples with cap at 250.
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
 * Cursor peer without rate plus stand.
 */
#[cfg(test)]
pub fn cursor_val(cursor: u32) -> u32 {
    cursor & CURSOR_MASK
}

/*
 * Store peer plus keep rate plus stand. Masks the
 * peer, so rotation keeps order with no extra
 * state.
 */
#[cfg(test)]
pub fn cursor_store(peer: u32, old: u32) -> u32 {
    (peer & CURSOR_MASK) | (old & (CURSOR_RATE_BIT | CURSOR_STAND_BIT))
}

/*
 * Set the stand latch plus keep peer plus rate.
 */
#[cfg(test)]
pub fn stand_set(cursor: u32) -> u32 {
    cursor | CURSOR_STAND_BIT
}

/*
 * Clear the stand latch plus keep peer plus rate.
 */
#[cfg(test)]
pub fn stand_clear(cursor: u32) -> u32 {
    cursor & !CURSOR_STAND_BIT
}

/*
 * True when the rate bit is clear for one kick.
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
 * True when woken deadline beats frontier plus gran.
 * Frontier is the service floor, so beating it by
 * granule proves earliness with no occupant state.
 */
#[cfg(test)]
pub fn deserved(woken_dl: u64, frontier: u64, granule: u64) -> bool {
    (woken_dl.wrapping_sub(frontier.wrapping_add(granule)) as i64) < 0
}

/*
 * True when all five preempt gates pass. Armed plus
 * deserved plus rate clear plus same group plus mask
 * with fail closed on any clear.
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
