/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Preempt unit tests for the flow scheduler. The tests
 * mirror the BPF header so behavior stays the same on
 * both sides of the boundary. Delay stays in 32us units
 * with integer math only and no float use.
 */
use crate::flow_preempt::*;
use crate::flow_select::*;

#[test]
fn delay_consts_match_header() {
    assert_eq!(
        DELAY_UNIT_NS,
        crate::bpf_intf::flow_consts_FLOW_DELAY_UNIT_NS as u64
    );
    assert_eq!(
        DELAY_MAX,
        crate::bpf_intf::flow_consts_FLOW_DELAY_MAX as u64
    );
    assert_eq!(
        DELAY_ARM,
        crate::bpf_intf::flow_consts_FLOW_DELAY_ARM as u64
    );
    assert_eq!(
        DELAY_STAND,
        crate::bpf_intf::flow_consts_FLOW_DELAY_STAND as u64
    );
    assert_eq!(
        DELAY_WIN_LEN,
        crate::bpf_intf::flow_consts_FLOW_DELAY_WIN_LEN as u64
    );
    assert_eq!(
        GRANULE_FLOOR_NS,
        crate::bpf_intf::flow_consts_FLOW_GRANULE_FLOOR_NS as u64
    );
    assert_eq!(
        CURSOR_RATE_BIT,
        crate::bpf_intf::flow_consts_FLOW_CURSOR_RATE_BIT as u32
    );
    assert_eq!(
        crate::flow_preempt::CURSOR_STAND_BIT,
        crate::bpf_intf::flow_consts_FLOW_CURSOR_STAND_BIT as u32
    );
    assert_eq!(
        CURSOR_MASK,
        crate::bpf_intf::flow_consts_FLOW_CURSOR_MASK as u32
    );
    assert_eq!(DELAY_UNIT_NS, 32_000);
    assert_eq!(DELAY_MAX, 250);
    assert_eq!(DELAY_ARM, 62);
    assert_eq!(DELAY_STAND, 31);
    assert_eq!(DELAY_WIN_LEN, 8);
    assert_eq!(GRANULE_FLOOR_NS, 64_000);
    assert_eq!(crate::flow_preempt::CURSOR_STAND_BIT, 0x400);
    assert_eq!(CURSOR_MASK, 0x7fff_fbff);
}

#[test]
fn delay_sample_maps_queued_to_units() {
    assert_eq!(delay_from_queued(0), 0);
    assert_eq!(delay_from_queued(1), 31);
    assert_eq!(delay_from_queued(2), 62);
    assert_eq!(delay_from_queued(3), 93);
    assert_eq!(delay_from_queued(4), 125);
    assert_eq!(delay_from_queued(7), 218);
    assert_eq!(delay_from_queued(8), 250);
    assert_eq!(delay_from_queued(9), 250);
    assert_eq!(delay_from_queued(100), 250);
    assert_eq!(delay_from_queued(u64::MAX), 250);
}

#[test]
fn delay_armed_needs_62() {
    assert!(!delay_armed(0));
    assert!(!delay_armed(31));
    assert!(!delay_armed(61));
    assert!(delay_armed(62));
    assert!(delay_armed(63));
    assert!(delay_armed(250));
}

#[test]
fn stand_holds_62_to_55_until_31() {
    assert!(delay_armed_latched(62, false));
    assert!(delay_armed_latched(55, true));
    assert!(!delay_armed(55));
    assert!(delay_armed_latched(31, true));
    assert!(!delay_armed_latched(30, true));
    assert!(!delay_armed_latched(55, false));
    assert!(!delay_armed_latched(31, false));
    assert!(!delay_armed_latched(0, true));
    assert!(!stand_held(0));
    assert!(stand_held(crate::flow_preempt::CURSOR_STAND_BIT));
    assert!(!stand_held(CURSOR_RATE_BIT));
    let win = delay_close(62, 0);
    assert_eq!(win, 55);
    assert!(delay_armed_latched(win, true));
    assert!(!delay_armed(win));
    let mut w = 62u8;
    let mut held = false;
    held = delay_armed_latched(w, held);
    assert!(held);
    w = delay_close(w, 0);
    held = delay_armed_latched(w, held);
    assert!(held);
    for _ in 0..16 {
        w = delay_close(w, 0);
        held = delay_armed_latched(w, held);
        if !held {
            break;
        }
    }
    assert!(!held);
    assert!((w as u64) < DELAY_STAND);
}

#[test]
fn delay_decay_holds_peaks_for_hysteresis() {
    assert_eq!(delay_decay(0), 0);
    assert_eq!(delay_decay(250), 219);
    assert_eq!(delay_decay(62), 55);
    assert_eq!(delay_decay(8), 7);
    let mut win = 250u8;
    for _ in 0..3 {
        win = delay_close(win, 0);
    }
    assert!(delay_armed(win));
    for _ in 0..12 {
        win = delay_close(win, 0);
    }
    assert!(!delay_armed(win));
    let mut w2 = 62u8;
    w2 = delay_close(w2, 0);
    assert!(!delay_armed(w2));
    let w3 = delay_close(62, 62);
    assert!(delay_armed(w3));
}

#[test]
fn delay_window_push_fast_arm_slow_fall() {
    let (w, c, n) = delay_push(0, 0, 0, 62);
    assert_eq!(w, 62);
    assert!(delay_armed(w));
    assert_eq!(c, 62);
    assert_eq!(n, 1);
    let mut win = 0u8;
    let mut cur = 0u8;
    let mut cnt = 0u16;
    for _ in 0..7 {
        let (a, b, d) = delay_push(win, cur, cnt, 10);
        win = a;
        cur = b;
        cnt = d;
    }
    assert!(!delay_armed(win));
    let (w2, _, _) = delay_push(win, cur, cnt, 250);
    assert!(delay_armed(w2));
    let mut w3 = w2;
    let mut c3 = 0u8;
    let mut n3 = 0u16;
    for _ in 0..120 {
        let (a, b, d) = delay_push(w3, c3, n3, 0);
        w3 = a;
        c3 = b;
        n3 = d;
        if !delay_armed(w3) {
            break;
        }
    }
    assert!(!delay_armed(w3));
}

#[test]
fn granule_is_weight_aware_with_64us_floor() {
    let slice = 1_000_000u64;
    assert_eq!(granule_for_weight(1024, slice), 250_000);
    assert_eq!(granule_for_weight(2048, slice), 125_000);
    assert_eq!(granule_for_weight(256, slice), 1_000_000);
    assert_eq!(granule_for_weight(1024, 0), 64_000);
    assert_eq!(granule_for_weight(0, slice), 250_000);
    assert_eq!(granule_for_weight(0, 0), 64_000);
    assert_eq!(granule_for_weight(0, 10_000), 64_000);
    assert_eq!(granule_for_weight(u32::MAX, slice), 64_000);
    assert!(granule_for_weight(2048, slice) < slice);
    assert_eq!(granule_for_weight(256, slice), slice);
    assert!(granule_for_weight(128, slice) > slice);
}

#[test]
fn frontier_deserved_beats_floor_by_granule() {
    let slice = 1_000_000u64;
    let gran = granule_for_weight(1024, slice);
    assert_eq!(gran, 250_000);
    let frontier = 100_000_000u64;
    assert!(deserved(frontier, frontier, gran));
    assert!(deserved(frontier + 100_000, frontier, gran));
    assert!(!deserved(frontier + gran, frontier, gran));
    assert!(!deserved(frontier + gran + 1, frontier, gran));
    assert!(!deserved(frontier + 1_000_000, frontier, gran));
    let old = u64::MAX - 10;
    let wrap_gran = 20u64;
    let wrap_sum = old.wrapping_add(wrap_gran);
    assert_eq!(wrap_sum, 9);
    assert!(deserved(5, old, wrap_gran));
    assert!(!deserved(20, old, wrap_gran));
}

#[test]
fn rate_bit_gates_once_per_slice() {
    use crate::flow_preempt::CURSOR_STAND_BIT;
    assert!(rate_clear(0));
    assert!(rate_clear(5));
    assert!(rate_clear(CURSOR_MASK));
    assert!(!rate_clear(CURSOR_RATE_BIT));
    assert!(!rate_clear(CURSOR_RATE_BIT | 5));
    assert_eq!(cursor_val(CURSOR_RATE_BIT | 5), 5);
    assert_eq!(cursor_val(CURSOR_STAND_BIT | 5), 5);
    assert_eq!(cursor_val(CURSOR_RATE_BIT | CURSOR_STAND_BIT | 5), 5);
    assert_eq!(cursor_val(5), 5);
    assert_eq!(cursor_val(0), 0);
    assert_eq!(rate_set(5), CURSOR_RATE_BIT | 5);
    assert!(!rate_clear(rate_set(5)));
    assert_eq!(cursor_val(rate_set(1023)), 1023);
    let masked = cursor_val(CURSOR_RATE_BIT | 2);
    assert_eq!(steal_next(masked, 4), 3);
    assert_eq!(steal_next(2, 4), 3);
    let masked_stand = cursor_val(CURSOR_STAND_BIT | 2);
    assert_eq!(masked_stand, 2);
    assert_eq!(steal_next(masked_stand, 4), 3);
    let both = cursor_val(CURSOR_RATE_BIT | CURSOR_STAND_BIT | 2);
    assert_eq!(both, 2);
    assert_eq!(steal_next(both, 4), steal_next(2, 4));
}

#[test]
fn rate_claim_wins_once_per_slice() {
    let mut c = 0u32;
    assert!(rate_claim(&mut c));
    assert!(!rate_clear(c));
    assert!(!rate_claim(&mut c));
    assert!(!rate_clear(c));
    assert_eq!(cursor_val(c), 0);
    let mut d = CURSOR_RATE_BIT | 5;
    assert!(!rate_claim(&mut d));
    assert_eq!(cursor_val(d), 5);
    let mut e = crate::flow_preempt::CURSOR_STAND_BIT | 5;
    assert!(rate_claim(&mut e));
    assert!(stand_held(e));
    assert_eq!(cursor_val(e), 5);
    assert!(!rate_claim(&mut e));
}

#[test]
fn delay_stamp_has_no_count() {
    let (w, c) = delay_stamp(0, 0, 62);
    assert_eq!(w, 62);
    assert_eq!(c, 62);
    assert!(delay_armed(w));
    let (w2, c2) = delay_stamp(100, 20, 10);
    assert_eq!(w2, 100);
    assert_eq!(c2, 20);
    let (w3, c3) = delay_stamp(10, 10, 250);
    assert_eq!(w3, 250);
    assert_eq!(c3, 250);
    let mut win = 0u8;
    let mut cur = 0u8;
    let mut cnt = 0u16;
    for _ in 0..7 {
        let (a, b, d) = delay_push(win, cur, cnt, 0);
        win = a;
        cur = b;
        cnt = d;
    }
    assert_eq!(cnt, 7);
    let (sw, sc) = delay_stamp(win, cur, 62);
    assert_eq!(sw, 62);
    assert_eq!(sc, 62);
    assert_eq!(cnt, 7);
    let (cw, cc, cn) = delay_push(sw, sc, cnt, 0);
    assert_eq!(cn, 0);
    assert_eq!(cc, 0);
    assert!(delay_armed(cw));
}

#[test]
fn cursor_store_keeps_rate_plus_stand() {
    use crate::flow_preempt::CURSOR_STAND_BIT;
    let old = CURSOR_RATE_BIT | CURSOR_STAND_BIT | 7;
    assert_eq!(cursor_store(2, old), CURSOR_RATE_BIT | CURSOR_STAND_BIT | 2);
    assert_eq!(cursor_store(2, 0), 2);
    assert_eq!(cursor_store(2, CURSOR_RATE_BIT | 7), CURSOR_RATE_BIT | 2);
    assert_eq!(cursor_store(2, CURSOR_STAND_BIT | 7), CURSOR_STAND_BIT | 2);
    assert_eq!(stand_set(5), CURSOR_STAND_BIT | 5);
    assert!(stand_held(stand_set(5)));
    assert!(!stand_held(stand_clear(stand_set(5))));
    assert_eq!(cursor_val(cursor_store(2, old)), 2);
    assert_eq!(
        steal_next(cursor_val(cursor_store(9, old)), 16),
        steal_next(9, 16)
    );
}

#[test]
fn preempt_needs_five_gates_fail_closed() {
    assert!(preempt_ok(true, true, true, true, true));
    assert!(!preempt_ok(false, true, true, true, true));
    assert!(!preempt_ok(true, false, true, true, true));
    assert!(!preempt_ok(true, true, false, true, true));
    assert!(!preempt_ok(true, true, true, false, true));
    assert!(!preempt_ok(true, true, true, true, false));
    assert!(!preempt_ok(false, false, false, false, false));
    assert!(!preempt_ok(true, true, true, true, false));
    let armed = delay_armed(61);
    assert!(!preempt_ok(armed, true, true, true, true));
    let armed2 = delay_armed(62);
    assert!(preempt_ok(armed2, true, true, true, true));
    assert!(!preempt_ok(armed2, false, true, true, true));
}

#[test]
fn disarmed_matches_prior_no_kick() {
    for win in [0u8, 31, 61] {
        assert!(!delay_armed(win));
        assert!(!preempt_ok(delay_armed(win), true, true, true, true));
    }
    for win in [62u8, 100, 250] {
        assert!(delay_armed(win));
        assert!(!preempt_ok(delay_armed(win), false, true, true, true));
        assert!(!preempt_ok(delay_armed(win), true, false, true, true));
    }
}

#[test]
fn facade_matches_preempt_helpers() {
    assert_eq!(
        crate::flow::DELAY_UNIT_NS,
        crate::flow_preempt::DELAY_UNIT_NS
    );
    assert_eq!(crate::flow::DELAY_MAX, crate::flow_preempt::DELAY_MAX);
    assert_eq!(crate::flow::DELAY_ARM, crate::flow_preempt::DELAY_ARM);
    assert_eq!(crate::flow::DELAY_STAND, crate::flow_preempt::DELAY_STAND);
    assert_eq!(
        crate::flow::CURSOR_STAND_BIT,
        crate::flow_preempt::CURSOR_STAND_BIT
    );
    assert_eq!(
        crate::flow::GRANULE_FLOOR_NS,
        crate::flow_preempt::GRANULE_FLOOR_NS
    );
    assert_eq!(
        crate::flow::delay_from_queued(2),
        crate::flow_preempt::delay_from_queued(2)
    );
    assert_eq!(
        crate::flow::granule_for_weight(1024, 1_000_000),
        crate::flow_preempt::granule_for_weight(1024, 1_000_000)
    );
    assert_eq!(
        crate::flow::delay_armed_latched(55, true),
        crate::flow_preempt::delay_armed_latched(55, true)
    );
    assert_eq!(
        crate::flow::stand_held(0x400),
        crate::flow_preempt::stand_held(0x400)
    );
}
