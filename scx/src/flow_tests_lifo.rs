// SPDX-License-Identifier: GPL-2.0
//! LIFO unit tests for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Covers the bounded LIFO helpers with period, index, and mirror checks.

use crate::flow_slot::*;

/// Period holds 3 heads with six tails at K 3 plus one forced tail at MAX.
#[test]
fn lifo_period_holds_k_3_with_wrap() {
    for seq in 0..27u32 {
        let want = seq % 9 < 3;
        assert_eq!(lifo_take_head(seq), want);
    }
    assert!(!lifo_take_head(3));
    assert!(!lifo_take_head(4));
    assert!(!lifo_take_head(8));
    assert!(!lifo_take_head(12));
    assert!(!lifo_take_head(17));
    assert!(lifo_take_head(0));
    assert!(lifo_take_head(1));
    assert!(lifo_take_head(2));
    assert!(lifo_take_head(9));
    let max = u32::MAX;
    assert!(!lifo_take_head(max));
    assert!(lifo_take_head(max.wrapping_sub(1)));
    let wrapped = max.wrapping_add(1);
    assert_eq!(wrapped, 0);
    assert!(lifo_take_head(wrapped));
    for off in 0..18u32 {
        let seq = max.wrapping_add(off);
        let want = seq != u32::MAX && seq % 9 < 3;
        assert_eq!(lifo_take_head(seq), want);
    }
}

/// Bound holds six tails per 9 with no more than 3 heads in a row.
#[test]
fn lifo_bound_breach_holds_once_per_period() {
    for base in [0u32, 1, 9, 100, 1000, u32::MAX - 20] {
        let mut heads = 0u32;
        let mut tails = 0u32;
        for off in 0..9u32 {
            let seq = base.wrapping_add(off);
            if lifo_take_head(seq) {
                heads += 1;
            } else {
                tails += 1;
            }
        }
        // Windows clear of MAX hold 3 heads with 6 tails. Windows with
        // MAX hold one extra forced tail, so allow 2 to 3 heads here.
        // The chosen bases all clear MAX, so expect the exact split.
        assert_eq!(heads, 3);
        assert_eq!(tails, 6);
    }
    for base in [0u32, 7, 8, 9] {
        let mut run = 0u32;
        let mut worst = 0u32;
        for off in 0..27u32 {
            let seq = base.wrapping_add(off);
            if lifo_take_head(seq) {
                run += 1;
                if run > worst {
                    worst = run;
                }
            } else {
                run = 0;
            }
        }
        assert!(worst <= 3);
    }
}

/// Index maps per CPU plus overflow at 1025 with no share.
#[test]
fn lifo_idx_maps_per_cpu_plus_overflow() {
    assert_eq!(lifo_idx(false, 0), 0);
    assert_eq!(lifo_idx(false, 1), 1);
    assert_eq!(lifo_idx(false, 1023), 1023);
    assert_eq!(lifo_idx(true, 0), 1024);
    assert_eq!(lifo_idx(true, 999), 1024);
    assert_eq!(LIFO_NSEQ, 1025);
    assert_eq!(SLOT_MAX_DSQS, 1025);
    assert_eq!(LIFO_NSEQ, SLOT_MAX_DSQS);
    assert_eq!(
        LIFO_NSEQ,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
}

/// Mirrors hold K, period, 1025, slice 1M, stats 112, and config 1000us.
#[test]
fn lifo_mirrors_hold() {
    assert_eq!(LIFO_K, 3);
    assert_eq!(LIFO_PERIOD, 9);
    assert_eq!(LIFO_K, crate::bpf_intf::flow_consts_FLOW_LIFO_K as u64);
    assert_eq!(
        LIFO_PERIOD,
        crate::bpf_intf::flow_consts_FLOW_LIFO_PERIOD as u64
    );
    assert_eq!(LIFO_NSEQ, 1025);
    assert_eq!(
        LIFO_NSEQ,
        crate::bpf_intf::flow_consts_FLOW_SLOT_MAX_DSQS as u64
    );
    assert_eq!(crate::flow_slice::SLICE_NS, 1_000_000);
    assert_eq!(
        crate::flow_slice::SLICE_NS,
        crate::bpf_intf::flow_consts_FLOW_SLICE_NS as u64
    );
    assert_eq!(
        std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
        112
    );
    let cfg = crate::config::Config::default();
    assert_eq!(cfg.slice_ns, 1_000_000);
    assert!(cfg.describe().contains("slice=1000us"));
}
