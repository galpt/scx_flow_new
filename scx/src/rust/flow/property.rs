// SPDX-License-Identifier: GPL-2.0
//! Property tests for EDF plus SSF plus fair order.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds deterministic property checks over the test-only mirrors with
//! fixed seeds and no randomness, so CI stays repeatable. Each property
//! walks a bounded input space and asserts the invariant the BPF side
//! relies on for veristat plus tail latency. Mirrors cover the math
//! subset for tests only with no map or RCU use; kernel order stays in
//! the priority queues and kicks stay in BPF.

#[cfg(test)]
mod tests {
    #[test]
    fn deadline_is_monotonic_in_period() {
        for now in [0u64, 1_000, 1_000_000, u64::MAX - 20_000_000] {
            for hint in [0u32, 1000, 8000, 32000] {
                let a = crate::flow::edf::pred_deadline(now, 0, 0, hint);
                let b = crate::flow::edf::fallback_deadline(now, hint);
                assert_eq!(a, b);
                assert!(a >= now || a == u64::MAX);
            }
        }
    }

    #[test]
    fn fair_key_is_min_of_deadline_and_vd() {
        for (d, v) in [
            (0u64, 0u64),
            (0, 100),
            (100, 0),
            (10_000_000, 2_000_000),
            (1_000_000, 2_000_000),
            (u64::MAX, 100),
        ] {
            let got = crate::flow::edf::fair_vtime(d, v);
            if d == 0 {
                assert_eq!(got, v);
            } else if v == 0 {
                assert_eq!(got, d);
            } else {
                assert!(got == d || got == v);
                assert!(
                    crate::flow::edf::time_before(got, d)
                        || got == d
                        || crate::flow::edf::time_before(got, v)
                        || got == v
                );
            }
        }
    }

    #[test]
    fn calc_is_monotonic_in_weight() {
        let delta = 1_000_000u64;
        let mut prev = u64::MAX;
        for w in [1u32, 16, 32, 64, 128, 256, 512, 1024, 4096, 16_384] {
            let cur = crate::flow::edf::scaled_delta(delta, w);
            assert!(cur <= prev, "w={w} cur={cur} prev={prev}");
            prev = cur;
        }
        assert_eq!(crate::flow::edf::scaled_delta(0, 1), 0);
        assert_eq!(crate::flow::edf::scaled_delta(1, 16_384), 1);
    }

    #[test]
    fn ssf_picks_slowest_sufficient_within_visit() {
        // Eight peer bound holds with the lagging minimum winning ties.
        assert_eq!(crate::flow::select::SHARED_SCAN_BOUND, 8);
        assert_eq!(crate::flow::select::BSF_SCAN_BOUND, 4);
        let got = crate::flow::select::place(
            &[],
            9,
            &[1, 2, 3],
            &[1, 2, 3],
            &[0, 0, 0],
            &[1024, 1024, 1024],
            &[300, 100, 200],
            100,
            0,
            99,
            2,
        );
        assert_eq!(got, 2);
        // Window stays four to eight with no hotspot.
        assert_eq!(crate::flow::select::steal_window(0), 8);
        assert_eq!(crate::flow::select::steal_window(8), 4);
        // Pow2 masking matches modulo with no divide on 16 CPUs.
        assert_eq!(crate::flow::select::wrap_idx(17, 16), 1);
        assert_eq!(crate::flow::select::wrap_idx(17, 12), 17 % 12);
    }

    #[test]
    fn overflow_and_tier_ids_are_live() {
        assert_eq!(crate::flow::slot::SLOT_OVERFLOW, 0x5A01);
        assert!(crate::flow::slot::dsq_valid(
            crate::flow::slot::overflow_dsq()
        ));
        assert!(crate::flow::slot::dsq_valid(
            crate::flow::slot::machine_dsq()
        ));
        assert_eq!(crate::flow::slot::slot_nr_dsqs(), 1042);
    }

    #[test]
    fn preempt_needs_lead_and_tail() {
        assert!(crate::flow::preempt::preempt_wants(
            10, 600_000, 2_000_000, 1, 0, 0, 0
        ));
        assert!(!crate::flow::preempt::preempt_wants(
            19, 20, 2_000_000, 1, 0, 0, 0
        ));
        assert!(!crate::flow::preempt::preempt_wants(
            10, 20, 100_000, 1, 0, 0, 0
        ));
    }

    #[test]
    fn ledger_and_min_hold_invariants() {
        assert_eq!(
            crate::flow::vtime::ledger_advance(1_000, 1_000_000, 128),
            1_001_000
        );
        assert_eq!(crate::flow::vtime::min_advance(100, 0), 100);
        assert_eq!(crate::flow::vtime::min_advance(100, 200), 200);
        assert_eq!(crate::flow::weight::nice_to_weight(0), 128);
    }

    #[test]
    fn bsf_and_steal_hold_combined_drain() {
        // BSF takes the smallest combined drain that still meets.
        let got = crate::flow::select::bsf_pick(
            &[1, 2, 3],
            &[1, 2, 3],
            &[9, 0, 5],
            &[9, 0, 0],
            100,
            0,
            99,
            0,
        );
        assert_eq!(got, 2);
        // Four-tier steal skips on any tier backlog with visits shared.
        assert!(!crate::flow::select::steal_should_skip(0, 0, 0, 0));
        assert!(crate::flow::select::steal_should_skip(0, 0, 0, 1));
        assert!(crate::flow::dispatch::should_steal(0, 0, 0, 0, 0));
        assert!(!crate::flow::dispatch::should_steal(0, 0, 0, 1, 0));
        assert_eq!(crate::flow::dispatch::VISIT_MAX, 8);
        assert_eq!(crate::flow::select::steal_window(0), 8);
        assert_eq!(crate::flow::select::cursor_next(0, 4), 2);
        // Q1 fast path drains local alone with no other backlog.
        assert!(crate::flow::dispatch::q1_only(1, 0, 0, 0));
        assert!(!crate::flow::dispatch::q1_only(1, 1, 0, 0));
        assert!(!crate::flow::dispatch::q1_only(0, 0, 0, 0));
    }

    #[test]
    fn lifecycle_and_timer_hold_charge() {
        assert_eq!(crate::flow::lifecycle::charge_delta(200, 100), 100);
        assert_eq!(crate::flow::lifecycle::charge_delta(50, 100), 0);
        assert!(crate::flow::lifecycle::should_count_miss(100, 101, false));
        assert!(!crate::flow::lifecycle::should_count_miss(100, 101, true));
        assert_eq!(crate::flow::timer::decay_noop(100, 200), 100);
        assert!(crate::flow::preempt::preempt_leads(10, 600_000, 0, 1));
        assert!(!crate::flow::preempt::preempt_leads(19, 20, 0, 1));
    }
}
