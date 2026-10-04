// SPDX-License-Identifier: GPL-2.0
//! Virtual time ledger plus CPU minimum mirrors.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF vtime.bpf.c with the ledger advance plus the minimum
//! fold. The ledger adds the fair delta with saturation, so heavy tasks
//! move slowly while light tasks move quickly. The minimum folds
//! forward best effort with no regression.

/// Advance vruntime by one delta at one weight with saturation.
#[cfg(test)]
pub fn ledger_advance(vruntime: u64, delta: u64, weight: u32) -> u64 {
    vruntime.saturating_add(crate::flow::edf::scaled_delta(delta, weight))
}

/// Fold one CPU minimum forward to at least the given vruntime.
/// Takes the max with no regression and no move on zero.
#[cfg(test)]
pub fn min_advance(cur: u64, vruntime: u64) -> u64 {
    if vruntime == 0 {
        return cur;
    }
    cur.max(vruntime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_scales_with_weight() {
        assert_eq!(ledger_advance(1_000, 1_000_000, 128), 1_001_000);
        assert_eq!(ledger_advance(0, 0, 128), 0);
        assert_eq!(ledger_advance(u64::MAX - 10, 100, 1), u64::MAX);
    }

    #[test]
    fn min_folds_forward_only() {
        assert_eq!(min_advance(100, 0), 100);
        assert_eq!(min_advance(100, 50), 100);
        assert_eq!(min_advance(100, 200), 200);
    }
}
