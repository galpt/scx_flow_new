// SPDX-License-Identifier: GPL-2.0
//! Dispatch tier mirrors for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF dispatch.bpf.c with the fixed five-tier order plus the
//! shared visit cap plus the saturated steal early-out plus the Q1
//! only fast path plus hint threaded moves plus fused perf. Tier order
//! is local plus node plus machine plus overflow plus steal with at most
//! one hint move per tier bounded by remaining slots. Five depths hoist
//! once, so tiers plus steal plus perf share the same reads with no
//! second poll. Visits cap at eight per pass shared across tiers with
//! resume next pass. Steal scans four to eight peers proportional to
//! remaining visits and only when all four queued tiers hold no backlog
//! with per peer hints threaded into the shared hint move. Perf reuses
//! the hoisted local plus local on plus node hints with no kfunc. The
//! shared cursor with select advances by two on success with best effort
//! races, and the TOCTOU between hoisted hints and moves only repeats or
//! skips a pass with no loss. Test-only with no map use.

//! Clippy stays clean on stable 1.91 with `-Dwarnings`.

/// Visit cap per pass shared across the five tiers.
#[cfg(test)]
pub const VISIT_MAX: u32 = 8;

/// Fixed tier order: local plus node plus machine plus overflow plus steal.
#[cfg(test)]
pub const TIER_ORDER: [&str; 5] = ["local", "node", "machine", "overflow", "steal"];

/// True when another tier move may still visit within the cap.
/// Mirrors the BPF likely visit check shared by every tier.
#[cfg(test)]
pub fn visit_ok(visits: u32) -> bool {
    visits < VISIT_MAX
}

/// True when only the local tier holds queued work.
/// Mirrors BPF dispatch Q1 only fast path, so the common single
/// queue pass drains local alone with no other tier move.
#[cfg(test)]
pub fn q1_only(local: u64, node: u64, machine: u64, overflow: u64) -> bool {
    local > 0 && node == 0 && machine == 0 && overflow == 0
}

/// True when the steal tier scans peers on this pass.
/// Mirrors BPF dispatch: needs visit room plus zero backlog over all
/// four queued tiers with saturation, so busy passes skip cheap.
#[cfg(test)]
pub fn should_steal(local: u64, node: u64, machine: u64, overflow: u64, visits: u32) -> bool {
    visit_ok(visits) && !crate::flow::select::steal_should_skip(local, node, machine, overflow)
}

/// True when a hint threaded move runs for one tier.
/// Mirrors BPF flow_move_one_hint: non-positive hints skip with no RCU
/// cost, otherwise the tier moves within the shared visit cap.
#[cfg(test)]
pub fn move_hint_ok(hint: i32, visits: u32) -> bool {
    hint > 0 && visit_ok(visits)
}

/// True when the fused perf probe sees busy from hoisted hints.
/// Mirrors BPF flow_perf_busy_hint with no kfunc: any positive hint or
/// a running pid means busy with signed hints.
#[cfg(test)]
pub fn perf_busy_hint(local_q: i32, local_on_q: i32, node_q: i32, running: bool) -> bool {
    local_q > 0 || local_on_q > 0 || node_q > 0 || running
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_order_is_fixed_five() {
        assert_eq!(
            TIER_ORDER,
            ["local", "node", "machine", "overflow", "steal"]
        );
        assert_eq!(VISIT_MAX, 8);
        assert_eq!(
            VISIT_MAX,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u32
        );
    }

    #[test]
    fn visits_cap_at_eight() {
        assert!(visit_ok(0));
        assert!(visit_ok(7));
        assert!(!visit_ok(8));
        assert!(!visit_ok(u32::MAX));
    }

    #[test]
    fn steal_needs_empty_tiers_and_room() {
        assert!(should_steal(0, 0, 0, 0, 0));
        assert!(!should_steal(1, 0, 0, 0, 0));
        assert!(!should_steal(0, 1, 0, 0, 0));
        assert!(!should_steal(0, 0, 1, 0, 0));
        assert!(!should_steal(0, 0, 0, 1, 0));
        assert!(!should_steal(0, 0, 0, 0, 8));
        // Window stays four to eight with no hotspot.
        assert_eq!(crate::flow::select::steal_window(0), 8);
        assert_eq!(crate::flow::select::steal_window(8), 4);
    }

    #[test]
    fn q1_only_drains_local_alone() {
        assert!(q1_only(1, 0, 0, 0));
        assert!(!q1_only(0, 0, 0, 0));
        assert!(!q1_only(1, 1, 0, 0));
        assert!(!q1_only(1, 0, 1, 0));
        assert!(!q1_only(1, 0, 0, 1));
        assert!(!q1_only(0, 1, 0, 0));
        // Q1 still needs visit room like other tiers.
        assert!(visit_ok(0));
        assert!(!visit_ok(8));
    }

    #[test]
    fn hint_moves_and_perf_fuse() {
        // Hint threaded moves skip empty tiers with no RCU cost.
        assert!(move_hint_ok(1, 0));
        assert!(!move_hint_ok(0, 0));
        assert!(!move_hint_ok(-1, 0));
        assert!(!move_hint_ok(1, 8));
        // Fused perf reuses hoisted hints with no kfunc.
        assert!(perf_busy_hint(1, 0, 0, false));
        assert!(perf_busy_hint(0, 1, 0, false));
        assert!(perf_busy_hint(0, 0, 1, false));
        assert!(perf_busy_hint(0, 0, 0, true));
        assert!(!perf_busy_hint(0, 0, 0, false));
        assert!(!perf_busy_hint(-1, 0, 0, false));
    }
}
