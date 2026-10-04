// SPDX-License-Identifier: GPL-2.0
//! Dispatch tier mirrors for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF dispatch.bpf.c with the fixed five-tier order plus the
//! shared visit cap plus the saturated steal early-out. Tier order is
//! local plus node plus machine plus overflow plus steal with at most
//! one move per tier bounded by remaining slots. Visits cap at eight
//! per pass shared across tiers with resume next pass. Steal scans
//! four to eight peers proportional to remaining visits and only when
//! all four queued tiers hold no backlog. Test-only with no map use.

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

/// True when the steal tier scans peers on this pass.
/// Mirrors BPF dispatch: needs visit room plus zero backlog over all
/// four queued tiers with saturation, so busy passes skip cheap.
#[cfg(test)]
pub fn should_steal(local: u64, node: u64, machine: u64, overflow: u64, visits: u32) -> bool {
    visit_ok(visits) && !crate::flow::select::steal_should_skip(local, node, machine, overflow)
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
}
