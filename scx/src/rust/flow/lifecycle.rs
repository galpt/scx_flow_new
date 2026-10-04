// SPDX-License-Identifier: GPL-2.0
//! Task lifecycle mirrors for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Mirrors BPF lifecycle.bpf.c with the stopping charge plus the CPU
//! minimum fold plus the miss count. Running claims the segment start
//! from zero only, stopping charges once via exchange then advances
//! vruntime by the scaled delta and folds the minimum forward, then
//! counts one requeue per runnable stop else one completion. A wall
//! completion past the deadline counts one miss with no wait and no
//! kick. Test-only with no map use.

/// Charged service for one segment with wrap safety.
/// Mirrors BPF stopping: a time before the start charges zero, else
/// now minus start. A zero start means no counted start, so callers
/// skip the charge like BPF with no advance.
#[cfg(test)]
pub fn charge_delta(now: u64, start: u64) -> u64 {
    if start == 0 {
        return 0;
    }
    if crate::flow::edf::time_before(now, start) {
        return 0;
    }
    now.wrapping_sub(start)
}

/// True when one stop counts a deadline miss.
/// Mirrors BPF stopping plus enqueue miss paths: a wall completion
/// past the deadline counts once with no wait and no kick. A zero
/// deadline means no order yet, so no count. Runnable stops never
/// count here since the task already left the CPU only on completion.
#[cfg(test)]
pub fn should_count_miss(deadline: u64, now: u64, runnable: bool) -> bool {
    if runnable {
        return false;
    }
    crate::flow::edf::missed(deadline, now)
}

/// True when one vruntime should fold the CPU minimum forward.
/// Mirrors BPF flow_min_advance: zero never moves the minimum.
#[cfg(test)]
pub fn min_should_advance(vruntime: u64) -> bool {
    vruntime != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_needs_claimed_start() {
        assert_eq!(charge_delta(100, 0), 0);
        assert_eq!(charge_delta(100, 100), 0);
        assert_eq!(charge_delta(200, 100), 100);
        // Backward clock charges nothing like BPF.
        assert_eq!(charge_delta(50, 100), 0);
    }

    #[test]
    fn miss_counts_wall_completion_only() {
        assert!(!should_count_miss(0, 200, false));
        assert!(!should_count_miss(100, 100, false));
        assert!(should_count_miss(100, 101, false));
        assert!(!should_count_miss(100, 101, true));
    }

    #[test]
    fn min_folds_on_nonzero_only() {
        assert!(!min_should_advance(0));
        assert!(min_should_advance(1));
        assert_eq!(crate::flow::vtime::min_advance(100, 0), 100);
        assert_eq!(crate::flow::vtime::min_advance(100, 200), 200);
    }
}
