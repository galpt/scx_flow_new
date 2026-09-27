// SPDX-License-Identifier: GPL-2.0
//! Kick rate helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the busy kick rate and class rule helpers shared by tests and docs.
//! The BPF busy path resolves the occupant first under one RCU pass,
//! then serves class plus slice shorten with the window gating batch
//! pairs only. See enqueue.bpf.c for the kick order.

/// Busy kick window in nanos at 2ms.
#[cfg(test)]
pub const RATE_WINDOW_NS: u64 = 2_000_000;
/// Preempt floor in nanos at 100us.
#[cfg(test)]
pub const PREEMPT_FLOOR_NS: u64 = 100_000;
/// Interactive class id.
#[cfg(test)]
pub const CLS_INTERACTIVE: u8 = 0;
/// Batch class id.
#[cfg(test)]
pub const CLS_BATCH: u8 = 1;

/// True when one busy kick may run.
/// Zero last always wins with wrap, so the first kick never waits.
/// Later kicks need one full window since the last win.
#[cfg(test)]
pub fn rate_ok(now: u64, last: u64) -> bool {
    if last == 0 {
        return true;
    }
    now.wrapping_sub(last) >= RATE_WINDOW_NS
}

/// True when one kick choice needs the 2ms window.
/// Batch pairs gate on the window, and interactive pairs keep it for
/// order though they yield with no kick. Interactive over batch stays
/// prompt with no gate, and denied pairs never kick.
#[cfg(test)]
pub fn kick_needs_gate(new_cls: u8, occ_cls: u8) -> bool {
    if new_cls == CLS_INTERACTIVE && occ_cls == CLS_BATCH {
        return false;
    }
    if new_cls == CLS_BATCH && occ_cls == CLS_INTERACTIVE {
        return false;
    }
    new_cls == occ_cls
}

/// Slice left for one occupant when the kick is rate limited.
/// Holds the 100us floor, so a hot window still shortens the slice
/// with no kick storm.
#[cfg(test)]
pub fn limited_shorten_ns() -> u64 {
    PREEMPT_FLOOR_NS
}

/// Class of one task from policy and duty.
/// Idle and batch policies always rest in batch. Other non normal policies
/// stay out of the fast lane with batch class. Normal tasks split at half
/// duty, so steady spinners cannot preempt sleepers.
#[cfg(test)]
pub fn class_of(policy: i32, duty: u8) -> u8 {
    if policy == 5 || policy == 3 {
        return CLS_BATCH;
    }
    if policy != 0 {
        return CLS_BATCH;
    }
    if duty >= crate::flow_admit::DUTY_BATCH {
        return CLS_BATCH;
    }
    CLS_INTERACTIVE
}

/// Kick choice for one busy arrival.
/// Interactive over batch preempts prompt at the 100us floor. Interactive
/// pairs yield at the micro quantum end with no kick. Batch over
/// interactive never preempts. Batch over batch preempts only past slice
/// exhaust with a deadline gap over one micro quantum.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kick {
    PromptFloor,
    PromptZero,
    Cooperative,
    Denied,
}

#[cfg(test)]
pub fn kick_choice(new_cls: u8, occ_cls: u8, occ_exhausted: bool, gap_ok: bool) -> Kick {
    if new_cls == CLS_BATCH && occ_cls == CLS_INTERACTIVE {
        return Kick::Denied;
    }
    if new_cls == CLS_INTERACTIVE && occ_cls == CLS_INTERACTIVE {
        return Kick::Cooperative;
    }
    if new_cls == CLS_INTERACTIVE {
        return Kick::PromptFloor;
    }
    if occ_exhausted && gap_ok {
        return Kick::PromptZero;
    }
    Kick::Denied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactive_over_batch_is_prompt_floor() {
        assert_eq!(
            kick_choice(CLS_INTERACTIVE, CLS_BATCH, false, false),
            Kick::PromptFloor
        );
    }

    #[test]
    fn interactive_pair_is_cooperative() {
        assert_eq!(
            kick_choice(CLS_INTERACTIVE, CLS_INTERACTIVE, true, true),
            Kick::Cooperative
        );
    }

    #[test]
    fn batch_over_interactive_is_denied() {
        assert_eq!(
            kick_choice(CLS_BATCH, CLS_INTERACTIVE, true, true),
            Kick::Denied
        );
    }

    #[test]
    fn batch_pair_needs_exhaust_and_gap() {
        assert_eq!(
            kick_choice(CLS_BATCH, CLS_BATCH, true, true),
            Kick::PromptZero
        );
        assert_eq!(kick_choice(CLS_BATCH, CLS_BATCH, false, true), Kick::Denied);
        assert_eq!(kick_choice(CLS_BATCH, CLS_BATCH, true, false), Kick::Denied);
    }

    #[test]
    fn class_splits_at_half_duty() {
        assert_eq!(class_of(0, 0), CLS_INTERACTIVE);
        assert_eq!(class_of(0, 200), CLS_BATCH);
        assert_eq!(class_of(5, 0), CLS_BATCH);
        assert_eq!(class_of(1, 0), CLS_BATCH);
    }

    #[test]
    fn rate_window_holds_first_and_window() {
        assert!(rate_ok(1_000_000, 0));
        assert!(!rate_ok(1_000_000, 500_000));
        assert!(rate_ok(3_000_000, 500_000));
        assert_eq!(PREEMPT_FLOOR_NS, 100_000);
    }

    #[test]
    fn prompt_pair_bypasses_window_while_batch_gates() {
        assert!(!kick_needs_gate(CLS_INTERACTIVE, CLS_BATCH));
        assert!(kick_needs_gate(CLS_BATCH, CLS_BATCH));
        assert!(kick_needs_gate(CLS_INTERACTIVE, CLS_INTERACTIVE));
        assert!(!kick_needs_gate(CLS_BATCH, CLS_INTERACTIVE));
    }

    #[test]
    fn limited_window_still_shortens_to_floor() {
        assert_eq!(limited_shorten_ns(), 100_000);
        assert_eq!(limited_shorten_ns(), PREEMPT_FLOOR_NS);
        assert_eq!(
            kick_choice(CLS_INTERACTIVE, CLS_BATCH, false, false),
            Kick::PromptFloor
        );
    }
}
