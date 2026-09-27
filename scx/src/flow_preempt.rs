// SPDX-License-Identifier: GPL-2.0
//! Kick rate helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the busy kick rate and class rule helpers shared by tests and docs.
//! The BPF busy path resolves the occupant first under one RCU pass,
//! then serves class plus slice shorten with the 2ms window gating batch
//! pairs only and a 500us prompt window on a separate stamp gating
//! interactive over batch with no shared pollute. Rust mirrors are read
//! only predicates with no stamp write. BPF owns the stamps with prompt
//! kicks stamping the prompt slot only and batch kicks stamping the shared
//! slot. See enqueue.bpf.c for the kick order.

/// Busy kick window in nanos at 2ms.
#[cfg(test)]
pub const RATE_WINDOW_NS: u64 = 2_000_000;
/// Prompt kick window in nanos at 500us.
/// Reuses the micro quantum, so interactive over batch stays prompt with no storm.
#[cfg(test)]
pub const PROMPT_WINDOW_NS: u64 = 500_000;
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

/// True when one prompt kick may run.
/// Zero last always wins with wrap, so the first prompt never waits.
/// Later prompts need one full 500us since the last prompt win with no
/// shared stamp, so batch pairs keep their own window.
#[cfg(test)]
pub fn prompt_ok(now: u64, last: u64) -> bool {
    if last == 0 {
        return true;
    }
    now.wrapping_sub(last) >= PROMPT_WINDOW_NS
}

/// True when one kick choice needs the 2ms window.
/// Only batch pairs gate on the shared window. Interactive over batch uses
/// the separate 500us prompt window, and all other pairs never kick with no
/// window consult, so kick choice stays the authority.
#[cfg(test)]
pub fn kick_needs_gate(new_cls: u8, occ_cls: u8) -> bool {
    new_cls == CLS_BATCH && occ_cls == CLS_BATCH
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
/// Interactive over batch preempts prompt at the 100us floor under a 500us
/// prompt window with floor only and no kick when hot. Interactive pairs
/// yield at the micro quantum end with no kick. Batch over interactive never
/// preempts. Batch over batch preempts only past slice exhaust with a
/// deadline gap over one micro quantum under the 2ms window.
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
    fn only_batch_pair_gates_on_shared_window() {
        assert!(!kick_needs_gate(CLS_INTERACTIVE, CLS_BATCH));
        assert!(kick_needs_gate(CLS_BATCH, CLS_BATCH));
        assert!(!kick_needs_gate(CLS_INTERACTIVE, CLS_INTERACTIVE));
        assert!(!kick_needs_gate(CLS_BATCH, CLS_INTERACTIVE));
    }

    #[test]
    fn prompt_window_holds_first_and_window() {
        assert!(prompt_ok(1_000_000, 0));
        assert!(!prompt_ok(1_000_000, 800_000));
        assert!(prompt_ok(1_500_000, 800_000));
        assert_eq!(PROMPT_WINDOW_NS, 500_000);
        assert_eq!(PROMPT_WINDOW_NS, crate::flow_slice::MICRO_QUANTUM_NS);
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
