// SPDX-License-Identifier: GPL-2.0
//! Paper share helpers for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the live subset of the Wu self suspending EDF math shared
//! by tests. Demand bound plus load with lambda, mu, and beta need
//! per task period plus deadline plus suspension terms with loops
//! and extra dividers that do not fit the verifier budget yet, so
//! they stay out of scope for this slice with no frozen stubs. The
//! live subset keeps utilization plus density plus slack plus
//! deadline with one divider each, and BPF runs every helper on
//! the enqueue path with the same saturating edges as below.

/// Fixed point scale for the share math at 1024.
pub const SSF_SCALE: u32 = 1024;
/// Largest execution before the scale multiply saturates.
#[cfg(test)]
const SSF_EXEC_MAX: u64 = 18_014_398_509_481_983;

/// Share of one period used by execution in scale units.
/// Zero period fails closed to full with no divide, huge execution
/// saturates with no wrap, so overload reads past scale.
#[cfg(test)]
pub fn ssf_util(exec: u64, period: u64) -> u32 {
    if period == 0 {
        return SSF_SCALE;
    }
    if exec > SSF_EXEC_MAX {
        return u32::MAX;
    }
    let scaled = exec * SSF_SCALE as u64 / period;
    if scaled > u32::MAX as u64 {
        return u32::MAX;
    }
    scaled as u32
}

/// Share of one span used by execution in scale units.
/// Zero span fails closed to full with no divide, huge execution
/// saturates with no wrap, so overload reads past scale.
#[cfg(test)]
pub fn ssf_density(exec: u64, span: u64) -> u32 {
    if span == 0 {
        return SSF_SCALE;
    }
    if exec > SSF_EXEC_MAX {
        return u32::MAX;
    }
    let scaled = exec * SSF_SCALE as u64 / span;
    if scaled > u32::MAX as u64 {
        return u32::MAX;
    }
    scaled as u32
}

/// Remaining span past execution with floor at zero.
/// A short span fails closed to zero, so overload carries no slack.
#[cfg(test)]
pub fn ssf_slack(span: u64, exec: u64) -> u64 {
    span.saturating_sub(exec)
}

/// Key deadline past the later of base and now with slack.
/// The later time wins with wrap safety, then slack adds with
/// saturation, so a long sleep never earns credit.
#[cfg(test)]
pub fn ssf_deadline(base: u64, now: u64, slack: u64) -> u64 {
    let at = crate::flow_edf::time_max(base, now);
    at.saturating_add(slack)
}

/// Weight aware execution estimate over the starvation window.
/// Scales the 2ms window by effective weight over base 100 with one
/// divider, so base keeps 2ms, heavy estimates past the window with
/// no slack, and light keeps slack for a later key.
#[cfg(test)]
pub fn ssf_exec(starve_ns: u64, eff_w: u32) -> u64 {
    let w = crate::flow_vruntime::clamp_weight(eff_w) as u64;
    starve_ns * w / crate::flow_vruntime::WEIGHT_BASE as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_is_fixed() {
        assert_eq!(SSF_SCALE, 1024);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_SSF_SCALE, SSF_SCALE);
    }

    #[test]
    fn util_tracks_share() {
        assert_eq!(ssf_util(1_000_000, 2_000_000), 512);
        assert_eq!(ssf_util(2_000_000, 2_000_000), 1024);
        assert_eq!(ssf_util(4_000_000, 2_000_000), 2048);
        assert_eq!(ssf_util(0, 2_000_000), 0);
    }

    #[test]
    fn util_fails_closed() {
        assert_eq!(ssf_util(1_000, 0), SSF_SCALE);
        assert_eq!(ssf_util(0, 0), SSF_SCALE);
        assert_eq!(ssf_util(u64::MAX, 2_000_000), u32::MAX);
        assert_eq!(ssf_util(SSF_EXEC_MAX + 1, 1), u32::MAX);
    }

    #[test]
    fn density_tracks_span() {
        assert_eq!(ssf_density(1_000_000, 2_000_000), 512);
        assert_eq!(ssf_density(2_000_000, 2_000_000), 1024);
        assert_eq!(ssf_density(0, 2_000_000), 0);
        assert_eq!(ssf_density(1_000, 0), SSF_SCALE);
        assert_eq!(ssf_density(u64::MAX, 1), u32::MAX);
    }

    #[test]
    fn slack_holds_remainder() {
        assert_eq!(ssf_slack(2_000_000, 1_000_000), 1_000_000);
        assert_eq!(ssf_slack(2_000_000, 2_000_000), 0);
        assert_eq!(ssf_slack(1_000_000, 2_000_000), 0);
        assert_eq!(ssf_slack(0, 0), 0);
    }

    #[test]
    fn deadline_adds_past_later_time() {
        assert_eq!(ssf_deadline(10_000_000, 9_000_000, 1_000_000), 11_000_000);
        assert_eq!(ssf_deadline(9_000_000, 10_000_000, 1_000_000), 11_000_000);
        assert_eq!(ssf_deadline(10_000_000, 10_000_000, 0), 10_000_000);
        assert_eq!(ssf_deadline(u64::MAX - 5, u64::MAX - 5, 10), u64::MAX);
        assert_eq!(ssf_deadline(u64::MAX, 1, 10), 11);
    }

    #[test]
    fn exec_bends_with_weight() {
        assert_eq!(ssf_exec(2_000_000, 100), 2_000_000);
        assert_eq!(ssf_exec(2_000_000, 10_000), 200_000_000);
        assert_eq!(ssf_exec(2_000_000, 1), 20_000);
        assert_eq!(ssf_exec(2_000_000, 50), 1_000_000);
    }

    #[test]
    fn live_chain_binds_every_helper() {
        let base = 10_000_000u64;
        let now = 9_000_000u64;
        let exec = ssf_exec(crate::flow_edf::STARVE_NS, 100);
        let util = ssf_util(exec, crate::flow_edf::STARVE_NS);
        let dens = ssf_density(exec, crate::flow_edf::STARVE_NS);
        let mut slack = ssf_slack(crate::flow_edf::STARVE_NS, exec);
        assert_eq!(util, SSF_SCALE);
        assert_eq!(dens, SSF_SCALE);
        assert_eq!(slack, 0);
        if util > SSF_SCALE || dens > SSF_SCALE {
            slack = 0;
        }
        assert_eq!(ssf_deadline(base, now, slack), base);
        let light = ssf_exec(crate::flow_edf::STARVE_NS, 1);
        let lu = ssf_util(light, crate::flow_edf::STARVE_NS);
        let ld = ssf_density(light, crate::flow_edf::STARVE_NS);
        let mut ls = ssf_slack(crate::flow_edf::STARVE_NS, light);
        assert!(lu < SSF_SCALE);
        assert!(ld < SSF_SCALE);
        if lu > SSF_SCALE || ld > SSF_SCALE {
            ls = 0;
        }
        assert_eq!(ls, crate::flow_edf::STARVE_NS - light);
        assert_eq!(ssf_deadline(base, now, ls), base + ls);
    }
}
