// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use crate::flow::CAP_BASE;
use crate::flow::HINT_MAX;
use crate::flow::PERIOD_NS;
use crate::flow::PRED_MAX_NS;
use crate::flow::PRED_MIN_NS;
use crate::flow::QUANTUM_NS;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default fixed slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Fixed slice in nanos. Always 1ms with no knob.
    pub quantum_ns: u64,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            quantum_ns: DEF_QUANTUM_NS,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// The slice stays fixed at 1ms with base weight 128 in range
    /// 1 to 16384. The period stays at 16ms with predictor 1ns to 1s.
    /// Dispatch moves at most one hint threaded move per tier bounded
    /// by remaining slots with visits capped at 8 per pass shared across
    /// five tiers plus five hoisted hints plus fused perf with no kfunc
    /// plus no batch plus no flood plus no step plus steal window 4 to 8
    /// plus BSF four disjoint past SSF eight for twelve unique peers
    /// with node-local phases plus drain plus minimum plus id tiebreak,
    /// and joins carry no admission
    /// bound with base capacity 1024. Queues hold 1024 local plus 16 node
    /// plus machine plus overflow with ids in the 0x5100 region. Hints hold 8192
    /// flat rows with period plus weight and no timer wait. Preempt
    /// needs 100us margin plus 100us tail strictly with a floor at 100us
    /// and one kick per wait gated on eligibility. Fairness bounds lag
    /// at 2ms with vruntime plus virtual deadline pacing queue order.
    /// Stats hold 15 counters at 120B with preempt kicks plus skipped.
    pub fn validate(&self) -> Result<()> {
        if self.quantum_ns != QUANTUM_NS {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 128 || WEIGHT_MAX != 16_384 {
            bail!("weight bounds bad");
        }
        if PERIOD_NS != 16_000_000 {
            bail!("period bounds bad");
        }
        if PRED_MIN_NS != 1 || PRED_MAX_NS != 1_000_000_000 {
            bail!("predictor bounds bad");
        }
        if CAP_BASE != 1024 {
            bail!("capacity base bad");
        }
        if HINT_MAX != 8192 {
            bail!("hint bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64 != 100_000 {
            bail!("margin bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64 != 100_000 {
            bail!("tail bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_VLAG_MAX_NS as u64 != 2_000_000 {
            bail!("lag bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64 != 1042 {
            bail!("dsq count bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64 != 8 {
            bail!("visit bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_STEAL_MIN_PEERS as u64 != 4
            || crate::bpf_intf::flow_consts_FLOW_STEAL_MAX_PEERS as u64 != 8
        {
            bail!("steal window bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64 != 4 {
            bail!("bsf bound bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64
            > crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64
        {
            bail!("bsf over visit bad");
        }
        if crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64 != 0x5A01 {
            bail!("overflow id bad");
        }
        if std::mem::size_of::<crate::bpf_intf::flow_sched_stats>() != 120 {
            bail!("stats size bad");
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    /// Values print in microseconds for brevity.
    pub fn describe(&self) -> String {
        format!("quantum={}us", self.quantum_ns / 1000,)
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_ns: Option<u64>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the fixed slice.
    pub fn quantum_ns(mut self, v: u64) -> Self {
        self.quantum_ns = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            quantum_ns: self.quantum_ns.unwrap_or(d.quantum_ns),
        };
        cfg.validate()?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn builder_defaults_match_config() {
        let cfg = ConfigBuilder::default().build().unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn rejects_bad_quantum() {
        let a = ConfigBuilder::default().quantum_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_ns(2_000_000).build();
        assert!(b.is_err());
    }

    #[test]
    /// Summary holds the fixed slice with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("quantum=1000us"));
        assert!(!s.contains("batch"));
    }

    #[test]
    /// Defaults match the shared header with local plus shared queues.
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().quantum_ns,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 1042);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_VLAG_MAX_NS as u64,
            2_000_000
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MACHINE as u64, 0x5A00);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x5A01);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_VISIT as u64,
            8
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_BSF_MAX_PEERS as u64, 4);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_LOCAL_BASE as u64, 0x5100);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_NODE_BASE as u64, 0x5900);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64,
            crate::flow::cgrp::HINT_MAX
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PRED_MIN_NS as u64,
            PRED_MIN_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PRED_MAX_NS as u64,
            PRED_MAX_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_MARGIN_NS as u64,
            100_000
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_TAIL_NS as u64,
            100_000
        );
    }
}
