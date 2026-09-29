// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use crate::flow::BW_PERIOD_MIN_US;
use crate::flow::CGRP_DEPTH_MAX;
use crate::flow::CGRP_MAX;
use crate::flow::CGRP_WEIGHT_DFL;
use crate::flow::DISPATCH_BATCH;
use crate::flow::QUANTUM_NS;
use crate::flow::SLOT_BUDGET;
use crate::flow::SLOT_GATED_CAP;
use crate::flow::SLOT_MISS_CAP;
use crate::flow::SLOT_OVER_CAP;
use crate::flow::SLOT_OWN_CAP;
use crate::flow::STARVE_NS;
use crate::flow::STEAL_BOUND;
use crate::flow::STEAL_MIN_DEPTH;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default fixed slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;
/// Default dispatch batch for the ops table.
const DEF_BATCH: u32 = DISPATCH_BATCH;
/// Default drain budget for one dispatch pass.
const DEF_SLOT_BUDGET: u32 = SLOT_BUDGET;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Fixed slice in nanos. Always 1ms with no knob.
    pub quantum_ns: u64,
    /// Dispatch batch for the ops table.
    pub dispatch_batch: u32,
    /// Drain budget for one dispatch pass.
    pub slot_budget: u32,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            quantum_ns: DEF_QUANTUM_NS,
            dispatch_batch: DEF_BATCH,
            slot_budget: DEF_SLOT_BUDGET,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// The quantum stays fixed at 1ms with base weight 100 in range
    /// 1 to 10000. Rust only validates the header, BPF owns the live
    /// quantum with no knob. The batch stays fixed at 32 and the budget at 32.
    /// The own trip stays at 12 with the shared tail at 4 and a miss
    /// cap at 4. The gated cap runs bounded but larger at 6, so old
    /// tasks behind young heads still surface. Steal scans bound
    /// 8 peers with donors past 2 and a 2ms starvation floor. Queues
    /// hold one deadline queue per CPU plus one overflow tail with ids
    /// below local on. Hierarchies hold 2048 rows with depth 8 and base
    /// share 100 plus a 1ms pool floor.
    pub fn validate(&self) -> Result<()> {
        if self.quantum_ns != QUANTUM_NS {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if self.quantum_ns != 1_000_000 {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 100 || WEIGHT_MAX != 10_000 {
            bail!("weight bounds bad");
        }
        if STARVE_NS != 2_000_000 {
            bail!("starve bounds bad");
        }
        if self.dispatch_batch != DISPATCH_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 32 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.slot_budget != SLOT_BUDGET {
            bail!("slot budget bad {}", self.slot_budget);
        }
        if self.slot_budget != 32 {
            bail!("slot budget bad {}", self.slot_budget);
        }
        if SLOT_OWN_CAP != 12 || SLOT_OVER_CAP != 4 || SLOT_GATED_CAP != 6 {
            bail!("drain caps bad");
        }
        if SLOT_MISS_CAP != 4 {
            bail!("miss cap bad");
        }
        if STEAL_BOUND != 8 {
            bail!("steal bound bad");
        }
        if STEAL_MIN_DEPTH != 2 {
            bail!("steal depth bad");
        }
        if CGRP_MAX != 2048 {
            bail!("hierarchy bound bad");
        }
        if CGRP_DEPTH_MAX != 8 {
            bail!("hierarchy depth bad");
        }
        if CGRP_WEIGHT_DFL != 100 {
            bail!("hierarchy share bad");
        }
        if BW_PERIOD_MIN_US != 1000 {
            bail!("pool floor bad");
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    /// Values print in microseconds for brevity.
    pub fn describe(&self) -> String {
        format!(
            "quantum={}us batch={}",
            self.quantum_ns / 1000,
            self.dispatch_batch,
        )
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_ns: Option<u64>,
    dispatch_batch: Option<u32>,
    slot_budget: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the fixed quantum.
    pub fn quantum_ns(mut self, v: u64) -> Self {
        self.quantum_ns = Some(v);
        self
    }
    /// Set the fixed dispatch batch. Only 32 passes.
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /// Set the fixed dispatch budget. Only 32 passes.
    pub fn slot_budget(mut self, v: u32) -> Self {
        self.slot_budget = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            quantum_ns: self.quantum_ns.unwrap_or(d.quantum_ns),
            dispatch_batch: self.dispatch_batch.unwrap_or(d.dispatch_batch),
            slot_budget: self.slot_budget.unwrap_or(d.slot_budget),
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
    fn builder_explicit_fixed_matches_default() {
        let cfg = ConfigBuilder::default().dispatch_batch(32).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.dispatch_batch, 32);
        assert_eq!(cfg.quantum_ns, Config::default().quantum_ns);
    }

    #[test]
    fn slot_consts_are_fixed() {
        assert_eq!(crate::flow_slot::SLOT_OWN_CAP, 12);
        assert_eq!(crate::flow_slot::SLOT_OVER_CAP, 4);
        assert_eq!(crate::flow_slot::SLOT_GATED_CAP, 6);
        assert_eq!(crate::flow_slot::SLOT_MISS_CAP, 4);
        assert_eq!(Config::default().slot_budget, crate::flow_slot::SLOT_BUDGET);
    }

    #[test]
    fn rejects_non_fixed_slot() {
        for bad in [0, 4, 16, 31, 33, 64] {
            let got = ConfigBuilder::default().slot_budget(bad).build();
            assert!(got.is_err(), "slot budget {bad} must fail");
        }
        let ok = ConfigBuilder::default().slot_budget(32).build();
        assert!(ok.is_ok());
    }

    #[test]
    fn quantum_matches_flow() {
        assert_eq!(Config::default().quantum_ns, crate::flow_slice::QUANTUM_NS);
        assert_eq!(crate::flow_slice::QUANTUM_NS, 1_000_000);
        assert_eq!(crate::flow_slice::WEIGHT_BASE, 100);
        assert_eq!(crate::flow_slice::WEIGHT_MIN, 1);
        assert_eq!(crate::flow_slice::WEIGHT_MAX, 10_000);
        assert_eq!(crate::flow_edf::STARVE_NS, 2_000_000);
    }

    #[test]
    fn runtime_key_holds_slack_cap() {
        assert_eq!(crate::flow_runtime::deadline_slack(100), 1_000_000);
        assert_eq!(
            crate::flow_runtime::deadline_slack(1),
            crate::flow_edf::STARVE_NS
        );
        assert_eq!(
            crate::flow_runtime::deadline_key(u64::MAX, u64::MAX, 1_000_000),
            u64::MAX
        );
        assert_eq!(
            crate::flow_runtime::insert_key(1_000, 1_000, 10_000_000, 0, 100),
            11_000_000
        );
        assert_eq!(
            crate::flow_runtime::charge_share(false, 200),
            crate::flow_slice::WEIGHT_BASE
        );
        assert_eq!(
            crate::flow_runtime::floor_max(u64::MAX, 1),
            crate::flow_runtime::deadline_key(u64::MAX, 1, 0)
        );
    }

    #[test]
    fn rejects_bad_quantum() {
        let a = ConfigBuilder::default().quantum_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_ns(5_000_000).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_non_fixed_batch() {
        for bad in [0, 1, 16, 31, 33, 64] {
            let got = ConfigBuilder::default().dispatch_batch(bad).build();
            assert!(got.is_err(), "batch {bad} must fail");
        }
        let ok = ConfigBuilder::default().dispatch_batch(32).build();
        assert!(ok.is_ok());
    }

    #[test]
    /// Summary holds the fixed quantum with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("quantum=1000us"));
        assert!(s.contains("batch=32"));
    }

    #[test]
    /// Defaults match the shared header with one queue per CPU.
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().quantum_ns,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 1025);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x7000);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_VTIME_BASE as u64, 0x6800);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_STARVE_NS as u64,
            crate::flow_edf::STARVE_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_CGRP_MAX as u64,
            crate::flow_cgrp::CGRP_MAX as u64
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_CGRP_DEPTH_MAX as u64,
            crate::flow_cgrp::CGRP_DEPTH_MAX as u64
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_BW_TIMER_NS as u64,
            crate::flow_cgrp::BW_TIMER_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_BW_PERIOD_MIN_US as u64,
            crate::flow_cgrp::BW_PERIOD_MIN_US
        );
    }
}
