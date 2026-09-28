// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use crate::flow::BW_PERIOD_MIN_US;
use crate::flow::CGRP_DEPTH_MAX;
use crate::flow::CGRP_MAX;
use crate::flow::CGRP_WEIGHT_DFL;
use crate::flow::CPUFREQ_MIN_CEIL_NS;
use crate::flow::CPUFREQ_MIN_FLOOR_NS;
use crate::flow::CPUFREQ_MIN_NS;
use crate::flow::DISPATCH_BATCH;
use crate::flow::GLOBAL_SCAN;
use crate::flow::LLC_MAX;
use crate::flow::NODE_MAX;
use crate::flow::PARK_HINT_NR;
use crate::flow::PARK_NR;
use crate::flow::SCAN_BOUND;
use crate::flow::STARVE_NS;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default tasks moved in one dispatch pass.
const DEF_BATCH: u32 = DISPATCH_BATCH;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Tasks moved in one dispatch pass.
    pub dispatch_batch: u32,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            dispatch_batch: DEF_BATCH,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// The batch stays fixed at 16 with the homeless scan at 4. Base
    /// weight stays 100 in range 1 to 10000 with a 2ms starvation
    /// floor. The tree holds 32768 nodes with a 4096 park ring.
    /// Frequency keeps 64 domain slots with a 16ms gap inside the
    /// 10ms to 32ms window. Placement scans bound 8 peers.
    /// Hierarchies hold 2048 rows with depth 8 and base
    /// share 100 plus a 1ms pool floor and 64 hint slots.
    pub fn validate(&self) -> Result<()> {
        if self.dispatch_batch != DISPATCH_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 16 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 100 || WEIGHT_MAX != 10_000 {
            bail!("weight bounds bad");
        }
        if STARVE_NS != 2_000_000 {
            bail!("starve bounds bad");
        }
        if GLOBAL_SCAN != 4 {
            bail!("global scan bad");
        }
        if NODE_MAX != 32768 {
            bail!("node bound bad");
        }
        if PARK_NR != 4096 {
            bail!("park bound bad");
        }
        if LLC_MAX != 64 {
            bail!("domain bound bad");
        }
        if CPUFREQ_MIN_NS != 16_000_000 {
            bail!("frequency gap bad");
        }
        if CPUFREQ_MIN_FLOOR_NS != 10_000_000 || CPUFREQ_MIN_CEIL_NS != 32_000_000 {
            bail!("frequency window bad");
        }
        if CPUFREQ_MIN_NS < CPUFREQ_MIN_FLOOR_NS || CPUFREQ_MIN_NS > CPUFREQ_MIN_CEIL_NS {
            bail!("frequency gap outside window");
        }
        if SCAN_BOUND != 8 {
            bail!("scan bound bad");
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
        if PARK_HINT_NR != 64 {
            bail!("hint bound bad");
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    pub fn describe(&self) -> String {
        format!("batch={}", self.dispatch_batch,)
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the fixed dispatch batch. Only 16 passes.
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            dispatch_batch: self.dispatch_batch.unwrap_or(d.dispatch_batch),
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
        let cfg = ConfigBuilder::default().dispatch_batch(16).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.dispatch_batch, 16);
    }

    #[test]
    fn rejects_non_fixed_batch() {
        for bad in [0, 1, 4, 8, 15, 17, 32, 64] {
            let got = ConfigBuilder::default().dispatch_batch(bad).build();
            assert!(got.is_err(), "batch {bad} must fail");
        }
        let ok = ConfigBuilder::default().dispatch_batch(16).build();
        assert!(ok.is_ok());
    }

    #[test]
    fn weights_match_flow() {
        assert_eq!(crate::flow_vruntime::WEIGHT_BASE, 100);
        assert_eq!(crate::flow_vruntime::WEIGHT_MIN, 1);
        assert_eq!(crate::flow_vruntime::WEIGHT_MAX, 10_000);
        assert_eq!(crate::flow_edf::STARVE_NS, 2_000_000);
        assert_eq!(crate::flow_edf::DISPATCH_BATCH, 16);
        assert_eq!(crate::flow_tree::GLOBAL_SCAN, 4);
    }

    #[test]
    /// Summary holds the fixed batch with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("batch=16"));
    }

    #[test]
    /// Defaults match the shared header with one global tree.
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().dispatch_batch,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_BATCH
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_GLOBAL_SCAN,
            crate::flow_tree::GLOBAL_SCAN
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_NODE_MAX as u64,
            crate::flow_tree::NODE_MAX
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PARK_NR as u64,
            crate::flow_tree::PARK_NR
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_LLC_MAX as u64,
            crate::flow_tree::LLC_MAX
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_CPUFREQ_MIN_NS as u64,
            crate::flow_tree::CPUFREQ_MIN_NS
        );
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_SCAN_BOUND as u64,
            crate::flow_select::SCAN_BOUND as u64
        );
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
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_PARK_HINT_NR as u64,
            crate::flow_cgrp::PARK_HINT_NR
        );
    }
}
