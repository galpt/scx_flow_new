// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults that match intf.h.

use crate::flow::DISPATCH_BATCH;
use crate::flow::DUTY_BATCH;
use crate::flow::DUTY_FAST;
use crate::flow::DUTY_SHIFT;
use crate::flow::LTARGET_NS;
use crate::flow::MICRO_QUANTUM_NS;
use crate::flow::PROB_CYCLES;
use crate::flow::QMAX_NS;
use crate::flow::QMIN_NS;
use crate::flow::SLOT_BUDGET;
use crate::flow::SLOT_D;
use crate::flow::STARVE_NS;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default least slice in nanos.
const DEF_QMIN_NS: u64 = QMIN_NS;
/// Default largest slice in nanos.
const DEF_QMAX_NS: u64 = QMAX_NS;
/// Default latency target in nanos.
const DEF_LTARGET_NS: u64 = LTARGET_NS;
/// Default micro quantum in nanos.
const DEF_MICRO_QUANTUM_NS: u64 = MICRO_QUANTUM_NS;
/// Default tasks moved in one dispatch pass.
const DEF_BATCH: u32 = DISPATCH_BATCH;
/// Default tasks moved by one fast trip.
const DEF_SLOT_D: u32 = SLOT_D;
/// Default tasks moved by one dispatch pass.
const DEF_SLOT_BUDGET: u32 = SLOT_BUDGET;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Least slice in nanos.
    pub qmin_ns: u64,
    /// Largest slice in nanos.
    pub qmax_ns: u64,
    /// Latency target in nanos.
    pub ltarget_ns: u64,
    /// Micro quantum in nanos.
    pub micro_quantum_ns: u64,
    /// Tasks moved in one dispatch pass.
    pub dispatch_batch: u32,
    /// Tasks moved by one fast trip.
    pub slot_d: u32,
    /// Tasks moved by one dispatch pass.
    pub slot_budget: u32,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            qmin_ns: DEF_QMIN_NS,
            qmax_ns: DEF_QMAX_NS,
            ltarget_ns: DEF_LTARGET_NS,
            micro_quantum_ns: DEF_MICRO_QUANTUM_NS,
            dispatch_batch: DEF_BATCH,
            slot_d: DEF_SLOT_D,
            slot_budget: DEF_SLOT_BUDGET,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds the BPF side relies on.
    /// An invalid value is a programming fault, not a runtime state.
    /// Slices span 250us to 15ms with a 5ms target and a 500us quantum.
    /// The batch stays fixed at 32, the fast trip at 4, and the budget
    /// at 32. Weights span 1 to 10000 with base 100.
    pub fn validate(&self) -> Result<()> {
        if self.qmin_ns != QMIN_NS {
            bail!("qmin bad {}", self.qmin_ns);
        }
        if self.qmin_ns != 250_000 {
            bail!("qmin bad {}", self.qmin_ns);
        }
        if self.qmax_ns != QMAX_NS {
            bail!("qmax bad {}", self.qmax_ns);
        }
        if self.qmax_ns != 15_000_000 {
            bail!("qmax bad {}", self.qmax_ns);
        }
        if self.ltarget_ns != LTARGET_NS {
            bail!("ltarget bad {}", self.ltarget_ns);
        }
        if self.ltarget_ns != 5_000_000 {
            bail!("ltarget bad {}", self.ltarget_ns);
        }
        if self.micro_quantum_ns != MICRO_QUANTUM_NS {
            bail!("quantum bad {}", self.micro_quantum_ns);
        }
        if self.micro_quantum_ns != 500_000 {
            bail!("quantum bad {}", self.micro_quantum_ns);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 100 || WEIGHT_MAX != 10_000 {
            bail!("weight bounds bad");
        }
        if DUTY_SHIFT != 3 || DUTY_FAST != 38 || DUTY_BATCH != 128 {
            bail!("duty bounds bad");
        }
        if PROB_CYCLES != 2 || STARVE_NS != 1_500_000 {
            bail!("admit bounds bad");
        }
        if self.dispatch_batch != DISPATCH_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 32 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.slot_d != SLOT_D {
            bail!("slot trip bad {}", self.slot_d);
        }
        if self.slot_d != 4 {
            bail!("slot trip bad {}", self.slot_d);
        }
        if self.slot_budget != SLOT_BUDGET {
            bail!("slot budget bad {}", self.slot_budget);
        }
        if self.slot_budget != 32 {
            bail!("slot budget bad {}", self.slot_budget);
        }
        Ok(())
    }

    /// One line summary of the constants for the start log.
    /// Values print in microseconds for brevity.
    pub fn describe(&self) -> String {
        format!(
            "slice={}-{}us target={}us batch={}",
            self.qmin_ns / 1000,
            self.qmax_ns / 1000,
            self.ltarget_ns / 1000,
            self.dispatch_batch,
        )
    }
}

/// Builder for Config used only by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    qmin_ns: Option<u64>,
    qmax_ns: Option<u64>,
    ltarget_ns: Option<u64>,
    micro_quantum_ns: Option<u64>,
    dispatch_batch: Option<u32>,
    slot_d: Option<u32>,
    slot_budget: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the least slice.
    pub fn qmin_ns(mut self, v: u64) -> Self {
        self.qmin_ns = Some(v);
        self
    }
    /// Set the largest slice.
    pub fn qmax_ns(mut self, v: u64) -> Self {
        self.qmax_ns = Some(v);
        self
    }
    /// Set the latency target.
    pub fn ltarget_ns(mut self, v: u64) -> Self {
        self.ltarget_ns = Some(v);
        self
    }
    /// Set the micro quantum.
    pub fn micro_quantum_ns(mut self, v: u64) -> Self {
        self.micro_quantum_ns = Some(v);
        self
    }
    /// Set the fixed dispatch batch. Only 32 passes.
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /// Set the fixed fast trip. Only 4 passes.
    pub fn slot_d(mut self, v: u32) -> Self {
        self.slot_d = Some(v);
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
            qmin_ns: self.qmin_ns.unwrap_or(d.qmin_ns),
            qmax_ns: self.qmax_ns.unwrap_or(d.qmax_ns),
            ltarget_ns: self.ltarget_ns.unwrap_or(d.ltarget_ns),
            micro_quantum_ns: self.micro_quantum_ns.unwrap_or(d.micro_quantum_ns),
            dispatch_batch: self.dispatch_batch.unwrap_or(d.dispatch_batch),
            slot_d: self.slot_d.unwrap_or(d.slot_d),
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
        assert_eq!(cfg.qmin_ns, Config::default().qmin_ns);
    }

    #[test]
    fn slot_consts_are_fixed() {
        assert_eq!(Config::default().slot_d, 4);
        assert_eq!(Config::default().slot_budget, 32);
        assert_eq!(Config::default().slot_d, crate::flow_slot::SLOT_D);
        assert_eq!(Config::default().slot_budget, crate::flow_slot::SLOT_BUDGET);
    }

    #[test]
    fn rejects_non_fixed_slot() {
        for bad in [0, 1, 3, 5, 8, 32] {
            let got = ConfigBuilder::default().slot_d(bad).build();
            assert!(got.is_err(), "slot trip {bad} must fail");
        }
        let ok = ConfigBuilder::default().slot_d(4).build();
        assert!(ok.is_ok());
        for bad in [0, 4, 16, 31, 33, 64] {
            let got = ConfigBuilder::default().slot_budget(bad).build();
            assert!(got.is_err(), "slot budget {bad} must fail");
        }
        let ok = ConfigBuilder::default().slot_budget(32).build();
        assert!(ok.is_ok());
    }

    #[test]
    fn slice_matches_flow() {
        assert_eq!(Config::default().qmin_ns, crate::flow_slice::QMIN_NS);
        assert_eq!(crate::flow_slice::QMIN_NS, 250_000);
        assert_eq!(crate::flow_slice::QMAX_NS, 15_000_000);
        assert_eq!(crate::flow_slice::LTARGET_NS, 5_000_000);
        assert_eq!(crate::flow_slice::MICRO_QUANTUM_NS, 500_000);
    }

    #[test]
    fn rejects_bad_slice() {
        let a = ConfigBuilder::default().qmin_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().qmax_ns(8_000_000).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().ltarget_ns(20_000_000).build();
        assert!(c.is_err());
        let d = ConfigBuilder::default().micro_quantum_ns(1).build();
        assert!(d.is_err());
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
    /// Summary holds the dynamic bounds with no knob.
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("slice=250-15000us"));
        assert!(s.contains("target=5000us"));
        assert!(s.contains("batch=32"));
    }

    #[test]
    /// Defaults match the shared header with two queues per CPU.
    fn defaults_match_intf_h() {
        assert_eq!(
            Config::default().qmin_ns,
            crate::bpf_intf::flow_consts_FLOW_QMIN_NS as u64
        );
        assert_eq!(
            Config::default().qmax_ns,
            crate::bpf_intf::flow_consts_FLOW_QMAX_NS as u64
        );
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 2049);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x7000);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_FAST_BASE as u64, 0x6000);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_VTIME_BASE as u64, 0x6800);
    }
}
