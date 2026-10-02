// SPDX-License-Identifier: GPL-2.0
//! Validated scheduling constants for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the validated constants with defaults matching the header.

use crate::flow::ADMIT_PERMILLE;
use crate::flow::CAP_BASE;
use crate::flow::DISPATCH_FLOOD_PROBES;
use crate::flow::DISPATCH_FLOOD_QUEUED;
use crate::flow::DISPATCH_PROBES;
use crate::flow::HINT_MAX;
use crate::flow::PERIOD_NS;
use crate::flow::QUANTUM_NS;
use crate::flow::WEIGHT_BASE;
use crate::flow::WEIGHT_MAX;
use crate::flow::WEIGHT_MIN;
use anyhow::Result;
use anyhow::bail;

/// Default base slice in nanos.
const DEF_QUANTUM_NS: u64 = QUANTUM_NS;
/// Default dispatch batch for the ops table. Mirrors the header batch
/// so the ops table holds every pass.
const DEF_BATCH: u32 = 16;
/// Default flood stall budget kept as ABI with no core effect.
/// Ordered drains sixteen per pass with the fallback on empty plus
/// corrupt plus stale.
const DEF_FLOOD_PROBES: u32 = 4;
/// Default flood queue bound kept as ABI with no core effect.
/// Marks deep backlog shape solely with ordered still draining sixteen.
const DEF_FLOOD_QUEUED: u32 = 128;

/// Validated scheduling constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Base slice in nanos. Always two milliseconds.
    pub quantum_ns: u64,
    /// Dispatch batch for the ops table. Always sixteen.
    pub dispatch_batch: u32,
}

impl Default for Config {
    /// Compile time defaults from the shared header.
    fn default() -> Self {
        Self {
            quantum_ns: DEF_QUANTUM_NS,
            dispatch_batch: DEF_BATCH,
        }
    }
}

impl Config {
    /// Validate the constants against the bounds used by the core.
    /// Faulty values mark a programming fault.
    /// The slice stays at two milliseconds with base weight one hundred
    /// twenty eight in range one to sixteen thousand. The period stays
    /// at sixteen milliseconds. The batch stays at sixteen with ordered
    /// filling the batch and the fallback solely on empty plus corrupt
    /// plus stale. Flood bound stays at four plus one hundred twenty
    /// eight as ABI deep backlog shape with a twenty probe cap kept as
    /// ABI. Admission
    /// holds use under nine hundred fifty per mille with base capacity
    /// one thousand twenty four. Queues hold five hundred twelve local,
    /// eight node, machine, overflow. Hints hold four
    /// thousand ninety six flat rows.
    pub fn validate(&self) -> Result<()> {
        if self.quantum_ns != QUANTUM_NS {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if self.quantum_ns != 2_000_000 {
            bail!("quantum bad {}", self.quantum_ns);
        }
        if WEIGHT_MIN != 1 || WEIGHT_BASE != 128 || WEIGHT_MAX != 16_384 {
            bail!("weight bounds bad");
        }
        if PERIOD_NS != 16_000_000 {
            bail!("period bounds bad");
        }
        if self.dispatch_batch != DEF_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch != 16 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if ADMIT_PERMILLE != 950 {
            bail!("admission bound bad");
        }
        if CAP_BASE != 1024 {
            bail!("capacity base bad");
        }
        if HINT_MAX != 4096 {
            bail!("hint bound bad");
        }
        if DISPATCH_FLOOD_PROBES != 4 {
            bail!("flood probes bad");
        }
        if DEF_FLOOD_PROBES != 4 {
            bail!("flood probes bad");
        }
        if DISPATCH_FLOOD_QUEUED != 128 {
            bail!("flood queued bad");
        }
        if DEF_FLOOD_QUEUED != 128 {
            bail!("flood queued bad");
        }
        if DISPATCH_PROBES != 20 {
            bail!("probe bound bad");
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

/// Builder for Config used solely by tests.
/// Production uses Config default directly.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_ns: Option<u64>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /// Set the base slice.
    pub fn quantum_ns(mut self, v: u64) -> Self {
        self.quantum_ns = Some(v);
        self
    }
    /// Set the fixed dispatch batch. Solely sixteen passes.
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /// Assemble and validate the result.
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let cfg = Config {
            quantum_ns: self.quantum_ns.unwrap_or(d.quantum_ns),
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
    fn rejects_bad_quantum() {
        let a = ConfigBuilder::default().quantum_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_ns(1_000_000).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_non_fixed_batch() {
        for bad in [0, 1, 8, 15, 17, 32] {
            let got = ConfigBuilder::default().dispatch_batch(bad).build();
            assert!(got.is_err(), "batch {bad} must fail");
        }
        let ok = ConfigBuilder::default().dispatch_batch(16).build();
        assert!(ok.is_ok());
    }

    #[test]
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("quantum=2000us"));
        assert!(s.contains("batch=16"));
    }

    #[test]
    fn defaults_match_intf_h() {
        assert_eq!(
            DEF_BATCH,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH
        );
        assert_eq!(DEF_BATCH, 16);
        assert_eq!(
            DEF_FLOOD_PROBES,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_FLOOD_PROBES
        );
        assert_eq!(DEF_FLOOD_PROBES, 4);
        assert_eq!(
            DEF_FLOOD_QUEUED,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_FLOOD_QUEUED
        );
        assert_eq!(DEF_FLOOD_QUEUED, 128);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_PROBES as usize,
            crate::flow::DISPATCH_PROBES
        );
        assert_eq!(
            Config::default().quantum_ns,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(
            crate::flow::QUANTUM_MID_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_MID_NS as u64
        );
        assert_eq!(crate::flow::QUANTUM_MID_NS, 4_000_000);
        assert_eq!(
            crate::flow::QUANTUM_MAX_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_MAX_NS as u64
        );
        assert_eq!(crate::flow::QUANTUM_MAX_NS, 8_000_000);
        assert_eq!(
            crate::flow::QUANTUM_MAX_STEP as u64,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_MAX_STEP as u64
        );
        assert_eq!(crate::flow::QUANTUM_MAX_STEP, 2);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64, 522);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64, 0x5A01);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_MACHINE as u64, 0x5A00);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_LOCAL_BASE as u64, 0x5100);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_NODE_BASE as u64, 0x5900);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64,
            crate::flow::cgrp::HINT_MAX
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn flood_and_drain_bounds_hold() {
        assert_eq!(DISPATCH_FLOOD_PROBES, 4);
        assert_eq!(DISPATCH_FLOOD_QUEUED, 128);
        assert_eq!(DISPATCH_PROBES, 20);
        assert_eq!(DEF_BATCH, 16);
        assert!(DISPATCH_FLOOD_PROBES < DISPATCH_PROBES);
        assert!(DEF_BATCH as usize <= DISPATCH_PROBES);
        // Ordered fills the batch per pass with the fallback solely on
        // empty plus corrupt plus stale, so deep backlog still drains
        // sixteen per pass in order.
        let slack = DEF_BATCH - DEF_FLOOD_PROBES;
        assert_eq!(slack, 12);
        assert_eq!(DEF_FLOOD_PROBES + (DEF_BATCH >> 2), 8);
    }
}
