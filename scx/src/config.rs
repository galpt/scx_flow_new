/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Validated scheduling constants for the flow scheduler.
 * The defaults match the shared BPF header. Validation
 * keeps bad values from reaching the BPF object.
 */
use crate::flow::DISPATCH_BATCH;
use crate::flow::QUANTUM_MAX0_NS;
use crate::flow::QUANTUM_MAX1_NS;
use crate::flow::QUANTUM_MAX2_NS;
use crate::flow::QUANTUM_MIN0_NS;
use crate::flow::QUANTUM_MIN1_NS;
use crate::flow::QUANTUM_MIN2_NS;
use crate::flow::STEAL_SCAN_MAX;
use anyhow::bail;
use anyhow::Result;

/* Default seeds match the BPF seeds per queue. */
const DEF_SEED0_NS: u64 = crate::flow::QUANTUM_SEED0_NS;
const DEF_SEED1_NS: u64 = crate::flow::QUANTUM_SEED1_NS;
const DEF_SEED2_NS: u64 = crate::flow::QUANTUM_SEED2_NS;
/* Default scan and batch match the BPF bounds. */
const DEF_SCAN: u32 = STEAL_SCAN_MAX;
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Seed quantum of the first queue in nanoseconds. */
    pub quantum_seed0_ns: u64,
    /* Seed quantum of the second queue in nanoseconds. */
    pub quantum_seed1_ns: u64,
    /* Seed quantum of the third queue in nanoseconds. */
    pub quantum_seed2_ns: u64,
    /* Remote cpus scanned in one dispatch pass. */
    pub steal_scan: u32,
    /* Tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            quantum_seed0_ns: DEF_SEED0_NS,
            quantum_seed1_ns: DEF_SEED1_NS,
            quantum_seed2_ns: DEF_SEED2_NS,
            steal_scan: DEF_SCAN,
            dispatch_batch: DEF_BATCH,
        }
    }
}

impl Config {
    /*
     * Validate the constants against the bounds the BPF
     * side relies on. An invalid value is a programming
     * fault, not a runtime state.
     */
    pub fn validate(&self) -> Result<()> {
        if self.quantum_seed0_ns < QUANTUM_MIN0_NS {
            bail!("seed0 bad {}", self.quantum_seed0_ns);
        }
        if self.quantum_seed0_ns > QUANTUM_MAX0_NS {
            bail!("seed0 bad {}", self.quantum_seed0_ns);
        }
        if self.quantum_seed1_ns < QUANTUM_MIN1_NS {
            bail!("seed1 bad {}", self.quantum_seed1_ns);
        }
        if self.quantum_seed1_ns > QUANTUM_MAX1_NS {
            bail!("seed1 bad {}", self.quantum_seed1_ns);
        }
        if self.quantum_seed2_ns < QUANTUM_MIN2_NS {
            bail!("seed2 bad {}", self.quantum_seed2_ns);
        }
        if self.quantum_seed2_ns > QUANTUM_MAX2_NS {
            bail!("seed2 bad {}", self.quantum_seed2_ns);
        }
        if self.steal_scan == 0 {
            bail!("scan bad {}", self.steal_scan);
        }
        if self.steal_scan > STEAL_SCAN_MAX {
            bail!("scan bad {}", self.steal_scan);
        }
        if self.dispatch_batch == 0 {
            bail!("batch bad {}", self.dispatch_batch);
        }
        if self.dispatch_batch > DISPATCH_BATCH {
            bail!("batch bad {}", self.dispatch_batch);
        }
        Ok(())
    }

    /*
     * One line summary of the constants for the start
     * log. Values print in microseconds for brevity.
     */
    pub fn describe(&self) -> String {
        format!(
            "seed0={}us seed1={}us seed2={}us scan={} batch={}",
            self.quantum_seed0_ns / 1000,
            self.quantum_seed1_ns / 1000,
            self.quantum_seed2_ns / 1000,
            self.steal_scan,
            self.dispatch_batch,
        )
    }
}

/*
 * Builder for Config used only by tests. Production
 * uses Config default directly. Each setter is optional
 * and missing fields fall back to the defaults.
 */
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    quantum_seed0_ns: Option<u64>,
    quantum_seed1_ns: Option<u64>,
    quantum_seed2_ns: Option<u64>,
    steal_scan: Option<u32>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the first queue seed. */
    pub fn quantum_seed0_ns(mut self, v: u64) -> Self {
        self.quantum_seed0_ns = Some(v);
        self
    }
    /* Set the second queue seed. */
    pub fn quantum_seed1_ns(mut self, v: u64) -> Self {
        self.quantum_seed1_ns = Some(v);
        self
    }
    /* Set the third queue seed. */
    pub fn quantum_seed2_ns(mut self, v: u64) -> Self {
        self.quantum_seed2_ns = Some(v);
        self
    }
    /* Set the steal scan bound. */
    pub fn steal_scan(mut self, v: u32) -> Self {
        self.steal_scan = Some(v);
        self
    }
    /* Set the dispatch batch bound. */
    pub fn dispatch_batch(mut self, v: u32) -> Self {
        self.dispatch_batch = Some(v);
        self
    }
    /* Assemble and validate the result. */
    pub fn build(self) -> Result<Config> {
        let d = Config::default();
        let s0 = self.quantum_seed0_ns.unwrap_or(d.quantum_seed0_ns);
        let s1 = self.quantum_seed1_ns.unwrap_or(d.quantum_seed1_ns);
        let s2 = self.quantum_seed2_ns.unwrap_or(d.quantum_seed2_ns);
        let scan = self.steal_scan.unwrap_or(d.steal_scan);
        let batch = self.dispatch_batch.unwrap_or(d.dispatch_batch);
        let cfg = Config {
            quantum_seed0_ns: s0,
            quantum_seed1_ns: s1,
            quantum_seed2_ns: s2,
            steal_scan: scan,
            dispatch_batch: batch,
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
    fn builder_overrides_one_field() {
        let cfg = ConfigBuilder::default().quantum_seed1_ns(2_000_000).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.quantum_seed1_ns, 2_000_000);
        assert_eq!(cfg.steal_scan, Config::default().steal_scan);
    }

    #[test]
    fn seeds_match_flow_seeds() {
        assert_eq!(
            Config::default().quantum_seed0_ns,
            crate::flow::QUANTUM_SEED0_NS
        );
        assert_eq!(
            Config::default().quantum_seed1_ns,
            crate::flow::QUANTUM_SEED1_NS
        );
        assert_eq!(
            Config::default().quantum_seed2_ns,
            crate::flow::QUANTUM_SEED2_NS
        );
        assert_eq!(
            Config::default().quantum_seed0_ns,
            crate::flow::seed_quantum(0)
        );
        assert_eq!(
            Config::default().quantum_seed1_ns,
            crate::flow::seed_quantum(1)
        );
        assert_eq!(
            Config::default().quantum_seed2_ns,
            crate::flow::seed_quantum(2)
        );
    }

    #[test]
    fn rejects_seed_below_floor() {
        let a = ConfigBuilder::default().quantum_seed0_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_seed0_ns(499_999).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().quantum_seed1_ns(999_999).build();
        assert!(c.is_err());
        let d = ConfigBuilder::default().quantum_seed2_ns(3_999_999).build();
        assert!(d.is_err());
    }

    #[test]
    fn rejects_seed_above_ceiling() {
        let a = ConfigBuilder::default().quantum_seed0_ns(5_000_000).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_seed1_ns(9_000_000).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default()
            .quantum_seed2_ns(33_000_000)
            .build();
        assert!(c.is_err());
    }

    #[test]
    fn rejects_zero_scan_and_batch() {
        let a = ConfigBuilder::default().steal_scan(0).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().dispatch_batch(0).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_scan_and_batch_above_cap() {
        let a = ConfigBuilder::default().steal_scan(65).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().dispatch_batch(33).build();
        assert!(b.is_err());
    }

    #[test]
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("seed0=1000us"));
        assert!(s.contains("seed1=2000us"));
        assert!(s.contains("seed2=8000us"));
        assert!(s.contains("scan=64"));
        assert!(s.contains("batch=32"));
    }
}
