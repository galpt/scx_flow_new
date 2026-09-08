/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Validated scheduling constants for the flow scheduler.
 * The defaults match the shared BPF header. Validation
 * keeps bad values from reaching the BPF object.
 */
use crate::flow::DISPATCH_BATCH;
use crate::flow::QUANTUM_MAX_NS;
use crate::flow::QUANTUM_MIN_NS;
use crate::flow::STEAL_SCAN_MAX;
use anyhow::bail;
use anyhow::Result;

/* Default seed matches the BPF seed. */
const DEF_SEED_NS: u64 = crate::flow::QUANTUM_SEED_NS;
/* Default scan and batch match the BPF bounds. */
const DEF_SCAN: u32 = STEAL_SCAN_MAX;
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Seed quantum in nanoseconds. */
    pub quantum_seed_ns: u64,
    /* Remote cpus scanned in one dispatch pass. */
    pub steal_scan: u32,
    /* Tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            quantum_seed_ns: DEF_SEED_NS,
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
        if self.quantum_seed_ns < QUANTUM_MIN_NS {
            bail!("seed bad {}", self.quantum_seed_ns);
        }
        if self.quantum_seed_ns > QUANTUM_MAX_NS {
            bail!("seed bad {}", self.quantum_seed_ns);
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
            "seed={}us scan={} batch={}",
            self.quantum_seed_ns / 1000,
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
    quantum_seed_ns: Option<u64>,
    steal_scan: Option<u32>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the seed quantum. */
    pub fn quantum_seed_ns(mut self, v: u64) -> Self {
        self.quantum_seed_ns = Some(v);
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
        let batch = d.dispatch_batch;
        let scan = d.steal_scan;
        let cfg = Config {
            quantum_seed_ns: self.quantum_seed_ns.unwrap_or(d.quantum_seed_ns),
            steal_scan: self.steal_scan.unwrap_or(scan),
            dispatch_batch: self.dispatch_batch.unwrap_or(batch),
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
        let cfg = ConfigBuilder::default().quantum_seed_ns(2_000_000).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.quantum_seed_ns, 2_000_000);
        assert_eq!(cfg.steal_scan, Config::default().steal_scan);
    }

    #[test]
    fn seed_matches_flow_seed() {
        assert_eq!(
            Config::default().quantum_seed_ns,
            crate::flow::QUANTUM_SEED_NS
        );
        assert_eq!(
            Config::default().quantum_seed_ns,
            crate::flow::seed_quantum()
        );
    }

    #[test]
    fn rejects_seed_below_floor() {
        let a = ConfigBuilder::default().quantum_seed_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_seed_ns(499_999).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_seed_above_ceiling() {
        let a = ConfigBuilder::default().quantum_seed_ns(33_000_000).build();
        assert!(a.is_err());
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
        assert!(s.contains("seed=2000us"));
        assert!(s.contains("scan=64"));
        assert!(s.contains("batch=32"));
    }
}
