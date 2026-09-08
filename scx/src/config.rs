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

/* Default quanta match the BPF seeds. */
const DEF_L0_NS: u64 = crate::flow::L0_QUANTUM_NS;
const DEF_L1_NS: u64 = crate::flow::L1_QUANTUM_NS;
const DEF_L2_NS: u64 = crate::flow::L2_QUANTUM_NS;
/* Default scan and batch match the BPF bounds. */
const DEF_SCAN: u32 = STEAL_SCAN_MAX;
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Quantum of the top level in nanoseconds. */
    pub l0_ns: u64,
    /* Quantum of the middle level in nanoseconds. */
    pub l1_ns: u64,
    /* Quantum of the bottom level in nanoseconds. */
    pub l2_ns: u64,
    /* Remote cpus scanned in one dispatch pass. */
    pub steal_scan: u32,
    /* Tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            l0_ns: DEF_L0_NS,
            l1_ns: DEF_L1_NS,
            l2_ns: DEF_L2_NS,
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
        if self.l0_ns < QUANTUM_MIN_NS {
            bail!("L0 bad {}", self.l0_ns);
        }
        if self.l0_ns > QUANTUM_MAX_NS {
            bail!("L0 bad {}", self.l0_ns);
        }
        if self.l1_ns < QUANTUM_MIN_NS {
            bail!("L1 bad {}", self.l1_ns);
        }
        if self.l1_ns > QUANTUM_MAX_NS {
            bail!("L1 bad {}", self.l1_ns);
        }
        if self.l2_ns < QUANTUM_MIN_NS {
            bail!("L2 bad {}", self.l2_ns);
        }
        if self.l2_ns > QUANTUM_MAX_NS {
            bail!("L2 bad {}", self.l2_ns);
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
            "levels 0={}us 1={}us 2={}us scan={} batch={}",
            self.l0_ns / 1000,
            self.l1_ns / 1000,
            self.l2_ns / 1000,
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
    l0_ns: Option<u64>,
    l1_ns: Option<u64>,
    l2_ns: Option<u64>,
    steal_scan: Option<u32>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the top level quantum. */
    pub fn l0_ns(mut self, v: u64) -> Self {
        self.l0_ns = Some(v);
        self
    }
    /* Set the middle level quantum. */
    pub fn l1_ns(mut self, v: u64) -> Self {
        self.l1_ns = Some(v);
        self
    }
    /* Set the bottom level quantum. */
    pub fn l2_ns(mut self, v: u64) -> Self {
        self.l2_ns = Some(v);
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
            l0_ns: self.l0_ns.unwrap_or(d.l0_ns),
            l1_ns: self.l1_ns.unwrap_or(d.l1_ns),
            l2_ns: self.l2_ns.unwrap_or(d.l2_ns),
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
        let cfg = ConfigBuilder::default().l0_ns(1_000_000).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.l0_ns, 1_000_000);
        assert_eq!(cfg.l1_ns, Config::default().l1_ns);
    }

    #[test]
    fn rejects_quantum_below_floor() {
        let a = ConfigBuilder::default().l0_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().l1_ns(499_999).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_quantum_above_ceiling() {
        let a = ConfigBuilder::default().l2_ns(33_000_000).build();
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
        assert!(s.contains("0=1000us"));
        assert!(s.contains("1=2000us"));
        assert!(s.contains("2=8000us"));
        assert!(s.contains("scan=64"));
        assert!(s.contains("batch=32"));
    }
}
