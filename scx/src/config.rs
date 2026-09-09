/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Validated scheduling constants for the flow scheduler.
 * The defaults match the shared BPF header. Validation
 * keeps bad values from reaching the BPF object.
 */
use crate::flow::DISPATCH_BATCH;
use crate::flow::EST_MAX_NS;
use crate::flow::EST_MIN_NS;
use crate::flow::TQ_MAX_NS;
use crate::flow::TQ_MIN_NS;
use crate::flow::TQ_SEED_NS;
use anyhow::bail;
use anyhow::Result;

/* Default seed of the per Cpu mean in nanos. */
const DEF_SEED_NS: u64 = TQ_SEED_NS;
/* Default floor of the per Cpu mean in nanos. */
const DEF_MIN_NS: u64 = TQ_MIN_NS;
/* Default ceiling of the per Cpu mean in nanos. */
const DEF_MAX_NS: u64 = TQ_MAX_NS;
/* Default tasks moved in one dispatch pass. */
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Seed of the per Cpu mean in nanos. */
    pub tq_seed_ns: u64,
    /* Floor of the per Cpu mean in nanos. */
    pub tq_min_ns: u64,
    /* Ceiling of the per Cpu mean in nanos. */
    pub tq_max_ns: u64,
    /* Tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            tq_seed_ns: DEF_SEED_NS,
            tq_min_ns: DEF_MIN_NS,
            tq_max_ns: DEF_MAX_NS,
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
        if self.tq_seed_ns != TQ_SEED_NS {
            bail!("seed bad {}", self.tq_seed_ns);
        }
        if self.tq_min_ns != TQ_MIN_NS {
            bail!("floor bad {}", self.tq_min_ns);
        }
        if self.tq_max_ns != TQ_MAX_NS {
            bail!("ceiling bad {}", self.tq_max_ns);
        }
        if self.tq_min_ns >= self.tq_max_ns {
            bail!("range bad {}", self.tq_min_ns);
        }
        if self.tq_seed_ns < self.tq_min_ns {
            bail!("seed bad {}", self.tq_seed_ns);
        }
        if self.tq_seed_ns > self.tq_max_ns {
            bail!("seed bad {}", self.tq_seed_ns);
        }
        if EST_MIN_NS != 1 {
            bail!("est floor bad {}", EST_MIN_NS);
        }
        if EST_MAX_NS != 1_000_000_000 {
            bail!("est ceiling bad {}", EST_MAX_NS);
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
            "seed={}us floor={}us ceiling={}us batch={}",
            self.tq_seed_ns / 1000,
            self.tq_min_ns / 1000,
            self.tq_max_ns / 1000,
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
    tq_seed_ns: Option<u64>,
    tq_min_ns: Option<u64>,
    tq_max_ns: Option<u64>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the mean seed. */
    pub fn tq_seed_ns(mut self, v: u64) -> Self {
        self.tq_seed_ns = Some(v);
        self
    }
    /* Set the mean floor. */
    pub fn tq_min_ns(mut self, v: u64) -> Self {
        self.tq_min_ns = Some(v);
        self
    }
    /* Set the mean ceiling. */
    pub fn tq_max_ns(mut self, v: u64) -> Self {
        self.tq_max_ns = Some(v);
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
        let seed = self.tq_seed_ns.unwrap_or(d.tq_seed_ns);
        let min = self.tq_min_ns.unwrap_or(d.tq_min_ns);
        let max = self.tq_max_ns.unwrap_or(d.tq_max_ns);
        let batch = self.dispatch_batch.unwrap_or(d.dispatch_batch);
        let cfg = Config {
            tq_seed_ns: seed,
            tq_min_ns: min,
            tq_max_ns: max,
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
        let cfg = ConfigBuilder::default().dispatch_batch(16).build();
        let cfg = cfg.unwrap();
        assert_eq!(cfg.dispatch_batch, 16);
        assert_eq!(cfg.tq_seed_ns, Config::default().tq_seed_ns);
    }

    #[test]
    fn seed_floor_ceiling_match_flow() {
        assert_eq!(Config::default().tq_seed_ns, crate::flow_mean::TQ_SEED_NS);
        assert_eq!(Config::default().tq_min_ns, crate::flow_mean::TQ_MIN_NS);
        assert_eq!(Config::default().tq_max_ns, crate::flow_mean::TQ_MAX_NS);
    }

    #[test]
    fn rejects_bad_seed_floor_ceiling() {
        let a = ConfigBuilder::default().tq_seed_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().tq_min_ns(1).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().tq_max_ns(1).build();
        assert!(c.is_err());
    }

    #[test]
    fn rejects_zero_and_large_batch() {
        let a = ConfigBuilder::default().dispatch_batch(0).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().dispatch_batch(33).build();
        assert!(b.is_err());
    }

    #[test]
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("seed=8000us"));
        assert!(s.contains("floor=500us"));
        assert!(s.contains("ceiling=32000us"));
        assert!(s.contains("batch=32"));
    }
}
