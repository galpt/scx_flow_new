/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Validated scheduling constants for the flow scheduler.
 * The defaults match the shared BPF header. Validation
 * keeps bad values from reaching the BPF object.
 */
use crate::flow::DEFICIT_SERVES;
use crate::flow::DISPATCH_BATCH;
use crate::flow::PREEMPT_GAP_NS;
use crate::flow::PROMOTE_STREAK;
use crate::flow::QUANTUM_TIER0_NS;
use crate::flow::QUANTUM_TIER1_NS;
use crate::flow::SHORT_BOUND_NS;
use crate::flow::STREAK_CAP;
use anyhow::bail;
use anyhow::Result;

/* Default slice of the interactive tier in nanos. */
const DEF_TIER0_NS: u64 = QUANTUM_TIER0_NS;
/* Default slice of the batch tier in nanos. */
const DEF_TIER1_NS: u64 = QUANTUM_TIER1_NS;
/* Default short bound in nanos. */
const DEF_SHORT_NS: u64 = SHORT_BOUND_NS;
/* Default streak that earns a move up. */
const DEF_STREAK: u32 = PROMOTE_STREAK;
/* Default cap of the block streak. */
const DEF_CAP: u32 = STREAK_CAP;
/* Default interactive serves per batch serve. */
const DEF_DEFICIT: u64 = DEFICIT_SERVES;
/* Default gap between busy preemptions in nanos. */
const DEF_GAP_NS: u64 = PREEMPT_GAP_NS;
/* Default tasks moved in one dispatch pass. */
const DEF_BATCH: u32 = DISPATCH_BATCH;

/* Validated scheduling constants. */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /* Fixed slice of the interactive tier in nanos. */
    pub quantum_tier0_ns: u64,
    /* Fixed slice of the batch tier in nanos. */
    pub quantum_tier1_ns: u64,
    /* Burst length that counts as short in nanos. */
    pub short_bound_ns: u64,
    /* Short blocks that earn a move up. */
    pub promote_streak: u32,
    /* Upper bound of the block streak. */
    pub streak_cap: u32,
    /* Interactive serves per batch serve. */
    pub deficit_serves: u64,
    /* Minimum gap between busy preemptions in nanos. */
    pub preempt_gap_ns: u64,
    /* Tasks moved in one dispatch pass. */
    pub dispatch_batch: u32,
}

impl Default for Config {
    /* Compile time defaults from the shared header. */
    fn default() -> Self {
        Self {
            quantum_tier0_ns: DEF_TIER0_NS,
            quantum_tier1_ns: DEF_TIER1_NS,
            short_bound_ns: DEF_SHORT_NS,
            promote_streak: DEF_STREAK,
            streak_cap: DEF_CAP,
            deficit_serves: DEF_DEFICIT,
            preempt_gap_ns: DEF_GAP_NS,
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
        if self.quantum_tier0_ns != QUANTUM_TIER0_NS {
            bail!("tier0 bad {}", self.quantum_tier0_ns);
        }
        if self.quantum_tier1_ns != QUANTUM_TIER1_NS {
            bail!("tier1 bad {}", self.quantum_tier1_ns);
        }
        if self.short_bound_ns != SHORT_BOUND_NS {
            bail!("short bad {}", self.short_bound_ns);
        }
        if self.promote_streak != PROMOTE_STREAK {
            bail!("streak bad {}", self.promote_streak);
        }
        if self.promote_streak == 0 {
            bail!("streak bad {}", self.promote_streak);
        }
        if self.streak_cap != STREAK_CAP {
            bail!("cap bad {}", self.streak_cap);
        }
        if self.streak_cap < self.promote_streak {
            bail!("cap bad {}", self.streak_cap);
        }
        if self.deficit_serves != DEFICIT_SERVES {
            bail!("deficit bad {}", self.deficit_serves);
        }
        if self.deficit_serves == 0 {
            bail!("deficit bad {}", self.deficit_serves);
        }
        if self.preempt_gap_ns != PREEMPT_GAP_NS {
            bail!("gap bad {}", self.preempt_gap_ns);
        }
        if self.preempt_gap_ns == 0 {
            bail!("gap bad {}", self.preempt_gap_ns);
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
            "tier0={}us tier1={}us short={}us streak={} cap={} \
            deficit={} gap={}us batch={}",
            self.quantum_tier0_ns / 1000,
            self.quantum_tier1_ns / 1000,
            self.short_bound_ns / 1000,
            self.promote_streak,
            self.streak_cap,
            self.deficit_serves,
            self.preempt_gap_ns / 1000,
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
    quantum_tier0_ns: Option<u64>,
    quantum_tier1_ns: Option<u64>,
    short_bound_ns: Option<u64>,
    promote_streak: Option<u32>,
    streak_cap: Option<u32>,
    deficit_serves: Option<u64>,
    preempt_gap_ns: Option<u64>,
    dispatch_batch: Option<u32>,
}

#[cfg(test)]
impl ConfigBuilder {
    /* Set the interactive tier slice. */
    pub fn quantum_tier0_ns(mut self, v: u64) -> Self {
        self.quantum_tier0_ns = Some(v);
        self
    }
    /* Set the batch tier slice. */
    pub fn quantum_tier1_ns(mut self, v: u64) -> Self {
        self.quantum_tier1_ns = Some(v);
        self
    }
    /* Set the short bound. */
    pub fn short_bound_ns(mut self, v: u64) -> Self {
        self.short_bound_ns = Some(v);
        self
    }
    /* Set the promotion streak. */
    pub fn promote_streak(mut self, v: u32) -> Self {
        self.promote_streak = Some(v);
        self
    }
    /* Set the streak cap. */
    pub fn streak_cap(mut self, v: u32) -> Self {
        self.streak_cap = Some(v);
        self
    }
    /* Set the deficit serves. */
    pub fn deficit_serves(mut self, v: u64) -> Self {
        self.deficit_serves = Some(v);
        self
    }
    /* Set the preempt gap. */
    pub fn preempt_gap_ns(mut self, v: u64) -> Self {
        self.preempt_gap_ns = Some(v);
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
        let t0 = self.quantum_tier0_ns.unwrap_or(d.quantum_tier0_ns);
        let t1 = self.quantum_tier1_ns.unwrap_or(d.quantum_tier1_ns);
        let short = self.short_bound_ns.unwrap_or(d.short_bound_ns);
        let streak = self.promote_streak.unwrap_or(d.promote_streak);
        let cap = self.streak_cap.unwrap_or(d.streak_cap);
        let deficit = self.deficit_serves.unwrap_or(d.deficit_serves);
        let gap = self.preempt_gap_ns.unwrap_or(d.preempt_gap_ns);
        let batch = self.dispatch_batch.unwrap_or(d.dispatch_batch);
        let cfg = Config {
            quantum_tier0_ns: t0,
            quantum_tier1_ns: t1,
            short_bound_ns: short,
            promote_streak: streak,
            streak_cap: cap,
            deficit_serves: deficit,
            preempt_gap_ns: gap,
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
        assert_eq!(cfg.quantum_tier0_ns, Config::default().quantum_tier0_ns);
    }

    #[test]
    fn tiers_match_flow_tiers() {
        assert_eq!(
            Config::default().quantum_tier0_ns,
            crate::flow::QUANTUM_TIER0_NS
        );
        assert_eq!(
            Config::default().quantum_tier1_ns,
            crate::flow::QUANTUM_TIER1_NS
        );
        assert_eq!(
            Config::default().quantum_tier0_ns,
            crate::flow::quantum_tier(0)
        );
        assert_eq!(
            Config::default().quantum_tier1_ns,
            crate::flow::quantum_tier(1)
        );
    }

    #[test]
    fn rejects_bad_tier_slice() {
        let a = ConfigBuilder::default().quantum_tier0_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().quantum_tier1_ns(1).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_bad_short_and_streak() {
        let a = ConfigBuilder::default().short_bound_ns(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().promote_streak(0).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().promote_streak(9).build();
        assert!(c.is_err());
    }

    #[test]
    fn rejects_bad_cap_and_deficit() {
        let a = ConfigBuilder::default().streak_cap(1).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().deficit_serves(0).build();
        assert!(b.is_err());
        let c = ConfigBuilder::default().deficit_serves(9).build();
        assert!(c.is_err());
    }

    #[test]
    fn rejects_zero_gap_and_batch() {
        let a = ConfigBuilder::default().preempt_gap_ns(0).build();
        assert!(a.is_err());
        let b = ConfigBuilder::default().dispatch_batch(0).build();
        assert!(b.is_err());
    }

    #[test]
    fn rejects_batch_above_cap() {
        let a = ConfigBuilder::default().dispatch_batch(33).build();
        assert!(a.is_err());
    }

    #[test]
    fn describe_is_stable() {
        let s = Config::default().describe();
        assert!(s.contains("tier0=500us"));
        assert!(s.contains("tier1=8000us"));
        assert!(s.contains("short=1000us"));
        assert!(s.contains("streak=3"));
        assert!(s.contains("cap=7"));
        assert!(s.contains("deficit=8"));
        assert!(s.contains("batch=32"));
    }
}
