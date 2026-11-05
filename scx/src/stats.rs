// SPDX-License-Identifier: GPL-2.0
//! Stats server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports per LLC counters summed across LLCs.

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::Stats;
use scx_stats_derive::stat_doc;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
/// Minimal counters with pair plus DSQ detail and sizing tail.
pub struct Metrics {
    #[stat(desc = "Tasks now queued in pair plus DSQ")]
    #[serde(default)]
    pub queued: u64,
    #[stat(desc = "Tasks moved to local in dispatch")]
    #[serde(default)]
    pub dispatched: u64,
    #[stat(desc = "Pair full plus duplicate plus stale discards")]
    #[serde(default)]
    pub fallback: u64,
    #[stat(desc = "Pair and LLC queue steals in dispatch")]
    #[serde(default)]
    pub steal: u64,
    #[stat(desc = "Pair full spills to LLC queue")]
    #[serde(default)]
    pub fb_pair_full: u64,
    #[stat(desc = "Duplicate requeues dropped by queued guard")]
    #[serde(default)]
    pub fb_duplicate: u64,
    #[stat(desc = "Stale pair pops with no task")]
    #[serde(default)]
    pub fb_stale: u64,
    #[stat(desc = "Last observed pair depth for sizing")]
    #[serde(default)]
    pub dhq_depth: u64,
    #[stat(desc = "Last observed pair capacity for sizing")]
    #[serde(default)]
    pub dhq_cap: u64,
    #[stat(desc = "Pair steals in dispatch")]
    #[serde(default)]
    pub steal_pair: u64,
    #[stat(desc = "Remote LLC steals in dispatch")]
    #[serde(default)]
    pub steal_llc: u64,
    #[stat(desc = "Preempt kicks on enqueue")]
    #[serde(default)]
    pub kick_preempt: u64,
    #[stat(desc = "Idle kicks on enqueue")]
    #[serde(default)]
    pub kick_idle: u64,
    #[stat(desc = "Enqueue kicks skipped with no wake")]
    #[serde(default)]
    pub kick_skip: u64,
    #[stat(desc = "Carry tasks that burnt the full slice")]
    #[serde(default)]
    pub overrun: u64,
    #[stat(desc = "Extra slice charged on full slice burn")]
    #[serde(default)]
    pub domino_penalty: u64,
    #[stat(desc = "Stops that leave the task still runnable")]
    #[serde(default)]
    pub blocked: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] queued={} dispatched={} fallback={} steal={} fb_pair_full={} fb_duplicate={} fb_stale={} dhq_depth={} dhq_cap={} steal_pair={} steal_llc={} kick_preempt={} kick_idle={} kick_skip={} overrun={} domino_penalty={} blocked={}",
            crate::cli::SCHEDULER_NAME,
            self.queued,
            self.dispatched,
            self.fallback,
            self.steal,
            self.fb_pair_full,
            self.fb_duplicate,
            self.fb_stale,
            self.dhq_depth,
            self.dhq_cap,
            self.steal_pair,
            self.steal_llc,
            self.kick_preempt,
            self.kick_idle,
            self.kick_skip,
            self.overrun,
            self.domino_penalty,
            self.blocked,
        )?;
        Ok(())
    }

    /// Interval delta with queued plus depth plus cap passing through as live gauges.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            queued: self.queued,
            dispatched: self.dispatched.wrapping_sub(rhs.dispatched),
            fallback: self.fallback.wrapping_sub(rhs.fallback),
            steal: self.steal.wrapping_sub(rhs.steal),
            fb_pair_full: self.fb_pair_full.wrapping_sub(rhs.fb_pair_full),
            fb_duplicate: self.fb_duplicate.wrapping_sub(rhs.fb_duplicate),
            fb_stale: self.fb_stale.wrapping_sub(rhs.fb_stale),
            dhq_depth: self.dhq_depth,
            dhq_cap: self.dhq_cap,
            steal_pair: self.steal_pair.wrapping_sub(rhs.steal_pair),
            steal_llc: self.steal_llc.wrapping_sub(rhs.steal_llc),
            kick_preempt: self.kick_preempt.wrapping_sub(rhs.kick_preempt),
            kick_idle: self.kick_idle.wrapping_sub(rhs.kick_idle),
            kick_skip: self.kick_skip.wrapping_sub(rhs.kick_skip),
            overrun: self.overrun.wrapping_sub(rhs.overrun),
            domino_penalty: self.domino_penalty.wrapping_sub(rhs.domino_penalty),
            blocked: self.blocked.wrapping_sub(rhs.blocked),
        }
    }
}

/// Stats printer loop for the monitor flag.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

/// Server data for the stats server.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;
        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });
        Ok(read)
    });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}
