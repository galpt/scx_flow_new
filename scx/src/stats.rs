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
    #[stat(desc = "Streak preempts that end a hog hold")]
    #[serde(default)]
    pub hog_escape: u64,
    #[stat(desc = "Mask change kicks for queued tasks")]
    #[serde(default)]
    pub orphan_kick: u64,
    #[stat(desc = "Forwards where the head cannot run here")]
    #[serde(default)]
    pub hol_forward: u64,
    #[stat(desc = "Enqueues that take the latency key")]
    #[serde(default)]
    pub lat_boost: u64,
    #[stat(desc = "Enqueues that keep the raw key as hogs")]
    #[serde(default)]
    pub hog_hold: u64,
    #[stat(desc = "Preempts won by a latency task")]
    #[serde(default)]
    pub lat_preempt: u64,
    #[stat(desc = "Old waits that step the hold down")]
    #[serde(default)]
    pub age_rescue: u64,
    #[stat(desc = "Extra quanta beyond the first as q minus one")]
    #[serde(default)]
    pub extra_award: u64,
    #[stat(desc = "Total quanta for the run as q")]
    #[serde(default)]
    pub total_quanta: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] queued={} dispatched={} fallback={} steal={} fb_pair_full={} fb_duplicate={} fb_stale={} dhq_depth={} dhq_cap={} steal_pair={} steal_llc={} kick_preempt={} kick_idle={} kick_skip={} overrun={} domino_penalty={} blocked={} hog_escape={} orphan_kick={} hol_forward={} lat_boost={} hog_hold={} lat_preempt={} age_rescue={} extra_award={} total_quanta={}",
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
            self.hog_escape,
            self.orphan_kick,
            self.hol_forward,
            self.lat_boost,
            self.hog_hold,
            self.lat_preempt,
            self.age_rescue,
            self.extra_award,
            self.total_quanta,
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
            hog_escape: self.hog_escape.wrapping_sub(rhs.hog_escape),
            orphan_kick: self.orphan_kick.wrapping_sub(rhs.orphan_kick),
            hol_forward: self.hol_forward.wrapping_sub(rhs.hol_forward),
            lat_boost: self.lat_boost.wrapping_sub(rhs.lat_boost),
            hog_hold: self.hog_hold.wrapping_sub(rhs.hog_hold),
            lat_preempt: self.lat_preempt.wrapping_sub(rhs.lat_preempt),
            age_rescue: self.age_rescue.wrapping_sub(rhs.age_rescue),
            extra_award: self.extra_award.wrapping_sub(rhs.extra_award),
            total_quanta: self.total_quanta.wrapping_sub(rhs.total_quanta),
        }
    }

    /// Books check on an interval window: total equals penalty plus extra.
    /// Awards land exactly on non pinned overruns, so the summed window
    /// keeps total minus penalty minus extra at zero with wrapping math.
    pub fn award_books_ok(&self, rhs: &Self) -> bool {
        let total = self.total_quanta.wrapping_sub(rhs.total_quanta);
        let penalty = self.domino_penalty.wrapping_sub(rhs.domino_penalty);
        let extra = self.extra_award.wrapping_sub(rhs.extra_award);
        total == penalty.wrapping_add(extra)
    }

    /// Extra award plus total quanta deltas for share work.
    /// Top band share stays open: deltas carry no score at award time,
    /// so Y needs the per award log which stays deferred.
    pub fn extra_deltas(&self, rhs: &Self) -> (u64, u64) {
        (
            self.extra_award.wrapping_sub(rhs.extra_award),
            self.total_quanta.wrapping_sub(rhs.total_quanta),
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::fold_llc_val;

    fn awarded(extra: u64, total: u64, penalty: u64) -> Metrics {
        Metrics {
            extra_award: extra,
            total_quanta: total,
            domino_penalty: penalty,
            overrun: penalty,
            ..Metrics::default()
        }
    }

    #[test]
    fn books_hold_for_single_quantum_award() {
        let prev = Metrics::default();
        let cur = awarded(0, 1, 1);
        assert!(cur.award_books_ok(&prev));
        assert_eq!(cur.extra_deltas(&prev), (0, 1));
    }

    #[test]
    fn books_hold_for_three_quantum_award() {
        let prev = Metrics::default();
        let cur = awarded(2, 3, 1);
        assert!(cur.award_books_ok(&prev));
        assert_eq!(cur.extra_deltas(&prev), (2, 3));
    }

    #[test]
    fn books_fail_on_mismatched_window() {
        let prev = Metrics::default();
        let cur = awarded(2, 4, 1);
        assert!(!cur.award_books_ok(&prev));
    }

    #[test]
    fn fold_len_guards_keep_tails_append_only() {
        let mut short = Metrics::default();
        let mut buf192 = [0u8; 192];
        buf192[184..192].copy_from_slice(&1u64.to_ne_bytes());
        fold_llc_val(&mut short, &buf192);
        assert_eq!(short.extra_award, 0);
        assert_eq!(short.total_quanta, 0);
        assert_eq!(short.age_rescue, 1);

        let mut extra_only = Metrics::default();
        let mut buf200 = [0u8; 200];
        buf200[192..200].copy_from_slice(&7u64.to_ne_bytes());
        fold_llc_val(&mut extra_only, &buf200);
        assert_eq!(extra_only.extra_award, 7);
        assert_eq!(extra_only.total_quanta, 0);

        let mut both = Metrics::default();
        let mut buf208 = [0u8; 208];
        buf208[192..200].copy_from_slice(&7u64.to_ne_bytes());
        buf208[200..208].copy_from_slice(&9u64.to_ne_bytes());
        fold_llc_val(&mut both, &buf208);
        assert_eq!(both.extra_award, 7);
        assert_eq!(both.total_quanta, 9);
    }
}
