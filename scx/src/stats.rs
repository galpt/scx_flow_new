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
/// Per LLC counters for queueing, kicks, holds, and awards.
pub struct Metrics {
    #[stat(desc = "Tasks now queued in DSQ")]
    #[serde(default)]
    pub queued: u64,
    #[stat(desc = "Tasks moved to local in dispatch")]
    #[serde(default)]
    pub dispatched: u64,
    #[stat(desc = "Fallback inserts and duplicate drops")]
    #[serde(default)]
    pub fallback: u64,
    #[stat(desc = "Remote LLC queue moves in dispatch")]
    #[serde(default)]
    pub steal: u64,
    #[stat(desc = "Duplicate requeues dropped while queued")]
    #[serde(default)]
    pub fb_duplicate: u64,
    #[stat(desc = "Remote moves counted on the thief")]
    #[serde(default)]
    pub steal_llc: u64,
    #[stat(desc = "Preempt kicks on enqueue")]
    #[serde(default)]
    pub kick_preempt: u64,
    #[stat(desc = "Idle kicks on enqueue")]
    #[serde(default)]
    pub kick_idle: u64,
    #[stat(desc = "Skipped enqueue kicks")]
    #[serde(default)]
    pub kick_skip: u64,
    #[stat(desc = "Tasks that burnt the full slice")]
    #[serde(default)]
    pub overrun: u64,
    #[stat(desc = "Extra slice charged on full slice burn")]
    #[serde(default)]
    pub domino_penalty: u64,
    #[stat(desc = "Stops that leave the task still runnable")]
    #[serde(default)]
    pub blocked: u64,
    #[stat(desc = "Fresh spans after an overdue deadline")]
    #[serde(default)]
    pub lst_escape: u64,
    #[stat(desc = "Mask change kicks for queued tasks")]
    #[serde(default)]
    pub orphan_kick: u64,
    #[stat(desc = "Forwards where the head cannot run here")]
    #[serde(default)]
    pub hol_forward: u64,
    #[stat(desc = "Enqueues with urgent slack")]
    #[serde(default)]
    pub lst_urgent: u64,
    #[stat(desc = "Enqueues with roomy slack")]
    #[serde(default)]
    pub lst_hold: u64,
    #[stat(desc = "Gap preempts won on enqueue")]
    #[serde(default)]
    pub lst_preempt: u64,
    #[stat(desc = "Deadlines seen past now")]
    #[serde(default)]
    pub lst_overdue: u64,
    #[stat(desc = "Extra quanta beyond the first")]
    #[serde(default)]
    pub extra_award: u64,
    #[stat(desc = "Total quanta granted")]
    #[serde(default)]
    pub total_quanta: u64,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] queued={} dispatched={} fallback={} steal={} fb_duplicate={} steal_llc={} kick_preempt={} kick_idle={} kick_skip={} overrun={} domino_penalty={} blocked={} lst_escape={} orphan_kick={} hol_forward={} lst_urgent={} lst_hold={} lst_preempt={} lst_overdue={} extra_award={} total_quanta={}",
            crate::cli::SCHEDULER_NAME,
            self.queued,
            self.dispatched,
            self.fallback,
            self.steal,
            self.fb_duplicate,
            self.steal_llc,
            self.kick_preempt,
            self.kick_idle,
            self.kick_skip,
            self.overrun,
            self.domino_penalty,
            self.blocked,
            self.lst_escape,
            self.orphan_kick,
            self.hol_forward,
            self.lst_urgent,
            self.lst_hold,
            self.lst_preempt,
            self.lst_overdue,
            self.extra_award,
            self.total_quanta,
        )?;
        Ok(())
    }

    /// Single LLC row with the same fields plus the LLC index.
    /// Keeps struct order with no reorder.
    pub fn format_llc<W: Write>(&self, w: &mut W, llc: u32) -> Result<()> {
        write!(w, "[{}:llc{}] ", crate::cli::SCHEDULER_NAME, llc)?;
        self.format(w)
    }

    /// Interval delta. Queued passes through as a live gauge.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            queued: self.queued,
            dispatched: self.dispatched.wrapping_sub(rhs.dispatched),
            fallback: self.fallback.wrapping_sub(rhs.fallback),
            steal: self.steal.wrapping_sub(rhs.steal),
            fb_duplicate: self.fb_duplicate.wrapping_sub(rhs.fb_duplicate),
            steal_llc: self.steal_llc.wrapping_sub(rhs.steal_llc),
            kick_preempt: self.kick_preempt.wrapping_sub(rhs.kick_preempt),
            kick_idle: self.kick_idle.wrapping_sub(rhs.kick_idle),
            kick_skip: self.kick_skip.wrapping_sub(rhs.kick_skip),
            overrun: self.overrun.wrapping_sub(rhs.overrun),
            domino_penalty: self.domino_penalty.wrapping_sub(rhs.domino_penalty),
            blocked: self.blocked.wrapping_sub(rhs.blocked),
            lst_escape: self.lst_escape.wrapping_sub(rhs.lst_escape),
            orphan_kick: self.orphan_kick.wrapping_sub(rhs.orphan_kick),
            hol_forward: self.hol_forward.wrapping_sub(rhs.hol_forward),
            lst_urgent: self.lst_urgent.wrapping_sub(rhs.lst_urgent),
            lst_hold: self.lst_hold.wrapping_sub(rhs.lst_hold),
            lst_preempt: self.lst_preempt.wrapping_sub(rhs.lst_preempt),
            lst_overdue: self.lst_overdue.wrapping_sub(rhs.lst_overdue),
            extra_award: self.extra_award.wrapping_sub(rhs.extra_award),
            total_quanta: self.total_quanta.wrapping_sub(rhs.total_quanta),
        }
    }

    /// Check totals on an interval window. Total matches penalty and extra combined.
    /// Awards land on overruns that are not pinned, so the window keeps
    /// the difference at zero with wrapping math.
    pub fn award_books_ok(&self, rhs: &Self) -> bool {
        let total = self.total_quanta.wrapping_sub(rhs.total_quanta);
        let penalty = self.domino_penalty.wrapping_sub(rhs.domino_penalty);
        let extra = self.extra_award.wrapping_sub(rhs.extra_award);
        total == penalty.wrapping_add(extra)
    }

    /// Deltas for extra awards and total quanta.
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

/// Wait hist for run plus dispatch halves by kind times bucket.
#[stat_doc]
#[derive(Clone, Debug, Serialize, Deserialize, Stats)]
pub struct LatMetrics {
    #[stat(desc = "Wait hist run plus dispatch by kind times bucket")]
    pub lat_hist: Vec<u64>,
}

impl Default for LatMetrics {
    fn default() -> Self {
        Self {
            lat_hist: vec![0; crate::bpf_intf::flow_consts_FLOW_HIST_LEN as usize],
        }
    }
}

impl LatMetrics {
    /// Interval delta with wrapping math per cell.
    pub fn delta(&self, rhs: &Self) -> Self {
        let want = crate::bpf_intf::flow_consts_FLOW_HIST_LEN as usize;
        let mut out = vec![0u64; want];
        for (i, slot) in out.iter_mut().enumerate() {
            let a = self.lat_hist.get(i).copied().unwrap_or(0);
            let b = rhs.lat_hist.get(i).copied().unwrap_or(0);
            *slot = a.wrapping_sub(b);
        }
        Self { lat_hist: out }
    }
}

/// Server data for the stats server.
pub fn server_data() -> StatsServerData<(), (Metrics, LatMetrics)> {
    let open_top: Box<dyn StatsOpener<(), (Metrics, LatMetrics)>> =
        Box::new(move |(req_ch, res_ch)| {
            req_ch.send(())?;
            let (cur, _) = res_ch.recv()?;
            let mut prev: Metrics = cur;
            let read: Box<dyn StatsReader<(), (Metrics, LatMetrics)>> =
                Box::new(move |_args, (req_ch, res_ch)| {
                    req_ch.send(())?;
                    let (cur, _) = res_ch.recv()?;
                    let delta = cur.delta(&prev);
                    prev = cur;
                    delta.to_json()
                });
            Ok(read)
        });
    let open_lat: Box<dyn StatsOpener<(), (Metrics, LatMetrics)>> =
        Box::new(move |(req_ch, res_ch)| {
            req_ch.send(())?;
            let (_, cur) = res_ch.recv()?;
            let mut prev: LatMetrics = cur;
            let read: Box<dyn StatsReader<(), (Metrics, LatMetrics)>> =
                Box::new(move |_args, (req_ch, res_ch)| {
                    req_ch.send(())?;
                    let (_, cur) = res_ch.recv()?;
                    let delta = cur.delta(&prev);
                    prev = cur;
                    delta.to_json()
                });
            Ok(read)
        });
    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_meta(LatMetrics::meta())
        .add_ops(
            "top",
            StatsOps {
                open: open_top,
                close: None,
            },
        )
        .add_ops(
            "lat",
            StatsOps {
                open: open_lat,
                close: None,
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::fold_lat_val;
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
    fn fold_len_guards_keep_tails() {
        let mut short = Metrics::default();
        let mut buf152 = [0u8; 152];
        buf152[144..152].copy_from_slice(&1u64.to_ne_bytes());
        fold_llc_val(&mut short, &buf152);
        assert_eq!(short.extra_award, 0);
        assert_eq!(short.total_quanta, 0);
        assert_eq!(short.lst_overdue, 1);

        let mut extra_only = Metrics::default();
        let mut buf160 = [0u8; 160];
        buf160[152..160].copy_from_slice(&7u64.to_ne_bytes());
        fold_llc_val(&mut extra_only, &buf160);
        assert_eq!(extra_only.extra_award, 7);
        assert_eq!(extra_only.total_quanta, 0);

        let mut both = Metrics::default();
        let mut buf168 = [0u8; 168];
        buf168[152..160].copy_from_slice(&7u64.to_ne_bytes());
        buf168[160..168].copy_from_slice(&9u64.to_ne_bytes());
        fold_llc_val(&mut both, &buf168);
        assert_eq!(both.extra_award, 7);
        assert_eq!(both.total_quanta, 9);
    }

    #[test]
    fn lat_default_len_is_hist_len() {
        let want = crate::bpf_intf::flow_consts_FLOW_HIST_LEN as usize;
        let cur = LatMetrics::default();
        assert_eq!(cur.lat_hist.len(), want);
        assert_eq!(want, 144);
    }

    #[test]
    fn lat_fold_uses_discovered_count() {
        let want = crate::bpf_intf::flow_consts_FLOW_HIST_LEN as usize;
        let mut out = LatMetrics::default();
        let mut full = vec![0u8; want * 8];
        full[0..8].copy_from_slice(&3u64.to_ne_bytes());
        full[(want - 1) * 8..want * 8].copy_from_slice(&5u64.to_ne_bytes());
        fold_lat_val(&mut out, &full);
        assert_eq!(out.lat_hist[0], 3);
        assert_eq!(out.lat_hist[want - 1], 5);

        let mut short = LatMetrics::default();
        let tiny = vec![0u8; 16];
        fold_lat_val(&mut short, &tiny);
        assert_eq!(short.lat_hist[0], 0);
        assert_eq!(short.lat_hist[1], 0);
        assert_eq!(short.lat_hist.len(), want);
    }

    #[test]
    fn lat_delta_wraps_per_cell() {
        let want = crate::bpf_intf::flow_consts_FLOW_HIST_LEN as usize;
        let mut cur = LatMetrics::default();
        let mut prev = LatMetrics::default();
        cur.lat_hist[0] = 5;
        prev.lat_hist[0] = 3;
        cur.lat_hist[want - 1] = 1;
        prev.lat_hist[want - 1] = 2;
        let d = cur.delta(&prev);
        assert_eq!(d.lat_hist[0], 2);
        assert_eq!(d.lat_hist[want - 1], 1u64.wrapping_sub(2));
    }
}
