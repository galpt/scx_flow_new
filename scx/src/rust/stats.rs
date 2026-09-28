// SPDX-License-Identifier: GPL-2.0
//! Stats server and web snapshot for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports the metrics view and the dashboard view from the BPF counters.

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
/// Counters with placement, preempt, and steal detail.
pub struct Metrics {
    #[stat(desc = "Tasks now on a CPU")]
    #[serde(default)]
    pub on_cpu: u64,
    #[stat(desc = "Total runtime in nanoseconds")]
    #[serde(default)]
    pub total_runtime: u64,
    #[stat(desc = "Uptime since attach in nanoseconds")]
    #[serde(default)]
    pub uptime_ns: u64,
    #[stat(desc = "Fresh deadline joins")]
    #[serde(default)]
    pub inserts: u64,
    #[stat(desc = "Runnable slice ends with requeue")]
    #[serde(default)]
    pub requeues: u64,
    #[stat(desc = "Blocks and exits with release")]
    #[serde(default)]
    pub completions: u64,
    #[stat(desc = "Moves from the overflow tail")]
    #[serde(default)]
    pub park_moves: u64,
    #[stat(desc = "Moves from a peer deadline queue")]
    #[serde(default)]
    pub steal_moves: u64,
    #[stat(desc = "Idle wakeup kicks sent after insert")]
    #[serde(default)]
    pub kicks: u64,
    /// Counts missing state plus homeless with no route. Name stays for the wire.
    #[stat(desc = "Inserts without task state")]
    #[serde(default)]
    pub enq_no_tctx: u64,
    #[stat(desc = "Busy preempt kicks")]
    #[serde(default)]
    pub preempt_kicks: u64,
    #[stat(desc = "Busy arrivals held without an earlier deadline")]
    #[serde(default)]
    pub preempt_skipped: u64,
    #[stat(desc = "Queue tasks moved via dispatch")]
    #[serde(default)]
    pub slot_moves: u64,
    #[stat(desc = "Moves from the kernel global queue")]
    #[serde(default)]
    pub global_moves: u64,
    /// Counts quanta at 1ms per throttle hit with no wall use.
    /// Keeps the wire name with the quantum semantic.
    #[stat(desc = "Throttled quanta in nanoseconds at 1ms per hit")]
    #[serde(default)]
    pub throttled_ns: u64,
    /// Counts throttle hits, same hits as parked below.
    /// Keeps the wire name with no split.
    #[stat(desc = "Throttle hits on limited hierarchies")]
    #[serde(default)]
    pub nr_throttled: u64,
    /// Counts overflow parks from throttling, same hits as above.
    /// Keeps the wire name with no split.
    #[stat(desc = "Overflow parks from throttling")]
    #[serde(default)]
    pub parked: u64,
    #[stat(desc = "Hierarchy moves with deadline carry")]
    #[serde(default)]
    pub bw_moves: u64,
}

/// One card of the per-CPU grid.
/// Static fields come from topology once at attach.
/// Live fields come from the per-CPU maps on each poll.
/// Frequency, LLC, and SMT stay display only and never shape placement.
/// Energy stays display only and never shapes placement either.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /// CPU id.
    #[serde(default)]
    pub id: u32,
    /// Max frequency in kilohertz. Zero when unknown.
    #[serde(default)]
    pub freq_khz: u64,
    /// Live frequency in kilohertz. Zero when unknown.
    #[serde(default)]
    pub cur_freq_khz: u64,
    /// Cache domain id. Zero when unknown.
    #[serde(default)]
    pub llc_id: u32,
    /// True for the second thread of a core.
    #[serde(default)]
    pub smt: bool,
    /// Pid now on the CPU. Zero when idle.
    #[serde(default)]
    pub running_pid: u32,
    /// Fixed quantum in nanos. Always 1ms.
    #[serde(default, alias = "tq_ns")]
    pub slice_ns: u64,
}

/// Default state text of the energy object.
/// Unavailable keeps old JSON honest with no silent meter.
fn default_energy_state() -> String {
    "unavailable".to_string()
}

/// Energy meter view for the web dashboard.
/// One nested object with defaults on every field, so old JSON without
/// energy still decodes into the unavailable state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnergyMetrics {
    /// Probe state. unavailable, baseline, collecting, waiting, backoff.
    #[serde(default = "default_energy_state")]
    pub state: String,
    /// Used energy since launch in kWh, a meter.
    #[serde(default)]
    pub since_running_kwh: f64,
    /// Last good watts for the live readout. Zero before use.
    #[serde(default)]
    pub live_watts: f64,
    /// Seconds left in waiting or backoff from wall clock.
    #[serde(default)]
    pub countdown_s: u64,
    /// Live derivation in monospace for the page.
    #[serde(default)]
    pub trace: String,
}

impl Default for EnergyMetrics {
    /// Missing energy means unavailable with an empty meter.
    fn default() -> Self {
        Self {
            state: default_energy_state(),
            since_running_kwh: 0.0,
            live_watts: 0.0,
            countdown_s: 0,
            trace: String::new(),
        }
    }
}

/// Snapshot for the web dashboard.
/// Counters stay raw with the on CPU gauge plus the live pid view.
/// The run loop pushes one per iteration.
/// The web thread keeps the newest behind a lock for the handlers.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /// Scheduler wide counters. Raw values.
    pub stats: Metrics,
    /// One entry per online CPU.
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /// Scheduler version for the page and the log.
    #[serde(default)]
    pub version: String,
    /// Wall time in nanos since epoch for the log.
    #[serde(default)]
    pub timestamp_ns: u64,
    /// One line topology summary for the page.
    #[serde(default)]
    pub topology: String,
    /// Governor display with EPP and platform suffix.
    #[serde(default)]
    pub governor: String,
    /// Energy meter view. Defaults to unavailable.
    #[serde(default)]
    pub energy: EnergyMetrics,
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime={} uptime={} \
            ins={} req={} done={} park={} steal={} \
            kick={} noctx={} \
            pkick={} pskip={} \
            smoves={} global={} \
            thr={} nthr={} parked={} bw={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.inserts,
            self.requeues,
            self.completions,
            self.park_moves,
            self.steal_moves,
            self.kicks,
            self.enq_no_tctx,
            self.preempt_kicks,
            self.preempt_skipped,
            self.slot_moves,
            self.global_moves,
            self.throttled_ns,
            self.nr_throttled,
            self.parked,
            self.bw_moves,
        )?;
        Ok(())
    }

    /// Interval delta.
    /// Counters move forward. Gauges pass through unchanged.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            inserts: self.inserts.wrapping_sub(rhs.inserts),
            requeues: self.requeues.wrapping_sub(rhs.requeues),
            completions: self.completions.wrapping_sub(rhs.completions),
            park_moves: self.park_moves.wrapping_sub(rhs.park_moves),
            steal_moves: self.steal_moves.wrapping_sub(rhs.steal_moves),
            kicks: self.kicks.wrapping_sub(rhs.kicks),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
            preempt_kicks: self.preempt_kicks.wrapping_sub(rhs.preempt_kicks),
            preempt_skipped: self.preempt_skipped.wrapping_sub(rhs.preempt_skipped),
            slot_moves: self.slot_moves.wrapping_sub(rhs.slot_moves),
            global_moves: self.global_moves.wrapping_sub(rhs.global_moves),
            throttled_ns: self.throttled_ns.wrapping_sub(rhs.throttled_ns),
            nr_throttled: self.nr_throttled.wrapping_sub(rhs.nr_throttled),
            parked: self.parked.wrapping_sub(rhs.parked),
            bw_moves: self.bw_moves.wrapping_sub(rhs.bw_moves),
        }
    }
}

/// Stats server with one top op.
/// The op reports deltas over the poll interval.
type Opener = dyn StatsOpener<(), Metrics>;
type Reader = dyn StatsReader<(), Metrics>;
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<Opener> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;
        let read: Box<Reader> = Box::new(move |_a, (req_ch, res_ch)| {
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

/// Monitor loop.
/// Polls the stats server and prints one line per interval.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |m| m.format(&mut std::io::stdout()),
    )
}
