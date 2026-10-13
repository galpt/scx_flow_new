// SPDX-License-Identifier: GPL-2.0
//! Stats server for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Exports the counters view plus the dashboard view from the BPF maps.
//! The stats server carries deltas while the dashboard carries raw
//! counters plus per CPU cards for the loopback page.

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
/// Counters with placement, admission, and miss detail.
/// BPF holds 20 counters, Rust adds display-only uptime for 21.
pub struct Metrics {
    #[stat(desc = "Tasks now on a CPU")]
    #[serde(default)]
    pub on_cpu: u64,
    #[stat(desc = "Total runtime in nanoseconds")]
    #[serde(default)]
    pub total_runtime: u64,
    /// Display-only uptime since attach in nanos with no BPF use.
    /// Filled from the start instant, never from the BPF counters.
    #[stat(desc = "Uptime since attach in nanoseconds")]
    #[serde(default)]
    pub uptime_ns: u64,
    #[stat(desc = "Fresh deadline joins")]
    #[serde(default)]
    pub inserts: u64,
    #[stat(desc = "Runnable slice ends with requeue")]
    #[serde(default)]
    pub requeues: u64,
    #[stat(desc = "Blocks and exits")]
    #[serde(default)]
    pub completions: u64,
    #[stat(desc = "Moves from the local tier")]
    #[serde(default)]
    pub local_moves: u64,
    #[stat(desc = "Moves from the node tier")]
    #[serde(default)]
    pub node_moves: u64,
    #[stat(desc = "Moves from the machine tier")]
    #[serde(default)]
    pub machine_moves: u64,
    #[stat(desc = "Idle wakeup kicks sent after insert")]
    #[serde(default)]
    pub kicks: u64,
    #[stat(desc = "Tasks admitted with no bound")]
    #[serde(default)]
    pub admits: u64,
    #[stat(
        desc = "Rejects dead at zero for wire compat with no writer; real rejects count in gate_rejects"
    )]
    #[serde(default)]
    pub rejects: u64,
    #[stat(desc = "Wall completions past deadline")]
    #[serde(default)]
    pub misses: u64,
    #[stat(desc = "Closed gate rejects on stale CPUs plus tasks")]
    #[serde(default)]
    pub gate_rejects: u64,
    #[stat(desc = "Busy preempts sent with margin plus tail")]
    #[serde(default)]
    pub preempt_kicks: u64,
    #[stat(desc = "Preempts held by margin plus tail plus eligibility")]
    #[serde(default)]
    pub preempt_skipped: u64,
    #[stat(desc = "RED overload rejects to the value ordered queue")]
    #[serde(default)]
    pub red_rejects: u64,
    #[stat(desc = "RED reclaims from the value ordered queue")]
    #[serde(default)]
    pub red_reclaims: u64,
    #[stat(desc = "ML burst hits within 64us")]
    #[serde(default)]
    pub ml_hits: u64,
    #[stat(desc = "ML train samples for accuracy")]
    #[serde(default)]
    pub ml_total: u64,
    #[stat(desc = "ML nudge saturations at 250us")]
    #[serde(default)]
    pub ml_clamped: u64,
}

/// One card of the per CPU grid.
/// Id plus SMT stay fixed while pid plus slice refresh on each poll.
/// Pid holds zero when idle and slice holds the shared quantum.
/// SMT marks the second thread of one core for display only with
/// no placement use and false on old JSON.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /// CPU id.
    #[serde(default)]
    pub id: u32,
    /// True for the second thread of one core with false on single thread.
    /// Display only with no placement use plus false on old JSON.
    #[serde(default)]
    pub smt: bool,
    /// Pid now on the CPU with zero when idle.
    #[serde(default)]
    pub running_pid: u32,
    /// Fixed slice in nanos with the shared quantum.
    #[serde(default)]
    pub slice_ns: u64,
}

/// Snapshot for the web dashboard.
/// Counters stay raw with the on CPU gauge plus the live pid view.
/// The run loop pushes one per poll and the web thread keeps the
/// newest behind a lock for the page plus the JSON routes.
/// Accuracy reads hits over total in 0.0 to 1.0 with higher better
/// plus zero on no samples, so the page tracks ML quality with no
/// extra poll.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /// Scheduler wide counters with raw values.
    pub stats: Metrics,
    /// One entry per online CPU in rank order.
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /// Scheduler version for the page plus the log.
    #[serde(default)]
    pub version: String,
    /// Wall time in nanos since epoch for the log.
    #[serde(default)]
    pub timestamp_ns: u64,
    /// One line topology summary for the page.
    #[serde(default)]
    pub topology: String,
    /// Train steps from the online model with zero on miss.
    /// Display only with no placement use plus zero on old JSON.
    #[serde(default)]
    pub ml_updates: u64,
    /// ML accuracy as hits over total in 0.0 to 1.0 with higher better.
    /// Zero on no samples plus zero on old JSON with no extra poll.
    #[serde(default)]
    pub ml_accuracy: f64,
    /// ML hits summed from the per CPU rows with zero on old JSON.
    #[serde(default)]
    pub ml_hits: u64,
    /// ML samples summed from the per CPU rows with zero on old JSON.
    #[serde(default)]
    pub ml_total: u64,
    /// ML clamps summed from the per CPU rows with zero on old JSON.
    #[serde(default)]
    pub ml_clamped: u64,
}

/// Stats printer loop for the monitor flag.
/// Polls the stats server on the interval with plain text lines.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

/// Server data for the stats server.
/// A single top op reports interval deltas of the counters.
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

impl Metrics {
    /// ML accuracy as hits over total in 0.0 to 1.0 with higher better.
    /// Zero on no samples, so an untrained model reads zero with no
    /// divide by zero. Clamps to 1.0 with no wrap.
    pub fn accuracy(&self) -> f64 {
        if self.ml_total == 0 {
            return 0.0;
        }
        let v = self.ml_hits as f64 / self.ml_total as f64;
        if !v.is_finite() {
            return 0.0;
        }
        v.clamp(0.0, 1.0)
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} ins={} req={} done={} \
             local={} node={} machine={} kick={} adm={} rej={} \
             miss={} gate={} pkick={} pskip={} redrej={} redrec={} \
             mlhits={} mltotal={} mlclamp={} mlacc={:.4}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.inserts,
            self.requeues,
            self.completions,
            self.local_moves,
            self.node_moves,
            self.machine_moves,
            self.kicks,
            self.admits,
            self.rejects,
            self.misses,
            self.gate_rejects,
            self.preempt_kicks,
            self.preempt_skipped,
            self.red_rejects,
            self.red_reclaims,
            self.ml_hits,
            self.ml_total,
            self.ml_clamped,
            self.accuracy(),
        )?;
        Ok(())
    }

    /// Interval delta of the counters over the poll interval.
    /// Gauges like on_cpu plus uptime_ns pass through as live values.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            inserts: self.inserts.wrapping_sub(rhs.inserts),
            requeues: self.requeues.wrapping_sub(rhs.requeues),
            completions: self.completions.wrapping_sub(rhs.completions),
            local_moves: self.local_moves.wrapping_sub(rhs.local_moves),
            node_moves: self.node_moves.wrapping_sub(rhs.node_moves),
            machine_moves: self.machine_moves.wrapping_sub(rhs.machine_moves),
            kicks: self.kicks.wrapping_sub(rhs.kicks),
            admits: self.admits.wrapping_sub(rhs.admits),
            rejects: self.rejects.wrapping_sub(rhs.rejects),
            misses: self.misses.wrapping_sub(rhs.misses),
            gate_rejects: self.gate_rejects.wrapping_sub(rhs.gate_rejects),
            preempt_kicks: self.preempt_kicks.wrapping_sub(rhs.preempt_kicks),
            preempt_skipped: self.preempt_skipped.wrapping_sub(rhs.preempt_skipped),
            red_rejects: self.red_rejects.wrapping_sub(rhs.red_rejects),
            red_reclaims: self.red_reclaims.wrapping_sub(rhs.red_reclaims),
            ml_hits: self.ml_hits.wrapping_sub(rhs.ml_hits),
            ml_total: self.ml_total.wrapping_sub(rhs.ml_total),
            ml_clamped: self.ml_clamped.wrapping_sub(rhs.ml_clamped),
        }
    }
}
