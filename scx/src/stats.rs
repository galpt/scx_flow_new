/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Stats server and web snapshot for the flow scheduler.
 * Metrics mirrors the BPF counters plus uptime. Tier
 * inserts and serves count per tier. Moves count tier
 * changes in either direction. Web metrics adds per cpu
 * cards with per tier slices and per tier waiting
 * counts.
 */
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Tasks now on a cpu")]
    pub on_cpu: u64,
    #[stat(desc = "Total runtime in nanoseconds")]
    pub total_runtime: u64,
    #[stat(desc = "Uptime since attach in nanoseconds")]
    pub uptime_ns: u64,
    #[stat(desc = "Inserts in tier zero")]
    pub enq_tier0: u64,
    #[stat(desc = "Inserts in tier one")]
    pub enq_tier1: u64,
    #[stat(desc = "Moves from tier zero to tier one")]
    pub demotions: u64,
    #[stat(desc = "Moves from tier one to tier zero")]
    pub promotions: u64,
    #[stat(desc = "Runs in tier zero")]
    pub serves_tier0: u64,
    #[stat(desc = "Runs in tier one")]
    pub serves_tier1: u64,
    #[stat(desc = "Gated batch serves in dispatch")]
    pub deficit_serves: u64,
    #[stat(desc = "Idle wakeup kicks sent after insert")]
    #[serde(default)]
    pub kicks: u64,
    #[stat(desc = "Busy preemption kicks for batch runners")]
    #[serde(default)]
    pub preempts: u64,
    #[stat(desc = "Inserts without task state")]
    pub enq_no_tctx: u64,
}

/*
 * One card of the per cpu grid. Static fields come from
 * topology once at attach. Dynamic fields come from the
 * per cpu map on each poll.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /* Cpu id. */
    pub id: u32,
    /* Max frequency in kilohertz. Zero when unknown. */
    pub freq_khz: u64,
    /* Live frequency in kilohertz. Zero when unknown. */
    pub cur_freq_khz: u64,
    /* Cache domain id. Zero when unknown. */
    pub llc_id: u32,
    /* True for the second thread of a core. */
    pub smt: bool,
    /* Estimate of the task now on the cpu. Zero idle. */
    pub running_est_ns: u64,
    /* Pid now on the cpu. Zero when idle. */
    pub running_pid: u32,
    /* Tier of the task now on the cpu. Zero idle. */
    #[serde(default)]
    pub running_tier: u32,
}

/*
 * Snapshot for the web dashboard. All fields are gauges.
 * The run loop pushes one per iteration. The web thread
 * keeps the newest behind a lock for the handlers.
 */
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /* Scheduler wide counters. Raw values. */
    pub stats: Metrics,
    /* One entry per online cpu. */
    #[serde(default)]
    pub per_cpu: Vec<PerCpuMetrics>,
    /* Fixed slice per tier in nanoseconds. */
    #[serde(default)]
    pub quanta_per_tier: [u64; 2],
    /* Joined tasks per tier. Index is the tier. */
    #[serde(default)]
    pub waiting_per_tier: [u64; 2],
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime={} uptime={} enq={}/{} \
            move={}/{} run={}/{} deficit={} kick={} \
            preempt={} noctx={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.enq_tier0,
            self.enq_tier1,
            self.demotions,
            self.promotions,
            self.serves_tier0,
            self.serves_tier1,
            self.deficit_serves,
            self.kicks,
            self.preempts,
            self.enq_no_tctx,
        )?;
        Ok(())
    }

    /*
     * Interval delta. Counters move forward. Gauges pass
     * through unchanged.
     */
    pub fn delta(&self, rhs: &Self) -> Self {
        let deficit = self.deficit_serves.wrapping_sub(rhs.deficit_serves);
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            enq_tier0: self.enq_tier0.wrapping_sub(rhs.enq_tier0),
            enq_tier1: self.enq_tier1.wrapping_sub(rhs.enq_tier1),
            demotions: self.demotions.wrapping_sub(rhs.demotions),
            promotions: self.promotions.wrapping_sub(rhs.promotions),
            serves_tier0: self.serves_tier0.wrapping_sub(rhs.serves_tier0),
            serves_tier1: self.serves_tier1.wrapping_sub(rhs.serves_tier1),
            deficit_serves: deficit,
            kicks: self.kicks.wrapping_sub(rhs.kicks),
            preempts: self.preempts.wrapping_sub(rhs.preempts),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
        }
    }
}

/*
 * Stats server with one top op. The op reports deltas
 * over the poll interval.
 */
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

/*
 * Monitor loop. Polls the stats server and prints one
 * line per interval. Runs on its own thread.
 */
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |m| m.format(&mut std::io::stdout()),
    )
}
