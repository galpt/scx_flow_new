// SPDX-License-Identifier: GPL-2.0
//! Flow daemon front end.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Loads the BPF object, seeds the topology view, drives the
//! loop. Admission plus order live in the core with no roundtrip.
//! Observability flows through counters plus the loopback dashboard
//! with per CPU cards plus a JSON snapshot for debug. The daemon
//! mirror never gates dispatch.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
#[path = "rust/config.rs"]
mod config;
#[path = "rust/flow/mod.rs"]
mod flow;
#[path = "rust/snapshot.rs"]
mod snapshot;
#[path = "rust/stats.rs"]
mod stats;
#[path = "rust/topology.rs"]
mod topology;
#[path = "rust/webui.rs"]
mod webui;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::Shell;
use clap_complete::generate;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use scx_stats::prelude::*;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use config::Config;
use stats::Metrics;

/* Binary name used in logs and stats. */
const SCHEDULER_NAME: &str = "scx_flow";
/* CPU bound shared with the BPF header. */
#[cfg(test)]
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;
/* Ring poll interval in millis decoupled from dashboard cadence. */
const RING_POLL_MS: u64 = 10;
/* Dashboard freshness in millis for cached per CPU cards. */
const WEB_CACHE_MS: u64 = 100;
/* Stale collection interval in millis for lost completes. */
const GC_INTERVAL_MS: u64 = 1000;
/* Event payload length in bytes matching the BPF event. */
const EVENT_LEN: usize = 40;

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /* Poll interval for the stats printer. */
    #[clap(long)]
    stats: Option<f64>,
    /* Run the stats printer only. */
    #[clap(long)]
    monitor: Option<f64>,
    /* Verbose BPF logging. */
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,
    /* Verbose output with libbpf detail. */
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
    /* Exit dump buffer length in bytes. */
    #[clap(long, default_value = "1048576")]
    exit_dump_len: u32,
    /* Print version and exit. */
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
    /* Show stat descriptions. */
    #[clap(long)]
    help_stats: bool,
    /* Generate shell completions and exit. */
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
    /* Disable the loopback dashboard thread. */
    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/* Scheduler owns the skeleton, the link, the stats server, */
/* the dashboard channel, the mirror. It drives the run loop */
/* until shutdown or exit. Backlog is the event channel length */
/* and drop rate is the parks delta with zero wire change. */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    started_at: std::time::Instant,
    /* Dashboard sender with empty when disabled. */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    /* Online identifiers once at init in rank order. */
    online_cpus: Vec<u32>,
    /* SMT flag per online CPU in rank order for the cards. */
    smt: Vec<bool>,
    /* One line topology summary for the page. */
    topology: String,
    /* Daemon mirror for observability solely. */
    pub(crate) daemon: flow::Daemon,
    /* Bounded event channel from the ring buffers. */
    ev_rx: crossbeam::channel::Receiver<[u8; EVENT_LEN]>,
    /* Userspace queue drops shared with ring callbacks. */
    ev_drops: Arc<AtomicU64>,
    /* Ring polling handle with empty on fault. */
    rings: Option<libbpf_rs::RingBuffer<'a>>,
    /* Last dashboard refresh for throttled per CPU reads. */
    last_web: Instant,
    /* Last stale collection for lost completes. */
    last_gc: Instant,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();
        let mut bld = BpfSkelBuilder::default();
        bld.obj_builder.debug(opts.debug || opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(bld, open_object, flow_ops, open_opts)?;
        /* Validate the constants before load. */
        let cfg = Config::default();
        cfg.validate()?;
        info!("Config: {}", cfg.describe());
        /* Ops flags live in the BPF object for recent kernels. */
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        /* Seed the BPF topology view with sibling plus node rows. */
        /* Faulty updates keep the BPF default. */
        let rows = topology::topo_rows();
        Self::seed_topo_with(&mut skel, &rows);
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        /* Bounded dashboard channel drops a frame when full. */
        let webui_tx = if opts.no_webui {
            None
        } else {
            let (tx, rx) = crossbeam::channel::bounded::<stats::WebMetrics>(16);
            let sd = shutdown.clone();
            std::thread::spawn(move || {
                webui::start(rx, sd);
            });
            Some(tx)
        };
        let online_cpus: Vec<u32> = rows.iter().map(|(cpu, _, _)| *cpu).collect();
        /* SMT flags cache the sibling view for the cards. */
        let smt: Vec<bool> = rows
            .iter()
            .map(|(cpu, sib, _)| topology::is_smt_thread(*cpu, *sib))
            .collect();
        let topology = topology::describe_topology(&rows);
        info!("Topology: {topology}");
        /* Bounded event queue drops with drop gauge when full. */
        /* Stack copies avoid per event heap growth on the hot path. */
        /* Faulty setup keeps progress at the core through fail open. */
        let (ev_tx, ev_rx) = crossbeam::channel::bounded::<[u8; EVENT_LEN]>(flow::EV_CAP);
        let ev_drops = Arc::new(AtomicU64::new(0));
        let rings = Self::build_rings(&skel, ev_tx, ev_drops.clone());
        let now = Instant::now();
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            started_at: std::time::Instant::now(),
            webui_tx,
            online_cpus,
            smt,
            topology,
            daemon: flow::Daemon::new(),
            ev_rx,
            ev_drops,
            rings,
            last_web: now
                .checked_sub(Duration::from_millis(WEB_CACHE_MS))
                .unwrap_or(now),
            last_gc: now,
        })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /* Forward one ring payload into the bounded queue. */
    /* Stack copies avoid per event heap growth on the hot path. */
    /* Full queues count one drop in the gauge with no core effect. */
    /* Short payloads drop with no state change. */
    fn forward_event(
        data: &[u8],
        tx: &crossbeam::channel::Sender<[u8; EVENT_LEN]>,
        drops: &Arc<AtomicU64>,
    ) -> i32 {
        if data.len() < EVENT_LEN {
            return 0;
        }
        let mut buf = [0u8; EVENT_LEN];
        buf.copy_from_slice(&data[..EVENT_LEN]);
        if tx.try_send(buf).is_err() {
            drops.fetch_add(1, Ordering::Relaxed);
        }
        0
    }

    /* Build one polling handle over both notify rings. */
    /* Stack copies carry fixed payloads into the bounded queue. */
    /* Full queues drop with gauge solely and no core effect. */
    /* Faulty maps yield empty with progress preserved through fail open. */
    fn build_rings(
        skel: &BpfSkel<'a>,
        ev_tx: crossbeam::channel::Sender<[u8; EVENT_LEN]>,
        ev_drops: Arc<AtomicU64>,
    ) -> Option<libbpf_rs::RingBuffer<'a>> {
        let mut bld = libbpf_rs::RingBufferBuilder::new();
        let tx_a = ev_tx.clone();
        let drops_a = ev_drops.clone();
        if bld
            .add(&skel.maps.flow_enq_rb, move |data| {
                Self::forward_event(data, &tx_a, &drops_a)
            })
            .is_err()
        {
            return None;
        }
        let tx_b = ev_tx;
        let drops_b = ev_drops;
        if bld
            .add(&skel.maps.flow_cmp_rb, move |data| {
                Self::forward_event(data, &tx_b, &drops_b)
            })
            .is_err()
        {
            return None;
        }
        bld.build().ok()
    }

    /* Seed one topology row per CPU into the BPF view. */
    /* Each row carries the thread sibling and the node identifier. */
    /* Faulty updates keep the BPF default. */
    fn seed_topo_with(skel: &mut BpfSkel<'_>, rows: &[(u32, u32, u32)]) {
        use libbpf_rs::MapCore;
        for (cpu, sib, node) in rows {
            let key = cpu.to_ne_bytes();
            let mut val = [0u8; 8];
            val[0..4].copy_from_slice(&sib.to_ne_bytes());
            val[4..8].copy_from_slice(&node.to_ne_bytes());
            if let Err(e) = skel
                .maps
                .topo_stor
                .update(&key, &val, libbpf_rs::MapFlags::ANY)
            {
                log::warn!("topo seed failed for cpu {cpu}: {e}");
            }
        }
    }

    /* Decode one ring payload into kind, sequence, pid, */
    /* CPU, weight, runnable, time. Short payloads drop. */
    /* Host endian passes through the ring with zero conversion as BPF */
    /* plus userspace share one host and the ring never crosses hosts. */
    fn decode_event(data: &[u8]) -> Option<(u64, u64, u32, u32, u32, u32, u64)> {
        if data.len() < EVENT_LEN {
            return None;
        }
        let kind = u64::from_ne_bytes(data[0..8].try_into().ok()?);
        let seq = u64::from_ne_bytes(data[8..16].try_into().ok()?);
        let pid = u32::from_ne_bytes(data[16..20].try_into().ok()?);
        let cpu = u32::from_ne_bytes(data[20..24].try_into().ok()?);
        let weight = u32::from_ne_bytes(data[24..28].try_into().ok()?);
        let pad = u32::from_ne_bytes(data[28..32].try_into().ok()?);
        let at = u64::from_ne_bytes(data[32..40].try_into().ok()?);
        Some((kind, seq, pid, cpu, weight, pad, at))
    }

    /* Apply one decoded notify to the daemon mirror solely. */
    /* Enqueue derives the hint from the task weight and caches the */
    /* row then mirrors admission for observability with no core */
    /* effect. Complete mirrors the share drop for observability. */
    /* Gaps stay observability solely with loss irrelevant. Reserved */
    /* plus unknown kinds hold at the core with progress kept. */
    /* Rejects park with no run in the core. */
    fn handle_event(&mut self, data: &[u8]) {
        let Some((kind, seq, pid, cpu, weight, pad, at)) = Self::decode_event(data) else {
            return;
        };
        let _ = self.daemon.note_seq(seq);
        if kind == flow::PROTO_ENQUEUE {
            let hint = flow::hint_period_us(weight) as u32;
            self.daemon.hints_mut().insert(pid as u64, hint as u64);
            let time = if at != 0 { at } else { Self::mono_ns() };
            let _ = self.daemon.handle_enqueue(pid, hint, cpu, time, seq);
        } else if kind == flow::PROTO_COMPLETE {
            let runnable = pad != 0;
            let time = if at != 0 { at } else { Self::mono_ns() };
            self.daemon.handle_complete(pid, time, runnable);
        } else {
            let action = flow::fail_open(&flow::FailReason::BadKey);
            debug_assert_eq!(action, flow::FailAction::HoldKick);
        }
    }

    /* Monotonic time in nanos since boot with zero on fault. */
    /* Shares the domain with the core clock for deadlines. */
    fn mono_ns() -> u64 {
        unsafe {
            let mut ts = std::mem::MaybeUninit::<libc::timespec>::uninit();
            if libc::clock_gettime(libc::CLOCK_MONOTONIC, ts.as_mut_ptr()) == 0 {
                let ts = ts.assume_init();
                (ts.tv_sec as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(ts.tv_nsec as u64)
            } else {
                0
            }
        }
    }

    /* Note one ring stall for observability solely. */
    /* Missing rings plus poll faults reach here with no park since */
    /* dispatch runs independent of the ring with loss irrelevant. */
    fn note_daemon_lag(&mut self) {
        let action = flow::fail_open(&flow::FailReason::DaemonLag);
        debug_assert_eq!(action, flow::FailAction::ParkFifo);
    }

    /* Drain available ring events into the mirror. */
    /* Polls kernel rings then drains until empty or cap with remainder */
    /* deferred to the next poll. Queue drops fold into the drop gauge */
    /* with parks from the core as source of truth. Missing rings plus */
    /* poll faults stay observability solely with no park since dispatch */
    /* runs independent. Dashboard backpressure drops the frame solely */
    /* with no park. Backlog is the channel length and drop rate is the */
    /* parks delta with zero wire change. */
    fn drain_rings(&mut self) {
        if let Some(rb) = self.rings.as_ref() {
            if rb.consume().is_err() {
                self.note_daemon_lag();
            }
        } else {
            self.note_daemon_lag();
        }
        let dropped = self.ev_drops.swap(0, Ordering::Relaxed);
        for _ in 0..dropped {
            self.daemon.note_ev_drop();
        }
        for _ in 0..flow::DRAIN_CAP {
            match self.ev_rx.try_recv() {
                Ok(data) => self.handle_event(&data),
                Err(_) => break,
            }
        }
    }

    /* Push one dashboard snapshot when past freshness. */
    /* Per CPU map reads run solely here so the hot thread stays cheap */
    /* while the page stays fresh at dashboard cadence. Failed sends */
    /* drop the frame solely with no park since dispatch runs */
    /* independent. */
    fn push_web_if_due(&mut self) {
        let Some(ref tx) = self.webui_tx else {
            return;
        };
        if self.last_web.elapsed() < Duration::from_millis(WEB_CACHE_MS) {
            return;
        }
        let web = self.get_web_metrics();
        self.last_web = Instant::now();
        let _ = tx.try_send(web);
    }

    /* Collect stale mirror rows past grace at a slow cadence. */
    /* Lost completes return shares here in the mirror for */
    /* observability solely with no core revoke. Core drops through */
    /* stopping plus disable plus exit exactly once. */
    fn maybe_gc(&mut self) {
        if self.last_gc.elapsed() < Duration::from_millis(GC_INTERVAL_MS) {
            return;
        }
        self.last_gc = Instant::now();
        let now = Self::mono_ns();
        let removed = self.daemon.gc_stale(now);
        let (admits, rejects, misses, parks, drops) = self.daemon.mirror_counts();
        log::debug!(
            "stale collected={} admits={} rejects={} misses={} parks={} drops={} seq={}",
            removed.len(),
            admits,
            rejects,
            misses,
            parks,
            drops,
            self.daemon.wire_last()
        );
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        /* Ring polls run each short tick decoupled from dashboard */
        /* cadence. Stats replies use cheap counter reads each request. */
        /* Per CPU cards refresh through the cache at dashboard cadence. */
        /* Stale rows collect at a slow cadence. One BPF read serves */
        /* both the stats reply plus the page. */
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            self.drain_rings();
            self.maybe_gc();
            match req_ch.recv_timeout(Duration::from_millis(RING_POLL_MS)) {
                Ok(()) => {
                    let stats = self.get_metrics();
                    self.push_web_if_due();
                    res_ch.send(stats)?
                }
                Err(RecvTimeoutError::Timeout) => {
                    self.push_web_if_due();
                }
                Err(e) => Err(e)?,
            }
        }
        self.drain_rings();
        let m = self.get_metrics();
        info!(
            "exit ins={} req={} done={} over={} kick={} adm={} rej={} miss={} park={} gate={} veb={} fifo={} runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.over_moves,
            m.kicks,
            m.admits,
            m.rejects,
            m.misses,
            m.parks,
            m.gate_rejects,
            m.veb_hits,
            m.fifo_parks,
            m.total_runtime,
            m.on_cpu,
        );
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
            SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }
    let only = opts.monitor.is_some();
    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }
    if opts.help_stats {
        println!("stats: top");
        return Ok(());
    }
    if !only {
        simplelog::SimpleLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
        )?;
        info!("{} {}", SCHEDULER_NAME, full_version());
        info!("Starting {} scheduler", SCHEDULER_NAME);
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || {
        sd.store(true, Ordering::Relaxed);
    })?;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(Duration::from_secs_f64(intv), sd) {
                log::warn!("monitor failed: {e}");
            }
        });
        if only {
            let _ = jh.join();
            return Ok(());
        }
    }
    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object, shutdown.clone())?;
    sched.run(shutdown)?;
    info!("Scheduler exited");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_name_is_flow() {
        assert_eq!(SCHEDULER_NAME, "scx_flow");
    }

    #[test]
    fn max_cpus_matches_header() {
        assert_eq!(
            MAX_CPUS,
            crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize
        );
    }

    #[test]
    fn batch_matches_header() {
        assert_eq!(
            crate::config::Config::default().dispatch_batch,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH
        );
        assert_eq!(crate::config::Config::default().dispatch_batch, 16);
        assert_eq!(
            crate::flow::DISPATCH_BATCH as u64,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH as u64
        );
        assert_eq!(
            crate::flow::DISPATCH_PROBES as u64,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_PROBES as u64
        );
        assert_eq!(crate::flow::DISPATCH_PROBES, 20);
        assert_eq!(crate::bpf_intf::flow_consts_FLOW_VEB_EMPTY, 0xFFFFFFFF);
    }

    #[test]
    fn quantum_matches_header() {
        assert_eq!(
            crate::flow::slice::QUANTUM_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_NS as u64
        );
        assert_eq!(crate::flow::slice::QUANTUM_NS, 2_000_000);
        assert_eq!(crate::flow::slice::WEIGHT_BASE, 128);
        assert_eq!(crate::flow::slice::WEIGHT_MIN, 1);
        assert_eq!(crate::flow::slice::WEIGHT_MAX, 16_384);
        assert_eq!(
            crate::flow::edf::ADMIT_PERMILLE,
            crate::bpf_intf::flow_consts_FLOW_ADMIT_PERMILLE as u64
        );
        assert_eq!(crate::flow::edf::ADMIT_PERMILLE, 950);
    }

    #[test]
    fn slot_matches_header() {
        assert_eq!(
            crate::flow::slot::SLOT_OVERFLOW,
            crate::bpf_intf::flow_consts_FLOW_OVERFLOW as u64
        );
        assert_eq!(crate::flow::slot::SLOT_OVERFLOW, 0x5A01);
        assert_eq!(
            crate::flow::slot::SLOT_MACHINE,
            crate::bpf_intf::flow_consts_FLOW_MACHINE as u64
        );
        assert_eq!(
            crate::flow::slot::SLOT_MAX_DSQS,
            crate::bpf_intf::flow_consts_FLOW_MAX_DSQS as u64
        );
        assert_eq!(crate::flow::slot::SLOT_MAX_DSQS, 522);
    }

    #[test]
    fn period_matches_header() {
        assert_eq!(
            crate::flow::edf::PERIOD_NS,
            crate::bpf_intf::flow_consts_FLOW_PERIOD_NS as u64
        );
        assert_eq!(crate::flow::edf::PERIOD_NS, 16_000_000);
    }

    #[test]
    fn task_size_is_24() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 24);
    }

    #[test]
    fn cpu_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>(), 8);
    }

    #[test]
    fn topo_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_topo>(), 8);
    }

    #[test]
    fn sched_stats_size_is_112() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            112
        );
    }

    #[test]
    fn order_is_deadline_only() {
        let mut d = crate::flow::Daemon::new();
        d.handle_enqueue(1, 32000, 0, 1_000_000, 101);
        d.handle_enqueue(2, 4000, 0, 1_000_000, 102);
        assert_eq!(d.peek_order().unwrap().pid, 2);
    }

    #[test]
    fn hint_matches_header() {
        assert_eq!(
            crate::flow::cgrp::HINT_MAX,
            crate::bpf_intf::flow_consts_FLOW_HINT_MAX as u64
        );
    }

    #[test]
    fn proto_matches_header() {
        assert_eq!(
            crate::flow::PROTO_ENQUEUE,
            crate::bpf_intf::flow_consts_FLOW_PROTO_ENQUEUE as u64
        );
        assert_eq!(
            crate::flow::PROTO_ORDER,
            crate::bpf_intf::flow_consts_FLOW_PROTO_ORDER as u64
        );
        assert_eq!(
            crate::flow::PROTO_DISPATCH,
            crate::bpf_intf::flow_consts_FLOW_PROTO_DISPATCH as u64
        );
        assert_eq!(
            crate::flow::PROTO_COMPLETE,
            crate::bpf_intf::flow_consts_FLOW_PROTO_COMPLETE as u64
        );
        assert_eq!(
            crate::flow::SEQ_INIT,
            crate::bpf_intf::flow_consts_FLOW_SEQ_INIT as u64
        );
        assert_eq!(
            crate::flow::ORDER_DEPTH_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_ORDER_DEPTH as u64
        );
        assert_eq!(
            crate::flow::TASKS_CAP as u64,
            crate::bpf_intf::flow_consts_FLOW_ORDER_CAP as u64
        );
        assert_eq!(
            crate::flow::VEB_U as u64,
            crate::bpf_intf::flow_consts_FLOW_VEB_U as u64
        );
        assert_eq!(
            crate::flow::QUANT_SHIFT as u64,
            crate::bpf_intf::flow_consts_FLOW_QUANT_SHIFT as u64
        );
        assert_eq!(crate::flow::PROTO_ENQUEUE, 1);
        assert_eq!(crate::flow::PROTO_ORDER, 2);
        assert_eq!(crate::flow::PROTO_DISPATCH, 3);
        assert_eq!(crate::flow::PROTO_COMPLETE, 4);
    }

    #[test]
    fn order_entry_matches_header() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_order_entry>(), 24);
        assert_eq!(
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH as usize,
            crate::flow::DISPATCH_BATCH
        );
        assert_eq!(crate::flow::DISPATCH_BATCH, 16);
    }

    #[test]
    fn event_decode_round_trip() {
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&1u64.to_ne_bytes());
        buf[8..16].copy_from_slice(&7u64.to_ne_bytes());
        buf[16..20].copy_from_slice(&123u32.to_ne_bytes());
        buf[20..24].copy_from_slice(&2u32.to_ne_bytes());
        buf[24..28].copy_from_slice(&128u32.to_ne_bytes());
        buf[28..32].copy_from_slice(&1u32.to_ne_bytes());
        buf[32..40].copy_from_slice(&999u64.to_ne_bytes());
        let got = Scheduler::decode_event(&buf).unwrap();
        assert_eq!(got, (1, 7, 123, 2, 128, 1, 999));
        assert!(Scheduler::decode_event(&buf[..10]).is_none());
    }
}
