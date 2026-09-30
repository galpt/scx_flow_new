// SPDX-License-Identifier: GPL-2.0
//! Flow daemon front end.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Loads the BPF object plus seeds the topology view plus drives the
//! loop. Observability flows through counters plus the loopback
//! dashboard with per CPU cards plus a JSON snapshot for debug.

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
use std::sync::atomic::Ordering;
use std::time::Duration;

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

/* Scheduler owns the skeleton plus the link plus the stats server */
/* plus the dashboard channel plus the daemon order. It drives the */
/* run loop until shutdown or exit. */
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
    /* Daemon order plus admission state. */
    pub(crate) daemon: flow::Daemon,
    /* Event channel from the ring buffers. */
    ev_rx: crossbeam::channel::Receiver<Vec<u8>>,
    /* Ring polling handle with empty on fault. */
    rings: Option<libbpf_rs::RingBuffer<'a>>,
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
        let _ = &mut skel;
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
        /* Queue layout for the start log plus header cover. */
        info!(
            "Queues: {} {} {} {}",
            flow::slot::SLOT_MAX_DSQS,
            flow::slot::SLOT_MACHINE,
            flow::slot::NODE_BASE,
            flow::slot::MAX_NODES
        );
        let _ = flow::slot::machine_dsq();
        let _ = flow::slot::node_dsq(0);
        let _ = flow::slot::slot_nr_dsqs();
        let _ = flow::slot::dsq_valid(flow::slot::machine_dsq());
        /* Ring buffers carry enqueue plus complete notifies. */
        /* Faulty setup keeps FIFO progress at the core. */
        let (ev_tx, ev_rx) = crossbeam::channel::unbounded::<Vec<u8>>();
        let rings = Self::build_rings(&skel, ev_tx);
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
            rings,
        })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /* Build one polling handle over both notify rings. */
    /* Faulty maps yield empty with FIFO progress preserved. */
    fn build_rings(
        skel: &BpfSkel<'a>,
        ev_tx: crossbeam::channel::Sender<Vec<u8>>,
    ) -> Option<libbpf_rs::RingBuffer<'a>> {
        let mut bld = libbpf_rs::RingBufferBuilder::new();
        let tx_a = ev_tx.clone();
        if bld
            .add(&skel.maps.flow_enq_rb, move |data| {
                let _ = tx_a.send(data.to_vec());
                0
            })
            .is_err()
        {
            return None;
        }
        let tx_b = ev_tx;
        if bld
            .add(&skel.maps.flow_cmp_rb, move |data| {
                let _ = tx_b.send(data.to_vec());
                0
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

    /* Decode one ring payload into kind plus sequence plus pid plus */
    /* CPU plus weight plus runnable plus time. Short payloads drop. */
    fn decode_event(data: &[u8]) -> Option<(u64, u64, u32, u32, u32, u32, u64)> {
        if data.len() < 40 {
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

    /* Apply one decoded notify to the daemon. */
    /* Enqueue derives the hint from the task weight and caches the */
    /* row before admission. Complete drops the stored share. Gaps */
    /* resync through the fail open matrix. Faulty payloads drop with */
    /* FIFO progress preserved at the core. */
    fn handle_event(&mut self, data: &[u8]) {
        let Some((kind, seq, pid, cpu, weight, pad, at)) = Self::decode_event(data) else {
            return;
        };
        let _ = self.daemon.note_seq(seq);
        if kind == flow::PROTO_ENQUEUE {
            if cpu as u64 >= flow::slot::MAX_CPUS {
                let _ = flow::fail_open(&flow::FailReason::BadCpu);
            }
            let hint = flow::hint_period_us(weight) as u32;
            let _ = self.daemon.share_for(hint);
            let _ = self.daemon.hints_mut().insert(pid as u64, hint as u64);
            let time = if at != 0 { at } else { Self::now_ns() };
            let _ = self.daemon.handle_enqueue(pid, hint, cpu, time, weight);
            let live: Vec<i32> = self.online_cpus.iter().map(|c| *c as i32).collect();
            let depths = vec![0u64; live.len()];
            let bound = flow::SHARED_SCAN_BOUND as usize;
            let live_b = if live.len() > bound {
                &live[..bound]
            } else {
                &live[..]
            };
            let depths_b = if depths.len() > bound {
                &depths[..bound]
            } else {
                &depths[..]
            };
            let _ = self
                .daemon
                .pick_cpu(&[], cpu as i32, &live, live_b, depths_b, at, time);
            let _ = self.daemon.should_kick(at, at.saturating_add(1));
            let _ = self.daemon.queue_for(cpu);
            let _ = self.daemon.admitted(cpu);
            let _ = self.daemon.queue_len();
        } else if kind == flow::PROTO_COMPLETE {
            let runnable = pad != 0;
            let time = if at != 0 { at } else { Self::now_ns() };
            self.daemon
                .handle_complete(pid, time, runnable, flow::QUANTUM_NS);
        } else if kind == flow::PROTO_ORDER || kind == flow::PROTO_DISPATCH {
            let _ = flow::fail_open(&flow::FailReason::BadKey);
            let _ = flow::slot::dsq_valid(flow::slot::machine_dsq());
            let _ = flow::slot::node_dsq(0);
            let _ = flow::slot::slot_nr_dsqs();
        } else {
            let _ = flow::fail_open(&flow::FailReason::BadKey);
        }
        let _ = self.daemon.peek_order();
        let _ = flow::DISPATCH_BATCH;
    }

    /* Wall time in nanos since epoch with zero on fault. */
    fn now_ns() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_nanos().min(u64::MAX as u128) as u64)
            .unwrap_or(0)
    }

    /* Drain available ring events into the daemon. */
    /* Bounded per pass by the dispatch batch. Faults keep FIFO. */
    fn drain_rings(&mut self) {
        if let Some(rb) = &self.rings {
            let _ = rb.consume();
        } else {
            let _ = flow::fail_open(&flow::FailReason::DaemonLag);
        }
        if self.webui_tx.as_ref().is_some_and(|tx| tx.is_full()) {
            let _ = flow::fail_open(&flow::FailReason::RingFull);
        }
        for _ in 0..flow::DISPATCH_BATCH {
            match self.ev_rx.try_recv() {
                Ok(data) => self.handle_event(&data),
                Err(_) => break,
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        /* Short tick keeps stats polls prompt while the page polls */
        /* once per second. Each tick drains ring events into the */
        /* daemon then serves the stats reply plus the page. One BPF */
        /* read serves both the stats reply plus the page. */
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            self.drain_rings();
            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    if let Some(ref tx) = self.webui_tx {
                        if !tx.is_full() {
                            let web = self.get_web_metrics();
                            let stats = web.stats.clone();
                            let _ = tx.try_send(web);
                            res_ch.send(stats)?
                        } else {
                            res_ch.send(self.get_metrics())?
                        }
                    } else {
                        res_ch.send(self.get_metrics())?
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(ref tx) = self.webui_tx
                        && !tx.is_full()
                    {
                        let web = self.get_web_metrics();
                        let _ = tx.try_send(web);
                    }
                }
                Err(e) => Err(e)?,
            }
        }
        self.drain_rings();
        let m = self.get_metrics();
        info!(
            "exit ins={} req={} done={} local={} node={} machine={} over={} kick={} adm={} rej={} miss={} park={} gate={} runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.local_moves,
            m.node_moves,
            m.machine_moves,
            m.over_moves,
            m.kicks,
            m.admits,
            m.rejects,
            m.misses,
            m.parks,
            m.gate_rejects,
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
    fn task_size_is_16() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 16);
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
    fn sched_stats_size_is_120() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            120
        );
    }

    #[test]
    fn kick_rule_matches_header() {
        assert!(crate::flow::arrival_kicks(10, 20));
        assert!(!crate::flow::arrival_kicks(20, 20));
    }

    #[test]
    fn runtime_advance_matches_base() {
        assert_eq!(crate::flow::runtime_advance(0, 2_000_000, 128), 2_000_000);
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
            crate::flow::PROTO_ENQUEUE as u64,
            crate::bpf_intf::flow_consts_FLOW_PROTO_ENQUEUE as u64
        );
        assert_eq!(
            crate::flow::PROTO_ORDER as u64,
            crate::bpf_intf::flow_consts_FLOW_PROTO_ORDER as u64
        );
        assert_eq!(
            crate::flow::PROTO_DISPATCH as u64,
            crate::bpf_intf::flow_consts_FLOW_PROTO_DISPATCH as u64
        );
        assert_eq!(
            crate::flow::PROTO_COMPLETE as u64,
            crate::bpf_intf::flow_consts_FLOW_PROTO_COMPLETE as u64
        );
        assert_eq!(
            crate::flow::SEQ_INIT as u64,
            crate::bpf_intf::flow_consts_FLOW_SEQ_INIT as u64
        );
        assert_eq!(
            crate::flow::ORDER_DEPTH_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_ORDER_DEPTH as u64
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
