// SPDX-License-Identifier: GPL-2.0
//! Loading and running the scx_flow BPF scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::mem::MaybeUninit;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use crossbeam::channel::RecvTimeoutError;
use log::debug;
use log::info;
use log::warn;
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use crate::BpfSkel;
use crate::BpfSkelBuilder;
use crate::bpf_intf;
use crate::cli::Opts;
use crate::cli::SCHEDULER_NAME;
use crate::lstopo::LstopoView;
use crate::stats::Metrics;
use crate::topology::BpfTopology;

/// Topology lines printed at startup before the rest is summarized.
const TOPO_LOG_LINES: usize = 64;

/// Largest lstopo output that is parsed.
const LSTOPO_MAX_BYTES: usize = 1 << 20;

pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
}

fn run_lstopo(timeout: &str, lstopo: &str) -> Option<Vec<u8>> {
    Command::new(timeout)
        .args(["10s", lstopo])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| out.stdout)
}

/// Cache sizes from lstopo-no-graphics, used only for the startup log. The
/// tool is optional, so any failure just leaves the sizes unknown. The
/// scheduler runs as root, so the system binaries are tried before PATH.
fn fetch_lstopo_view() -> Option<LstopoView> {
    let out = run_lstopo("/usr/bin/timeout", "/usr/bin/lstopo-no-graphics")
        .or_else(|| run_lstopo("timeout", "lstopo-no-graphics"))?;
    let len = out.len().min(LSTOPO_MAX_BYTES);

    crate::lstopo::parse_lstopo_text(&String::from_utf8_lossy(&out[..len])).ok()
}

fn log_lines(level: log::Level, (lines, total): (Vec<String>, usize)) {
    let shown = lines.len();

    for line in lines {
        log::log!(level, "Topology: {line}");
    }
    if total > shown {
        log::log!(level, "Topology: ...+{} more", total - shown);
    }
}

fn log_topology(topo: &Topology) {
    info!("Topology: {}", crate::topology::describe_topo_summary(topo));
    log_lines(
        log::Level::Info,
        crate::topology::render_per_core_lines(topo, fetch_lstopo_view().as_ref(), TOPO_LOG_LINES),
    );
    if log::log_enabled!(log::Level::Debug) {
        log_lines(
            log::Level::Debug,
            crate::topology::render_topo_lines(topo, TOPO_LOG_LINES),
        );
    }
}

impl<'a> Scheduler<'a> {
    pub fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        let nr_cpus = *NR_CPU_IDS;
        let max_cpus = bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

        if nr_cpus > max_cpus {
            bail!("found {nr_cpus} possible CPUs, at most {max_cpus} are supported");
        }

        // Without a topology every CPU is treated as part of a single LLC.
        let topo = Topology::new()
            .inspect_err(|e| warn!("topology discovery failed, assuming a single LLC: {e:#}"))
            .ok();
        let tables = topo.as_ref().map(BpfTopology::new).transpose()?;

        try_set_rlimit_infinity();
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)
            .context("failed to open BPF object (check dmesg)")?;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF read-only data is not mapped")?;
        rodata.flow_nr_cpus = nr_cpus as u32;
        if let Some(t) = tables.as_ref() {
            rodata.flow_nr_llcs = t.nr_llcs;
            rodata.flow_nr_groups = t.nr_groups;
            for (cpu, llc) in &t.cpu_llc {
                if let Some(slot) = rodata.flow_cpu_llc.get_mut(*cpu) {
                    *slot = *llc;
                }
            }
            for (cpu, group) in &t.cpu_group {
                if let Some(slot) = rodata.flow_cpu_group.get_mut(*cpu) {
                    *slot = *group;
                }
            }
            for (slot, node) in rodata.flow_llc_node.iter_mut().zip(&t.llc_node) {
                *slot = *node;
            }
        }

        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        if let Some(t) = topo.as_ref() {
            log_topology(t);
        }
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(crate::stats::server_data()).launch()?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn log_per_llc(&self) {
        if !log::log_enabled!(log::Level::Debug) {
            return;
        }
        for (llc, row) in crate::metrics::collect_per_llc(&self.skel)
            .iter()
            .enumerate()
        {
            let mut buf: Vec<u8> = Vec::new();
            if row.format_llc(&mut buf, llc).is_ok() {
                debug!("{}", String::from_utf8_lossy(&buf).trim_end());
            }
        }
    }

    pub fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    res_ch.send(crate::metrics::collect(&self.skel))?;
                    self.log_per_llc();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

/// Run the scheduler until it is told to stop, restarting it when the
/// kernel asks for a restart.
pub fn drive(opts: &Opts) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || sd.store(true, Ordering::Relaxed))
        .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let dur = crate::cli::poll_interval_secs(intv)?;
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = crate::stats::monitor(dur, sd) {
                warn!("monitor failed: {e:#}");
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    loop {
        let mut sched = Scheduler::init(opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    info!("Scheduler exited");
    Ok(())
}
