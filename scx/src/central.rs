// SPDX-License-Identifier: GPL-2.0
//! The central cores of --unslice.
//!
//! Every wakeup waits for a central CPU to dispatch it, so the central
//! cores are kept out of deep idle states while the scheduler runs. Their
//! CPUs get a PM QoS resume latency that only the shallowest idle state
//! meets, and the old limits are written back when the scheduler stops.
//! They are also kept in a file under /run, so that the next start writes
//! them back when the scheduler was killed before it could. At startup, the
//! central core of each domain is reported along with whether the kernel
//! lets the workers stop their tick.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeSet;
use std::fs;

use log::info;
use log::warn;
use scx_utils::Topology;

use crate::topology::CentralDomain;
use crate::topology::cpu_list;

/// The limits that ShallowIdle replaced, one "path value" line each. /run
/// is emptied at boot, which also resets the limits.
const SAVED_LIMITS: &str = "/run/scx_flow/pmqos";

fn cpu_dir(cpu: usize) -> String {
    format!("/sys/devices/system/cpu/cpu{cpu}")
}

/// Exit latency in microseconds of the shallowest enabled idle state of
/// @cpu that does not poll, if cpuidle lists one.
fn shallow_exit_latency_us(cpu: usize) -> Option<u32> {
    let dir = format!("{}/cpuidle", cpu_dir(cpu));

    for state in 0.. {
        let read = |file: &str| fs::read_to_string(format!("{dir}/state{state}/{file}"));
        let name = read("name").ok()?;
        if name.trim() == "POLL" || read("disable").is_ok_and(|d| d.trim() != "0") {
            continue;
        }
        return read("latency").ok()?.trim().parse().ok();
    }
    None
}

/// The resume latency limit that @current asks for already admits only
/// states that wake up within @limit_us. "n/a" admits no latency at all,
/// and zero admits any.
fn already_strict(current: &str, limit_us: u32) -> bool {
    current == "n/a"
        || current
            .parse::<u32>()
            .is_ok_and(|us| us != 0 && us <= limit_us)
}

/// Whether `path` is the PM QoS resume latency file of a CPU.
fn is_limit_path(path: &str) -> bool {
    path.strip_prefix("/sys/devices/system/cpu/cpu")
        .and_then(|rest| rest.strip_suffix("/power/pm_qos_resume_latency_us"))
        .is_some_and(|cpu| !cpu.is_empty() && cpu.bytes().all(|b| b.is_ascii_digit()))
}

/// Remove SAVED_LIMITS once the limits in it are back or were never replaced.
fn forget_saved_limits() {
    if let Err(e) = fs::remove_file(SAVED_LIMITS) {
        warn!("failed to remove {SAVED_LIMITS}: {e}");
    }
}

/// Write back the limits that a scheduler which was killed left behind.
pub fn restore_saved_limits() {
    let Ok(saved) = fs::read_to_string(SAVED_LIMITS) else {
        return;
    };
    for (path, old) in saved.lines().filter_map(|line| line.split_once(' ')) {
        if !is_limit_path(path) {
            continue;
        }
        match fs::write(path, old) {
            Ok(()) => info!("restored {old} in {path}, left behind by an earlier run"),
            Err(e) => warn!("failed to restore {old} in {path}: {e}"),
        }
    }
    forget_saved_limits();
}

/// Save the limits about to be replaced to SAVED_LIMITS.
fn save_limits(limits: &[(String, String)]) -> std::io::Result<()> {
    let lines: String = limits
        .iter()
        .map(|(path, old)| format!("{path} {old}\n"))
        .collect();

    if let Some(dir) = std::path::Path::new(SAVED_LIMITS).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(SAVED_LIMITS, lines)
}

/// Keeps the CPUs of the central cores in their shallowest idle state and
/// writes the old resume latency limits back when dropped.
///
/// The PM QoS resume latency of a CPU is the longest wakeup the idle
/// governor may pick a state for. Zero means no limit and "n/a" means that
/// no latency is accepted, which leaves only polling. The limit is set to
/// the exit latency of the shallowest state that does not poll, and to at
/// least one microsecond so that it is never read as no limit.
pub struct ShallowIdle {
    saved: Vec<(String, String)>,
}

impl ShallowIdle {
    pub fn hold(cpus: &[usize]) -> Self {
        let mut planned = Vec::new();
        let mut saved = Vec::new();

        for &cpu in cpus {
            let path = format!("{}/power/pm_qos_resume_latency_us", cpu_dir(cpu));
            let Ok(current) = fs::read_to_string(&path) else {
                info!(
                    "CPU {cpu} has no PM QoS resume latency file, so its idle states are left alone"
                );
                continue;
            };
            let current = current.trim().to_string();
            let Some(limit_us) = shallow_exit_latency_us(cpu).map(|us| us.max(1)) else {
                info!("CPU {cpu} reports no idle state to hold it in, so its limit is left alone");
                continue;
            };
            if !already_strict(&current, limit_us) {
                planned.push((cpu, path, current, limit_us));
            }
        }

        let old: Vec<(String, String)> = planned
            .iter()
            .map(|(_, path, current, _)| (path.clone(), current.clone()))
            .collect();
        let noted = !old.is_empty()
            && match save_limits(&old) {
                Ok(()) => true,
                Err(e) => {
                    warn!("failed to save the old idle state limits to {SAVED_LIMITS}: {e}");
                    false
                }
            };
        for (cpu, path, current, limit_us) in planned {
            match fs::write(&path, limit_us.to_string()) {
                Ok(()) => {
                    info!("CPU {cpu} only enters idle states that wake up within {limit_us} us");
                    saved.push((path, current));
                }
                Err(e) => warn!("failed to limit the idle states of CPU {cpu}: {e}"),
            }
        }
        if noted && saved.is_empty() {
            forget_saved_limits();
        }
        Self { saved }
    }
}

impl Drop for ShallowIdle {
    fn drop(&mut self) {
        if self.saved.is_empty() {
            return;
        }
        for (path, old) in &self.saved {
            if let Err(e) = fs::write(path, old) {
                warn!("failed to restore {old} in {path}: {e}");
            }
        }
        forget_saved_limits();
    }
}

/// Report the central core of each domain and whether the workers can stop
/// their tick.
pub fn log_central_cores(topo: &Topology, domains: &[CentralDomain]) {
    for (i, domain) in domains.iter().enumerate() {
        let what = if domains.len() > 1 {
            format!(
                "Central core of domain {i} (CPUs {})",
                cpu_list(&domain.cpus.iter().copied().collect())
            )
        } else {
            String::from("Central core")
        };
        let why = match domain.source {
            Some(source) => format!("the fastest core by {source}"),
            None => String::from("the first core, as all cores look equally fast"),
        };
        if domain.cpu() == domain.timer_cpu() {
            info!(
                "{what}: CPU {}, {why}. It schedules for the workers and runs the preemption \
                 timer.",
                domain.cpu(),
            );
        } else {
            info!(
                "{what}: CPUs {}, {why}. CPU {} schedules for the workers and CPU {} runs the \
                 preemption timer.",
                cpu_list(&domain.central.iter().copied().collect()),
                domain.cpu(),
                domain.timer_cpu(),
            );
        }
    }

    // Kernels that can suspend keep the tick of the boot CPU for
    // timekeeping and drop it from nohz_full=, so it is left out.
    let central: BTreeSet<usize> = domains
        .iter()
        .flat_map(|domain| domain.central.iter().copied())
        .collect();
    let workers: BTreeSet<usize> = topo
        .all_cpus
        .keys()
        .copied()
        .filter(|cpu| *cpu != 0 && !central.contains(cpu))
        .collect();
    let nohz: BTreeSet<usize> = fs::read_to_string("/sys/devices/system/cpu/nohz_full")
        .ok()
        .and_then(|list| scx_utils::read_cpulist(list.trim()).ok())
        .unwrap_or_default()
        .into_iter()
        .collect();

    if workers.is_empty() {
        return;
    }
    if workers.is_subset(&nohz) {
        info!("nohz_full lists the workers, so a busy worker can stop its tick.");
        return;
    }
    let boot_cpu_note = if topo.all_cpus.contains_key(&0) && !central.contains(&0) {
        ", which covers every worker but CPU 0, whose tick the kernel keeps for timekeeping"
    } else {
        ""
    };
    info!(
        "The workers keep their tick unless the kernel is booted with nohz_full={}{}.",
        cpu_list(&workers),
        boot_cpu_note,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_limit_files_are_restored() {
        assert!(is_limit_path(
            "/sys/devices/system/cpu/cpu6/power/pm_qos_resume_latency_us"
        ));
        assert!(!is_limit_path("/etc/passwd"));
        assert!(!is_limit_path(
            "/sys/devices/system/cpu/cpu/power/pm_qos_resume_latency_us"
        ));
        assert!(!is_limit_path(
            "/sys/devices/system/cpu/cpu6x/power/pm_qos_resume_latency_us"
        ));
        assert!(!is_limit_path(
            "/sys/devices/system/cpu/cpu6/../../../../etc/power/pm_qos_resume_latency_us"
        ));
    }

    #[test]
    fn strict_limits_are_kept() {
        assert!(already_strict("n/a", 1));
        assert!(already_strict("1", 2));
        assert!(!already_strict("0", 2));
        assert!(!already_strict("50", 2));
        assert!(!already_strict("junk", 2));
    }
}
