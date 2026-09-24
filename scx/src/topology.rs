// SPDX-License-Identifier: GPL-2.0
//! Trimmed topology for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Seeds display only CPU cards and reads governors with no placement use.

use log::warn;
use scx_utils::Topology;

/// Compile time CPU bound. Matches the BPF header.
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

/// True when a lower id shares the core.
fn has_older(topo: &Topology, id: usize, core: usize) -> bool {
    topo.all_cpus
        .iter()
        .any(|(oid, o)| o.core_id == core && *oid < id)
}

/// Static per CPU cards seeded once at attach.
/// Max frequency, cache domain, and thread role come from the host.
/// Zero frequency means unknown and stays display only.
/// Failures yield an empty list, so the scheduler keeps running.
/// Live frequency stays display only and never shapes placement.
pub fn web_cpu_static() -> Vec<crate::stats::PerCpuMetrics> {
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(e) => {
            warn!("topology failed, web cards empty: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (id, cpu) in topo.all_cpus.iter() {
        if *id >= MAX_CPUS {
            continue;
        }
        let smt = has_older(&topo, *id, cpu.core_id);
        out.push(crate::stats::PerCpuMetrics {
            id: *id as u32,
            freq_khz: cpu.max_freq as u64,
            cur_freq_khz: 0,
            llc_id: cpu.llc_id as u32,
            smt,
            running_pid: 0,
            slice_ns: crate::flow::SLICE_NS,
        });
    }
    out.sort_by_key(|e| e.id);
    out
}

/// One line topology summary for the start log.
/// Counts CPUs and notes sibling and frequency state in plain words.
/// Unknown frequency stays unknown and never prints as zero.
/// Missing cards stay unknown.
pub fn describe_topology(cards: &[crate::stats::PerCpuMetrics]) -> String {
    if cards.is_empty() {
        return "topology unknown, plain per-CPU".to_string();
    }
    let count = cards.len();
    let smt = cards.iter().any(|c| c.smt);
    let freq = cards.iter().any(|c| c.freq_khz != 0);
    let cpu_word = if count == 1 { "CPU" } else { "CPUs" };
    let smt_word = if smt { "SMT" } else { "no SMT" };
    let freq_word = if freq { "freq known" } else { "freq unknown" };
    format!(
        "topology: {} {}, {}, {}",
        count, cpu_word, smt_word, freq_word
    )
}

/// Parse a frequency string in kilohertz.
/// Trims space and parses the number. Bad input yields zero for unknown.
pub fn parse_freq_khz(s: &str) -> u64 {
    s.trim().parse().unwrap_or(0)
}

/// Base governor without the diagnostic suffix.
/// Trims space and cuts at the paren and space.
/// Empty stays empty with no trap.
pub fn governor_base(g: &str) -> &str {
    let t = g.trim();
    if let Some(idx) = t.find('(') {
        return t[..idx].trim();
    }
    if let Some(idx) = t.find(' ') {
        return t[..idx].trim();
    }
    t
}

/// Platform profile once per tick.
/// The file is machine global with one value for all CPUs.
/// Missing files yield nothing with no trap.
pub fn read_platform_profile() -> Option<String> {
    std::fs::read_to_string("/sys/firmware/acpi/platform_profile")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Governor of one CPU with a given platform value.
/// Reads the scaling governor and EPP files per CPU.
/// Missing files yield unknown and no suffix with no trap.
/// The suffix is display only and never feeds the base check.
pub fn read_governor_with_profile(cpu: u32, platform: Option<&str>) -> String {
    let base = std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "scaling_governor"
    ))
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .unwrap_or_else(|| "unknown".to_string());
    if base == "unknown" {
        return base;
    }
    let epp = std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "energy_performance_preference"
    ))
    .ok()
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());
    let pp = platform
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match (epp, pp) {
        (Some(e), Some(p)) => format!("{base} (epp:{e} pp:{p})"),
        (Some(e), None) => format!("{base} (epp:{e})"),
        (None, Some(p)) => format!("{base} (pp:{p})"),
        (None, None) => base,
    }
}

/// Governors for one tick with one platform read.
/// Calls the provider exactly once per collection.
pub fn collect_governors_with<F>(cpus: &[u32], mut provider: F) -> Vec<String>
where
    F: FnMut() -> Option<String>,
{
    let platform = provider();
    cpus.iter()
        .map(|&id| read_governor_with_profile(id, platform.as_deref()))
        .collect()
}

/// Governors for one tick over online CPUs.
/// Reads the platform profile once per call.
pub fn collect_governors(cpus: &[u32]) -> Vec<String> {
    collect_governors_with(cpus, read_platform_profile)
}

/// True when every governor reads performance.
/// Needs a non empty list with each base at performance.
/// The EPP and platform suffix never feeds this check.
pub fn perf_unanimous(governors: &[String]) -> bool {
    if governors.is_empty() {
        return false;
    }
    for g in governors {
        if governor_base(g) != "performance" {
            return false;
        }
    }
    true
}

/// Display governor for the dashboard and snapshot.
/// Empty reads as unknown. Unanimous with same suffix reads as the first
/// full string. Mixed bases read as mixed with no list.
pub fn display_governor(governors: &[String]) -> String {
    if governors.is_empty() {
        return "unknown".to_string();
    }
    let first = governor_base(&governors[0]).to_string();
    let mut same = true;
    for g in governors.iter().skip(1) {
        if governor_base(g) != first {
            same = false;
            break;
        }
    }
    if !same {
        return "mixed".to_string();
    }
    if first == "unknown" || first.is_empty() {
        return "unknown".to_string();
    }
    if governors.len() == 1 {
        return governors[0].clone();
    }
    let mut suffix_same = true;
    for g in governors.iter().skip(1) {
        if g != &governors[0] {
            suffix_same = false;
            break;
        }
    }
    if suffix_same {
        return governors[0].clone();
    }
    first
}

/// Parse one CPU list from sysfs.
/// Accepts comma and range form such as 0-7, 0,2,4, and 0-3,8-11.
/// Bad tokens stay out with no trap. Sorted with no dup.
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo_s, hi_s)) = part.split_once('-') {
            let lo: u32 = match lo_s.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let hi: u32 = match hi_s.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            if lo > hi {
                continue;
            }
            for id in lo..=hi {
                if (id as usize) < MAX_CPUS {
                    out.push(id);
                }
            }
        } else {
            match part.parse::<u32>() {
                Ok(id) => {
                    if (id as usize) < MAX_CPUS {
                        out.push(id);
                    }
                }
                Err(_) => continue,
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Read one CPU list file from sysfs.
/// Missing files yield empty with no trap.
pub fn read_cpu_list_file(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| parse_cpu_list(&s))
        .unwrap_or_default()
}

/// Online CPUs once at init.
/// Reads the online file a single time. Missing files fall back to
/// topology cards with no trap. Sorted with no dup.
pub fn online_cpus() -> Vec<u32> {
    let mut out = read_cpu_list_file("/sys/devices/system/cpu/online");
    if !out.is_empty() {
        return out;
    }
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    out = topo
        .all_cpus
        .keys()
        .map(|&id| id as u32)
        .filter(|&id| (id as usize) < MAX_CPUS)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Possible CPUs from sysfs.
/// Missing files fall back to online with no trap.
pub fn possible_cpus() -> Vec<u32> {
    let out = read_cpu_list_file("/sys/devices/system/cpu/possible");
    if !out.is_empty() {
        return out;
    }
    online_cpus()
}

/// Possible CPU count for the start log.
/// Holds max id and one capped at the CPU bound.
pub fn possible_nr() -> usize {
    let poss = possible_cpus();
    if let Some(&m) = poss.iter().max() {
        return (m as usize + 1).min(MAX_CPUS);
    }
    let on = online_cpus();
    if let Some(&m) = on.iter().max() {
        return (m as usize + 1).min(MAX_CPUS);
    }
    0
}

/// Live frequency of one CPU in kilohertz.
/// Reads the cpufreq file. Missing files yield zero for unknown.
/// The value is display only and never feeds placement.
pub fn current_freq_khz(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "scaling_cur_freq"
    ))
    .ok()
    .map(|s| parse_freq_khz(&s))
    .unwrap_or(0)
}

/// Filter cards to an allowed subset for tests.
/// Keeps cards whose id is marked in the mask.
#[cfg(test)]
pub fn filter_allowed(
    cards: &[crate::stats::PerCpuMetrics],
    allowed: &[bool],
) -> Vec<crate::stats::PerCpuMetrics> {
    cards
        .iter()
        .filter(|c| allowed.get(c.id as usize).copied().unwrap_or(false))
        .cloned()
        .collect()
}

/// Synthetic card for tests.
/// Builds one display only card with the given id and frequency.
/// Slice stays fixed at 1ms.
#[cfg(test)]
pub fn synthetic_card(
    id: u32,
    freq_khz: u64,
    llc_id: u32,
    smt: bool,
) -> crate::stats::PerCpuMetrics {
    crate::stats::PerCpuMetrics {
        id,
        freq_khz,
        cur_freq_khz: 0,
        llc_id,
        smt,
        running_pid: 0,
        slice_ns: crate::flow::SLICE_NS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_cpu_card_reports_one_cpu() {
        let cards = vec![synthetic_card(0, 3800000, 0, false)];
        assert_eq!(cards.len(), 1);
        assert_eq!(
            describe_topology(&cards),
            "topology: 1 CPU, no SMT, freq known"
        );
        assert_eq!(filter_allowed(&cards, &[true]).len(), 1);
        assert_eq!(filter_allowed(&cards, &[false]).len(), 0);
        assert!(crate::flow_select::may_run_on(0, &[true]));
        assert!(!crate::flow_select::may_run_on(1, &[true]));
    }

    #[test]
    fn lestat_16_plus_16_subset_keeps_allowed() {
        let mut cards = Vec::new();
        for cpu in 0..32u32 {
            let llc = if cpu < 16 { 0 } else { 1 };
            cards.push(synthetic_card(cpu, 3500000, llc, false));
        }
        assert_eq!(cards.len(), 32);
        let mut allowed = vec![false; 32];
        for slot in allowed.iter_mut().take(8) {
            *slot = true;
        }
        for slot in allowed.iter_mut().skip(16).take(8) {
            *slot = true;
        }
        let subset = filter_allowed(&cards, &allowed);
        assert_eq!(subset.len(), 16);
        for c in &subset {
            assert!(allowed[c.id as usize]);
            assert!(c.freq_khz != 0);
        }
        assert_eq!(
            describe_topology(&subset),
            "topology: 16 CPUs, no SMT, freq known"
        );
        for cpu in [8, 15, 24, 31] {
            assert!(!allowed[cpu]);
        }
    }

    #[test]
    fn freq_parse_handles_valid_and_bad() {
        assert_eq!(parse_freq_khz("3800000\n"), 3800000);
        assert_eq!(parse_freq_khz("  3500000  "), 3500000);
        assert_eq!(parse_freq_khz(""), 0);
        assert_eq!(parse_freq_khz("abc"), 0);
        assert_eq!(parse_freq_khz("0"), 0);
        assert_ne!(3800000, 0);
    }

    #[test]
    fn unknown_topology_stays_plain() {
        let empty: Vec<crate::stats::PerCpuMetrics> = Vec::new();
        assert_eq!(describe_topology(&empty), "topology unknown, plain per-CPU");
        let unknown = vec![synthetic_card(0, 0, 0, false)];
        assert_eq!(
            describe_topology(&unknown),
            "topology: 1 CPU, no SMT, freq unknown"
        );
    }

    #[test]
    fn cpu_list_parses_ranges_and_sparse() {
        assert_eq!(parse_cpu_list("0-7\n"), (0..8).collect::<Vec<u32>>());
        assert_eq!(parse_cpu_list("0,2,4"), vec![0, 2, 4]);
        assert_eq!(parse_cpu_list("0-3,8-11"), vec![0, 1, 2, 3, 8, 9, 10, 11]);
        assert_eq!(parse_cpu_list("0-1"), vec![0, 1]);
        assert!(parse_cpu_list("").is_empty());
        assert!(parse_cpu_list("abc").is_empty());
        assert_eq!(parse_cpu_list("  0-2  "), vec![0, 1, 2]);
        assert_eq!(parse_cpu_list("0-15"), (0..16).collect::<Vec<u32>>());
    }

    /// Governor base strips the diagnostic suffix only.
    #[test]
    fn governor_base_strips_suffix_only() {
        assert_eq!(governor_base("performance"), "performance");
        assert_eq!(
            governor_base("performance (epp:performance)"),
            "performance"
        );
        assert_eq!(
            governor_base("powersave (epp:performance pp:balanced)"),
            "powersave"
        );
        assert_eq!(governor_base("powersave"), "powersave");
        assert_eq!(governor_base("unknown"), "unknown");
        assert_eq!(governor_base("  performance  "), "performance");
        assert_eq!(governor_base(""), "");
    }

    /// Unanimous performance needs every base at perf.
    #[test]
    fn perf_unanimous_needs_every_perf() {
        let all: Vec<String> = vec!["performance".into(), "performance".into()];
        assert!(perf_unanimous(&all));
        let suffixed: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "performance (epp:powersave)".into(),
        ];
        assert!(perf_unanimous(&suffixed));
        let single: Vec<String> = vec!["performance".into()];
        assert!(perf_unanimous(&single));
    }

    /// Mixed, unknown, and empty stay non unanimous.
    #[test]
    fn perf_mixed_and_unknown_stay_strict() {
        let mixed: Vec<String> = vec!["performance".into(), "powersave".into()];
        assert!(!perf_unanimous(&mixed));
        let unknown: Vec<String> = vec!["unknown".into(), "performance".into()];
        assert!(!perf_unanimous(&unknown));
        let empty: Vec<String> = Vec::new();
        assert!(!perf_unanimous(&empty));
        let powersave: Vec<String> = vec!["powersave".into(), "powersave".into()];
        assert!(!perf_unanimous(&powersave));
    }

    /// Display keeps suffix when unanimous else mixed.
    #[test]
    fn display_governor_keeps_suffix_when_unanimous() {
        let empty: Vec<String> = Vec::new();
        assert_eq!(display_governor(&empty), "unknown");
        let perf: Vec<String> = vec![
            "performance (epp:performance)".into(),
            "performance (epp:performance)".into(),
        ];
        assert_eq!(display_governor(&perf), "performance (epp:performance)");
        let power: Vec<String> = vec!["powersave".into(), "powersave".into()];
        assert_eq!(display_governor(&power), "powersave");
        let mixed: Vec<String> = vec!["performance".into(), "powersave".into()];
        assert_eq!(display_governor(&mixed), "mixed");
        let unknown: Vec<String> = vec!["unknown".into(), "unknown".into()];
        assert_eq!(display_governor(&unknown), "unknown");
    }

    /// Provider runs once per collection over N CPUs.
    #[test]
    fn collect_governors_reads_platform_once() {
        let cpus: Vec<u32> = (0..16).collect();
        let mut calls = 0;
        let got = collect_governors_with(&cpus, || {
            calls += 1;
            Some("balanced".to_string())
        });
        assert_eq!(calls, 1);
        assert_eq!(got.len(), 16);
    }

    /// Batched output matches per CPU reads exactly.
    #[test]
    fn collect_governors_matches_per_cpu_reads() {
        let cpus: Vec<u32> = (0..8).collect();
        for platform in [
            None,
            Some("balanced".to_string()),
            Some("performance".to_string()),
        ] {
            let want: Vec<String> = cpus
                .iter()
                .map(|&id| read_governor_with_profile(id, platform.as_deref()))
                .collect();
            let got = collect_governors_with(&cpus, || platform.clone());
            assert_eq!(got, want);
        }
        let empty: Vec<u32> = Vec::new();
        let mut calls = 0;
        let got = collect_governors_with(&empty, || {
            calls += 1;
            None
        });
        assert!(got.is_empty());
        assert_eq!(calls, 1);
    }
}
