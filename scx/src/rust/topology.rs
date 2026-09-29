// SPDX-License-Identifier: GPL-2.0
//! Topology view for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Reads the host CPU lists plus the node rows for the BPF seed.
//! Frequency plus governor reads stay disabled with no sysfs use.

/// Online CPU ids in rank order with empty on read fault.
pub fn online_cpus() -> Vec<u32> {
    read_cpu_list_file("/sys/devices/system/cpu/online")
}

/// One topology row per CPU with sibling plus node.
/// Sibling reads the thread list with all ones on fault, and node
/// reads the node list with zero on fault.
pub fn topo_rows() -> Vec<(u32, u32, u32)> {
    let online = online_cpus();
    let mut rows = Vec::new();
    for cpu in online {
        let sib = thread_sibling(cpu).unwrap_or(u32::MAX);
        let node = cpu_node(cpu).unwrap_or(0);
        rows.push((cpu, sib, node));
    }
    rows
}

/// Short topology line for the start log.
pub fn describe_topology(rows: &[(u32, u32, u32)]) -> String {
    format!("cpus={} seeded", rows.len())
}

/// Parse a kernel CPU list like 0-3 plus 5 into ids.
pub fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-')
            && let (Ok(lo), Ok(hi)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>())
        {
            for cpu in lo..=hi {
                out.push(cpu);
            }
            continue;
        }
        if let Ok(cpu) = part.parse::<u32>() {
            out.push(cpu);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Read one kernel CPU list file into ids with empty on fault.
pub fn read_cpu_list_file(path: &str) -> Vec<u32> {
    std::fs::read_to_string(path)
        .map(|s| parse_cpu_list(&s))
        .unwrap_or_default()
}

/// Thread sibling of one CPU with None on fault.
fn thread_sibling(cpu: u32) -> Option<u32> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    let ids = read_cpu_list_file(&path);
    ids.into_iter().find(|id| *id != cpu)
}

/// Node of one CPU with None on fault.
fn cpu_node(cpu: u32) -> Option<u32> {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/physical_package_id");
    let raw = std::fs::read_to_string(&path).ok()?;
    raw.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_singles() {
        assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0-1,3"), vec![0, 1, 3]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
    }
}
