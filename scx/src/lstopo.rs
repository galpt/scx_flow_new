// SPDX-License-Identifier: GPL-2.0
//! True size view from the hardware list tool.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//!
//! Parses console text only. No launch happens here. Sizes stay
//! integer only with no float. Malformed lines are skipped with
//! no partial row and no abort. Die sizes stay size only and
//! never feed cluster ids.

use std::collections::BTreeMap;

use anyhow::Result;

/// One CPU row from the list text. Kernel id is the P number.
/// Cache shares are kibibytes with zero meaning unknown.
/// Die share stays size only with no grouping use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LstopoCpu {
    /// Logical PU number when present.
    pub pu_l: Option<u32>,
    /// Kernel PU number used as the map key.
    pub pu_p: u32,
    /// Logical core number when present.
    pub core_l: Option<u32>,
    /// Level one data share in kibibytes.
    pub l1d_kb: u32,
    /// Level one instruction share in kibibytes.
    pub l1i_kb: u32,
    /// Level two share in kibibytes.
    pub l2_kb: u32,
    /// Level three share in kibibytes.
    pub l3_kb: u32,
    /// Die share in kibibytes for size facts only.
    pub die_kb: u32,
}

/// Parsed view keyed by kernel PU number.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LstopoView {
    /// Rows by kernel PU number.
    pub cpus: BTreeMap<u32, LstopoCpu>,
}

/// Fold three level shares into one kibibyte value.
/// Takes the max across data plus instruction plus level two.
/// Max is used and not sum because levels overlap through
/// inclusion so a sum would double count shared lines.
/// Saturates with no wrap on overflow.
pub fn l1_fold_kb(l1d_kb: u32, l1i_kb: u32, l2_kb: u32) -> u32 {
    let mut out: u32 = l1d_kb;
    if l1i_kb > out {
        out = l1i_kb;
    }
    if l2_kb > out {
        out = l2_kb;
    }
    out
}

/// Die hint for cluster ids. Always none.
/// Die stays size only with no cluster feed.
/// A missing row reads unknown so group zero stays valid.
pub fn die_ccx_hint(_die_kb: u32) -> Option<u32> {
    None
}

/// Parse digits at the head of a slice. Returns value plus rest.
/// Saturates at u32 MAX with no wrap. Returns none on no digits.
fn parse_u32_head(s: &str) -> Option<(u32, &str)> {
    let mut val: u64 = 0;
    let mut len: usize = 0;
    for c in s.chars() {
        if !c.is_ascii_digit() {
            break;
        }
        val = val
            .saturating_mul(10)
            .saturating_add((c as u64).wrapping_sub('0' as u64));
        if val > u32::MAX as u64 {
            val = u32::MAX as u64;
        }
        len = len.wrapping_add(1);
    }
    if len == 0 {
        return None;
    }
    Some((val as u32, &s[len..]))
}

/// Kibibytes for one number plus unit pair. Unit must be KB
/// plus MB plus GB in upper case. Multiplies saturate with
/// no wrap. Returns none when the unit is absent.
fn kb_for_number_unit(val: u32, unit: &str) -> Option<u32> {
    if unit.starts_with("KB") {
        return Some(val);
    }
    if unit.starts_with("MB") {
        return Some(val.saturating_mul(1024));
    }
    if unit.starts_with("GB") {
        return Some(val.saturating_mul(1024).saturating_mul(1024));
    }
    None
}

/// First cache size in kibibytes found in a segment.
/// Scans for digits followed by KB plus MB plus GB.
/// Returns zero when no size is present. Never panics.
fn first_size_kb(segment: &str) -> u32 {
    let bytes: &[u8] = segment.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let rest: &str = &segment[i..];
            if let Some((val, tail)) = parse_u32_head(rest) {
                let tail_trim: &str = tail.trim_start();
                if tail_trim.starts_with("KB")
                    || tail_trim.starts_with("MB")
                    || tail_trim.starts_with("GB")
                {
                    let unit: &str = &tail_trim[..2];
                    if let Some(kb) = kb_for_number_unit(val, unit) {
                        return kb;
                    }
                    return u32::MAX;
                }
            }
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i = i.wrapping_add(1);
            }
            continue;
        }
        i = i.wrapping_add(1);
    }
    0
}

/// Logical number after L hash in a segment. Returns none when absent.
fn find_lnum(segment: &str) -> Option<u32> {
    let mut search: &str = segment;
    while let Some(pos) = search.find("L#") {
        let rest: &str = &search[pos.wrapping_add(2)..];
        if let Some((val, _)) = parse_u32_head(rest) {
            return Some(val);
        }
        search = rest;
    }
    None
}

/// Physical number after P hash in a segment. Returns none when absent.
fn find_pnum(segment: &str) -> Option<u32> {
    let mut search: &str = segment;
    while let Some(pos) = search.find("P#") {
        let rest: &str = &search[pos.wrapping_add(2)..];
        if let Some((val, _)) = parse_u32_head(rest) {
            return Some(val);
        }
        search = rest;
    }
    None
}

/// True when a line carries IO records only. HostBridge plus PCI
/// plus Net plus Block records are ignored exhaustively. Depth
/// census lines are ignored as well. Locale plus version detail
/// is tolerated with no parse fail.
fn is_ignored_line(content: &str) -> bool {
    if content.is_empty() {
        return true;
    }
    if content.starts_with("depth ") || content.starts_with("Special depth") {
        return true;
    }
    if content.contains("HostBridge") {
        return true;
    }
    if content.contains("PCIBridge") {
        return true;
    }
    if content.contains("PCI ") || content.contains("PCI\t") || content.contains("PCI L#") {
        return true;
    }
    if content.contains("Block") {
        return true;
    }
    if content.contains("Network") {
        return true;
    }
    // Net OS devices carry a quoted name with no PU marker.
    // A bare Net token means an IO leaf. PU lines never carry Net.
    if content.contains("Net ") || content.contains("Net\t") || content.contains("Net\"") {
        return true;
    }
    if content.contains("OSDev") {
        return true;
    }
    if content.contains("Bridge") && !content.contains("Package") {
        // Covers Bridge leaves while keeping Package lines.
        // Package never carries Bridge. IO bridges always do.
        if content.contains("HostBridge") || content.contains("PCIBridge") {
            return true;
        }
    }
    false
}

/// Entity kind for one plus separated segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SegKind {
    Machine,
    Package,
    Die,
    Numa,
    L3,
    L2,
    L1d,
    L1i,
    Core,
    Pu,
    Other,
}

/// Kind for one segment by keyword. Longer cache names win
/// over short names so L3Cache does not read as L3 plus Cache.
fn seg_kind(segment: &str) -> SegKind {
    if segment.contains("L3Cache") || contains_word(segment, "L3") {
        return SegKind::L3;
    }
    if segment.contains("L2Cache") || contains_word(segment, "L2") {
        return SegKind::L2;
    }
    if segment.contains("L1dCache") || contains_word(segment, "L1d") {
        return SegKind::L1d;
    }
    if segment.contains("L1iCache") || contains_word(segment, "L1i") {
        return SegKind::L1i;
    }
    if contains_word(segment, "PU") {
        return SegKind::Pu;
    }
    if contains_word(segment, "Core") {
        return SegKind::Core;
    }
    if segment.contains("NUMANode") || contains_word(segment, "NUMA") {
        return SegKind::Numa;
    }
    if contains_word(segment, "Die") {
        return SegKind::Die;
    }
    if contains_word(segment, "Package") {
        return SegKind::Package;
    }
    if contains_word(segment, "Machine") {
        return SegKind::Machine;
    }
    SegKind::Other
}

/// True when a word appears with a non letter bound on both sides.
/// Keeps L2 from matching L2Cache twice and PU from matching CPU.
fn contains_word(hay: &str, word: &str) -> bool {
    let hb: &[u8] = hay.as_bytes();
    let wb: &[u8] = word.as_bytes();
    if wb.is_empty() || hb.len() < wb.len() {
        return false;
    }
    let mut i: usize = 0;
    while i.wrapping_add(wb.len()) <= hb.len() {
        if &hb[i..i.wrapping_add(wb.len())] == wb {
            let before_ok: bool = if i == 0 {
                true
            } else {
                !hb[i.wrapping_sub(1)].is_ascii_alphanumeric()
            };
            let after: usize = i.wrapping_add(wb.len());
            let after_ok: bool = if after >= hb.len() {
                true
            } else {
                !hb[after].is_ascii_alphanumeric()
            };
            if before_ok && after_ok {
                return true;
            }
        }
        i = i.wrapping_add(1);
    }
    false
}

/// Ancestor context carried by indent. Cache shares inherit
/// from the parent when the current line carries no size.
/// Core ids inherit in the same way for verbose nesting.
#[derive(Clone, Debug, Default)]
struct Ctx {
    indent: usize,
    die_kb: u32,
    l3_kb: u32,
    l2_kb: u32,
    l1d_kb: u32,
    l1i_kb: u32,
    core_l: Option<u32>,
    core_p: Option<u32>,
}

/// Parse console plus verbose list text into a view.
/// Skips malformed lines with no partial row and no abort.
/// Returns an error only on a wholly empty input with no PU rows.
/// Never panics on any input.
pub fn parse_lstopo_text(text: &str) -> Result<LstopoView> {
    let mut view = LstopoView::default();
    let mut stack: Vec<Ctx> = Vec::new();
    for raw in text.lines() {
        if raw.len() > 1_048_576 {
            continue;
        }
        let indent: usize = raw.len().wrapping_sub(raw.trim_start_matches(' ').len());
        let content: &str = raw.trim_start_matches(' ');
        let trimmed: &str = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_ignored_line(trimmed) {
            continue;
        }
        while stack.last().map(|c| c.indent >= indent).unwrap_or(false) {
            stack.pop();
        }
        let parent: Ctx = stack.last().cloned().unwrap_or_default();
        // Split console combined records on plus. Verbose lines
        // carry one record so the split keeps one segment.
        let parts: Vec<&str> = trimmed.split('+').collect();
        let mut line_die: Option<u32> = None;
        let mut line_l3: Option<u32> = None;
        let mut line_l2: Option<u32> = None;
        let mut line_l1d: Option<u32> = None;
        let mut line_l1i: Option<u32> = None;
        let mut line_core_l: Option<u32> = None;
        let mut line_core_p: Option<u32> = None;
        let mut pu_l: Option<u32> = None;
        let mut pu_p: Option<u32> = None;
        let mut has_pu: bool = false;
        let mut has_core: bool = false;
        let mut has_cache_or_topo: bool = false;
        for part in &parts {
            let seg: &str = part.trim();
            if seg.is_empty() {
                continue;
            }
            // A segment with IO detail inside a combined line is skipped.
            // Console never mixes IO with cache records on one line.
            if seg.contains("HostBridge") || seg.contains("PCIBridge") || seg.contains("Block") {
                continue;
            }
            let kind: SegKind = seg_kind(seg);
            match kind {
                SegKind::Pu => {
                    has_pu = true;
                    let l: Option<u32> = find_lnum(seg);
                    let p: Option<u32> = find_pnum(seg);
                    // Keep the first PU record on the line. One PU
                    // line carries one PU. Later records are ignored.
                    if pu_l.is_none() && pu_p.is_none() {
                        pu_l = l;
                        pu_p = p;
                    }
                }
                SegKind::Core => {
                    has_core = true;
                    has_cache_or_topo = true;
                    if line_core_l.is_none() {
                        line_core_l = find_lnum(seg);
                    }
                    if line_core_p.is_none() {
                        line_core_p = find_pnum(seg);
                    }
                }
                SegKind::L3 => {
                    has_cache_or_topo = true;
                    let kb: u32 = first_size_kb(seg);
                    if kb != 0 {
                        line_l3 = Some(kb);
                    }
                }
                SegKind::L2 => {
                    has_cache_or_topo = true;
                    let kb: u32 = first_size_kb(seg);
                    if kb != 0 {
                        line_l2 = Some(kb);
                    }
                }
                SegKind::L1d => {
                    has_cache_or_topo = true;
                    let kb: u32 = first_size_kb(seg);
                    if kb != 0 {
                        line_l1d = Some(kb);
                    }
                }
                SegKind::L1i => {
                    has_cache_or_topo = true;
                    let kb: u32 = first_size_kb(seg);
                    if kb != 0 {
                        line_l1i = Some(kb);
                    }
                }
                SegKind::Die => {
                    has_cache_or_topo = true;
                    let kb: u32 = first_size_kb(seg);
                    if kb != 0 {
                        line_die = Some(kb);
                    }
                }
                SegKind::Package | SegKind::Numa | SegKind::Machine => {
                    has_cache_or_topo = true;
                }
                SegKind::Other => {
                    // Unknown records are tolerated with no fail.
                    // A line with only unknown records is skipped.
                    continue;
                }
            }
        }
        // Die plus L3 share one size on console combined lines.
        // One size fills both so size facts stay complete.
        if line_die.is_none() && line_l3.is_some() && trimmed.contains("Die") {
            line_die = line_l3;
        }
        if line_l3.is_none() && line_die.is_some() && trimmed.contains("L3") {
            line_l3 = line_die;
        }
        if has_pu {
            let key: Option<u32> = pu_p.or(pu_l);
            let k: u32 = match key {
                Some(v) => v,
                None => continue,
            };
            // Skip duplicate PU rows with no overwrite.
            if view.cpus.contains_key(&k) {
                continue;
            }
            let row = LstopoCpu {
                pu_l,
                pu_p: k,
                core_l: line_core_l.or(parent.core_l),
                l1d_kb: parent.l1d_kb,
                l1i_kb: parent.l1i_kb,
                l2_kb: parent.l2_kb,
                l3_kb: parent.l3_kb,
                die_kb: parent.die_kb,
            };
            view.cpus.insert(k, row);
            continue;
        }
        if has_core || has_cache_or_topo {
            let mut next: Ctx = Ctx {
                indent,
                die_kb: parent.die_kb,
                l3_kb: parent.l3_kb,
                l2_kb: parent.l2_kb,
                l1d_kb: parent.l1d_kb,
                l1i_kb: parent.l1i_kb,
                core_l: parent.core_l,
                core_p: parent.core_p,
            };
            if let Some(v) = line_die {
                next.die_kb = v;
            }
            if let Some(v) = line_l3 {
                next.l3_kb = v;
            }
            if let Some(v) = line_l2 {
                next.l2_kb = v;
            }
            if let Some(v) = line_l1d {
                next.l1d_kb = v;
            }
            if let Some(v) = line_l1i {
                next.l1i_kb = v;
            }
            if has_core {
                // Core ids on the line win over ancestors.
                // Verbose Core lines carry P numbers as well.
                if line_core_l.is_some() {
                    next.core_l = line_core_l;
                }
                if line_core_p.is_some() {
                    next.core_p = line_core_p;
                }
            }
            stack.push(next);
        }
    }
    if view.cpus.is_empty() {
        anyhow::bail!("no PU rows in list text");
    }
    Ok(view)
}

/// Per CPU cache shares from list text. Keys are kernel PU numbers.
/// Values hold data plus instruction plus level two plus level three
/// kibibytes in order. Die shares are omitted because Die never
/// feeds cluster ids. Skips malformed lines with no abort.
pub fn lstopo_parse_caches(text: &str) -> Result<BTreeMap<u32, (u32, u32, u32, u32)>> {
    let view: LstopoView = parse_lstopo_text(text)?;
    let mut out: BTreeMap<u32, (u32, u32, u32, u32)> = BTreeMap::new();
    for (k, row) in view.cpus.iter() {
        out.insert(*k, (row.l1d_kb, row.l1i_kb, row.l2_kb, row.l3_kb));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::die_ccx_hint;
    use super::l1_fold_kb;
    use super::lstopo_parse_caches;
    use super::parse_lstopo_text;

    const HOST_TEXT: &str = "Machine (59GB total)\n  Package L#0\n    NUMANode L#0 (P#0 59GB)\n    L3 L#0 (16MB)\n      L2 L#0 (512KB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU L#1 (P#1)\n      L2 L#1 (512KB) + L1d L#1 (32KB) + L1i L#1 (32KB) + Core L#1\n        PU L#2 (P#2)\n        PU L#3 (P#3)\n  HostBridge\n    PCIBridge\n      PCI 01:00.0 (VGA)\n        Net \"enp2s0\"\n        Block(Disk) \"nvme0n1\"\n";

    const ASYM_TEXT: &str = "Machine (47GB total)\n  Package L#0\n    NUMANode L#0 (P#0 47GB)\n    Die L#0 + L3 L#0 (96MB)\n      L2 L#0 (1024KB) + L1d L#0 (48KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU L#1 (P#16)\n    Die L#1 + L3 L#1 (32MB)\n      L2 L#8 (1024KB) + L1d L#8 (48KB) + L1i L#8 (32KB) + Core L#8\n        PU L#16 (P#8)\n        PU L#17 (P#24)\n  HostBridge\n    PCIBridge\n      PCI 02:00.0 (NVMExp)\n        Block(Disk) \"nvme0n1\"\n";

    const VERBOSE_TEXT: &str = "Machine (P#0 total=61381144KB Backend=Linux)\n  Package L#0 (P#0 total=61381144KB)\n    NUMANode L#0 (P#0 local=61381144KB)\n    L3Cache L#0 (P#0 size=16384KB linesize=64 ways=16)\n      L2Cache L#0 (P#0 size=512KB linesize=64 ways=8)\n        L1dCache L#0 (P#0 size=32KB linesize=64 ways=8)\n          L1iCache L#0 (P#0 size=32KB linesize=64 ways=8)\n            Core L#0 (P#0)\n              PU L#0 (P#0)\n              PU L#1 (P#1)\ndepth 0:           1 Machine (type #0)\nSpecial depth -4:  7 Bridge (type #14)\n  HostBridge L#0 (buses=0000:[00-07])\n    PCIBridge L#1 (busid=0000:00:01.1)\n      PCI L#0 (busid=0000:01:00.0)\n        Network L#0 (Address=e4:a8:df:de:99:22) \"enp2s0\"\n";

    #[test]
    fn host_symmetric_sizes_match() {
        let view = parse_lstopo_text(HOST_TEXT).unwrap();
        assert_eq!(view.cpus.len(), 4);
        let c0 = view.cpus.get(&0).unwrap();
        assert_eq!(c0.l3_kb, 16384);
        assert_eq!(c0.l2_kb, 512);
        assert_eq!(c0.l1d_kb, 32);
        assert_eq!(c0.l1i_kb, 32);
        assert_eq!(c0.die_kb, 0);
        let c3 = view.cpus.get(&3).unwrap();
        assert_eq!(c3.l3_kb, 16384);
        assert_eq!(l1_fold_kb(c0.l1d_kb, c0.l1i_kb, c0.l2_kb), 512);
        let map = lstopo_parse_caches(HOST_TEXT).unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map.get(&1).unwrap(), &(32, 32, 512, 16384));
    }

    #[test]
    fn asymmetric_die_sizes_stay_size_only() {
        let view = parse_lstopo_text(ASYM_TEXT).unwrap();
        assert_eq!(view.cpus.len(), 4);
        let first = view.cpus.get(&0).unwrap();
        assert_eq!(first.l3_kb, 98304);
        assert_eq!(first.die_kb, 98304);
        assert_eq!(first.l2_kb, 1024);
        assert_eq!(first.l1d_kb, 48);
        assert_eq!(first.l1i_kb, 32);
        let second = view.cpus.get(&8).unwrap();
        assert_eq!(second.l3_kb, 32768);
        assert_eq!(second.die_kb, 32768);
        // PU pairs split by sixteen on the reference host.
        assert!(view.cpus.contains_key(&16));
        assert!(view.cpus.contains_key(&24));
        // Die never feeds cluster ids.
        assert_eq!(die_ccx_hint(first.die_kb), None);
        assert_eq!(die_ccx_hint(second.die_kb), None);
        assert_eq!(l1_fold_kb(48, 32, 1024), 1024);
        assert_eq!(l1_fold_kb(32, 32, 512), 512);
    }

    #[test]
    fn io_records_are_ignored() {
        let view = parse_lstopo_text(HOST_TEXT).unwrap();
        // Four PU rows only. HostBridge plus PCI plus Net plus
        // Block records add no rows.
        assert_eq!(view.cpus.len(), 4);
        for (k, row) in view.cpus.iter() {
            assert!(*k < 4);
            assert!(row.l3_kb != 0);
        }
        let verbose = parse_lstopo_text(VERBOSE_TEXT).unwrap();
        assert_eq!(verbose.cpus.len(), 2);
        let v0 = verbose.cpus.get(&0).unwrap();
        assert_eq!(v0.l3_kb, 16384);
        assert_eq!(v0.l2_kb, 512);
    }

    #[test]
    fn byte_cap_saturates_with_no_wrap() {
        let big = "Machine (1GB total)\n  Package L#0\n    L3 L#0 (9999999GB)\n      L2 L#0 (9999999MB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n";
        let view = parse_lstopo_text(big).unwrap();
        let row = view.cpus.get(&0).unwrap();
        assert_eq!(row.l3_kb, u32::MAX);
        assert_eq!(row.l2_kb, u32::MAX);
        assert_eq!(l1_fold_kb(row.l1d_kb, row.l1i_kb, row.l2_kb), u32::MAX);
        // Malformed lines are skipped with no abort.
        let bad = "Machine (1GB total)\n  Package L#0\n    L3 L#0 (16MB)\n      gibberish without ids\n      L2 L#0 (512KB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU without numbers\n";
        let view2 = parse_lstopo_text(bad).unwrap();
        assert_eq!(view2.cpus.len(), 1);
        // Empty input fails closed with no panic.
        assert!(parse_lstopo_text("").is_err());
        assert!(parse_lstopo_text("  HostBridge\n    PCI 01:00.0 (VGA)\n").is_err());
    }

    #[test]
    fn physical_ids_map_by_p_number() {
        let phys = "Machine (59GB total)\n  Package P#0\n    NUMANode P#0 (59GB)\n    L3 P#0 (16MB)\n      L2 P#0 (512KB) + L1d P#0 (32KB) + L1i P#0 (32KB) + Core P#0\n        PU P#0\n        PU P#1\n";
        let view = parse_lstopo_text(phys).unwrap();
        assert_eq!(view.cpus.len(), 2);
        assert!(view.cpus.contains_key(&0));
        assert!(view.cpus.contains_key(&1));
    }
}
