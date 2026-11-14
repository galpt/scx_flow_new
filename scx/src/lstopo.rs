// SPDX-License-Identifier: GPL-2.0
//! Cache sizes from the text output of lstopo.
//!
//! scx_utils reports one aggregated cache size per CPU, so the per-level
//! sizes printed at startup come from the console output of
//! lstopo-no-graphics instead. Lines that cannot be parsed are skipped.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;

use anyhow::Result;

/// Cache sizes seen by one CPU, in kibibytes. Zero means unknown.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LstopoCpu {
    pub l1d_kb: u32,
    pub l1i_kb: u32,
    pub l2_kb: u32,
    pub l3_kb: u32,
}

/// Cache sizes keyed by kernel CPU id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LstopoView {
    pub cpus: BTreeMap<u32, LstopoCpu>,
}

/// Leading decimal number of @s and the rest of it. Saturates at u32::MAX.
fn parse_u32_head(s: &str) -> Option<(u32, &str)> {
    let len = s.bytes().take_while(u8::is_ascii_digit).count();

    if len == 0 {
        return None;
    }
    let val = s[..len].bytes().fold(0u64, |acc, b| {
        (acc * 10 + u64::from(b - b'0')).min(u64::from(u32::MAX))
    });
    Some((val as u32, &s[len..]))
}

/// First size such as "512KB", "16MB" or "1GB" in @segment, in kibibytes.
/// A size written with a decimal point or a thousands separator is not
/// trusted and reads as unknown, so "1.5MB" never turns into 5MB.
fn first_size_kb(segment: &str) -> u32 {
    let mut rest = segment;

    while let Some(start) = rest.find(|c: char| c.is_ascii_digit()) {
        let Some((val, tail)) = parse_u32_head(&rest[start..]) else {
            break;
        };
        if tail.starts_with('.') || tail.starts_with(',') {
            return 0;
        }
        let unit = tail.trim_start();
        if unit.starts_with("KB") {
            return val;
        }
        if unit.starts_with("MB") {
            return val.saturating_mul(1024);
        }
        if unit.starts_with("GB") {
            return val.saturating_mul(1024 * 1024);
        }
        rest = tail;
    }
    0
}

/// Number following @tag, such as the 3 of "P#3".
fn find_num(segment: &str, tag: &str) -> Option<u32> {
    let mut rest = segment;

    while let Some(pos) = rest.find(tag) {
        rest = &rest[pos + tag.len()..];
        if let Some((val, _)) = parse_u32_head(rest) {
            return Some(val);
        }
    }
    None
}

/// Lines describing I/O devices or object depths, which carry no caches.
fn is_ignored_line(content: &str) -> bool {
    const IO_TOKENS: [&str; 10] = [
        "HostBridge",
        "PCIBridge",
        "PCI ",
        "PCI\t",
        "PCI L#",
        "Block",
        "Network",
        "Net ",
        "Net\t",
        "Net\"",
    ];

    content.is_empty()
        || content.starts_with("depth ")
        || content.starts_with("Special depth")
        || content.contains("OSDev")
        || IO_TOKENS.iter().any(|t| content.contains(t))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SegKind {
    Topology,
    Die,
    L3,
    L2,
    L1d,
    L1i,
    Pu,
    Other,
}

/// True when @word appears in @hay with no letter or digit glued to it, so
/// "PU" does not match "CPU" and "L3" does not match "L3Cache".
fn contains_word(hay: &str, word: &str) -> bool {
    let bytes = hay.as_bytes();
    let is_bound = |i: Option<usize>| {
        i.and_then(|i| bytes.get(i))
            .is_none_or(|b| !b.is_ascii_alphanumeric())
    };

    !word.is_empty()
        && hay
            .match_indices(word)
            .any(|(i, _)| is_bound(i.checked_sub(1)) && is_bound(Some(i + word.len())))
}

/// Kind of one record. Verbose output spells caches as "L3Cache" and the
/// console output as "L3".
fn seg_kind(segment: &str) -> SegKind {
    let is = |long: &str, short: &str| segment.contains(long) || contains_word(segment, short);

    if is("L3Cache", "L3") {
        SegKind::L3
    } else if is("L2Cache", "L2") {
        SegKind::L2
    } else if is("L1dCache", "L1d") {
        SegKind::L1d
    } else if is("L1iCache", "L1i") {
        SegKind::L1i
    } else if contains_word(segment, "PU") {
        SegKind::Pu
    } else if contains_word(segment, "Die") {
        SegKind::Die
    } else if ["Core", "NUMA", "Package", "Machine"]
        .iter()
        .any(|w| contains_word(segment, w))
        || segment.contains("NUMANode")
    {
        SegKind::Topology
    } else {
        SegKind::Other
    }
}

/// Cache sizes inherited by the lines nested below an object.
#[derive(Clone, Debug, Default)]
struct Ctx {
    indent: usize,
    sizes: LstopoCpu,
}

/// Parse the console or verbose output of lstopo. Fails only when no CPU
/// with a kernel id was found.
pub fn parse_lstopo_text(text: &str) -> Result<LstopoView> {
    let mut view = LstopoView::default();
    let mut stack: Vec<Ctx> = Vec::new();

    for raw in text.lines() {
        let content = raw.trim_start();
        let indent = raw.len() - content.len();
        let line = content.trim();

        if line.is_empty() || is_ignored_line(line) {
            continue;
        }
        while stack.last().is_some_and(|c| c.indent >= indent) {
            stack.pop();
        }
        let mut sizes = stack.last().map(|c| c.sizes.clone()).unwrap_or_default();

        // The console output joins nested objects with '+' on one line.
        let mut is_pu = false;
        let mut pu_id = None;
        let mut is_object = false;
        let mut die_kb = 0;
        let mut l3_kb = 0;
        for seg in line.split('+').map(str::trim) {
            let kb = first_size_kb(seg);

            match seg_kind(seg) {
                SegKind::Pu => {
                    if !is_pu {
                        is_pu = true;
                        pu_id = find_num(seg, "P#");
                    }
                    continue;
                }
                SegKind::Other => continue,
                SegKind::Topology => {}
                SegKind::Die => die_kb = kb,
                SegKind::L3 => l3_kb = kb,
                SegKind::L2 if kb != 0 => sizes.l2_kb = kb,
                SegKind::L1d if kb != 0 => sizes.l1d_kb = kb,
                SegKind::L1i if kb != 0 => sizes.l1i_kb = kb,
                SegKind::L2 | SegKind::L1d | SegKind::L1i => {}
            }
            is_object = true;
        }

        // "Die + L3" may carry its only size on the die record.
        if l3_kb == 0 && contains_word(line, "L3") {
            l3_kb = die_kb;
        }
        if l3_kb != 0 {
            sizes.l3_kb = l3_kb;
        }

        if is_pu {
            // A CPU without a kernel id cannot be matched with the topology.
            if let Some(cpu) = pu_id {
                view.cpus.entry(cpu).or_insert(sizes);
            }
        } else if is_object {
            stack.push(Ctx { indent, sizes });
        }
    }

    if view.cpus.is_empty() {
        anyhow::bail!("no CPU found in the lstopo output");
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_TEXT: &str = "Machine (59GB total)\n  Package L#0\n    NUMANode L#0 (P#0 59GB)\n    L3 L#0 (16MB)\n      L2 L#0 (512KB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU L#1 (P#1)\n      L2 L#1 (512KB) + L1d L#1 (32KB) + L1i L#1 (32KB) + Core L#1\n        PU L#2 (P#2)\n        PU L#3 (P#3)\n  HostBridge\n    PCIBridge\n      PCI 01:00.0 (VGA)\n        Net \"enp2s0\"\n        Block(Disk) \"nvme0n1\"\n";

    const ASYM_TEXT: &str = "Machine (47GB total)\n  Package L#0\n    NUMANode L#0 (P#0 47GB)\n    Die L#0 + L3 L#0 (96MB)\n      L2 L#0 (1024KB) + L1d L#0 (48KB) + L1i L#0 (32KB) + Core L#0\n        PU L#0 (P#0)\n        PU L#1 (P#16)\n    Die L#1 + L3 L#1 (32MB)\n      L2 L#8 (1024KB) + L1d L#8 (48KB) + L1i L#8 (32KB) + Core L#8\n        PU L#16 (P#8)\n        PU L#17 (P#24)\n  HostBridge\n    PCIBridge\n      PCI 02:00.0 (NVMExp)\n        Block(Disk) \"nvme0n1\"\n";

    const VERBOSE_TEXT: &str = "Machine (P#0 total=61381144KB Backend=Linux)\n  Package L#0 (P#0 total=61381144KB)\n    NUMANode L#0 (P#0 local=61381144KB)\n    L3Cache L#0 (P#0 size=16384KB linesize=64 ways=16)\n      L2Cache L#0 (P#0 size=512KB linesize=64 ways=8)\n        L1dCache L#0 (P#0 size=32KB linesize=64 ways=8)\n          L1iCache L#0 (P#0 size=32KB linesize=64 ways=8)\n            Core L#0 (P#0)\n              PU L#0 (P#0)\n              PU L#1 (P#1)\ndepth 0:           1 Machine (type #0)\nSpecial depth -4:  7 Bridge (type #14)\n  HostBridge L#0 (buses=0000:[00-07])\n    PCIBridge L#1 (busid=0000:00:01.1)\n      PCI L#0 (busid=0000:01:00.0)\n        Network L#0 (Address=e4:a8:df:de:99:22) \"enp2s0\"\n";

    fn sizes(l1d_kb: u32, l1i_kb: u32, l2_kb: u32, l3_kb: u32) -> LstopoCpu {
        LstopoCpu {
            l1d_kb,
            l1i_kb,
            l2_kb,
            l3_kb,
        }
    }

    fn only_cpu(text: &str) -> LstopoCpu {
        parse_lstopo_text(text).unwrap().cpus.remove(&0).unwrap()
    }

    #[test]
    fn console_sizes_reach_every_cpu() {
        let view = parse_lstopo_text(HOST_TEXT).unwrap();
        assert_eq!(view.cpus.len(), 4);
        for cpu in view.cpus.values() {
            assert_eq!(*cpu, sizes(32, 32, 512, 16384));
        }
    }

    #[test]
    fn cpus_are_keyed_by_kernel_id() {
        let view = parse_lstopo_text(ASYM_TEXT).unwrap();
        assert_eq!(
            view.cpus.keys().copied().collect::<Vec<_>>(),
            vec![0, 8, 16, 24]
        );
        assert_eq!(view.cpus[&0], sizes(48, 32, 1024, 98304));
        assert_eq!(view.cpus[&8].l3_kb, 32768);
    }

    #[test]
    fn verbose_output_parses() {
        let view = parse_lstopo_text(VERBOSE_TEXT).unwrap();
        assert_eq!(view.cpus.len(), 2);
        assert_eq!(view.cpus[&1], sizes(32, 32, 512, 16384));
    }

    #[test]
    fn die_size_fills_l3_on_a_joined_line() {
        let text = "Machine\n  Package L#0\n    Die L#0 (96MB) + L3 L#0\n      L2 L#0 (1024KB) + Core L#0\n        PU L#0 (P#0)\n";
        assert_eq!(only_cpu(text).l3_kb, 98304);

        let glued = "Machine\n  Package L#0\n    Die L#0 (96MB) + L3Foo\n      L2 L#0 (1024KB) + Core L#0\n        PU L#0 (P#0)\n";
        assert_eq!(only_cpu(glued).l3_kb, 0);
    }

    #[test]
    fn cpus_without_a_kernel_id_are_skipped() {
        let logical_only = "Machine\n  Package L#0\n    L3 L#0 (16MB)\n      Core L#0\n        PU L#0\n        PU L#1\n";
        assert!(parse_lstopo_text(logical_only).is_err());

        let mixed = "Machine\n  Package L#0\n    L3 L#0 (16MB)\n      Core L#0\n        PU L#0 (P#0)\n        PU L#1\n";
        let view = parse_lstopo_text(mixed).unwrap();
        assert_eq!(view.cpus.keys().copied().collect::<Vec<_>>(), vec![0]);

        let physical = "Machine\n  Package P#0\n    L3 P#0 (16MB)\n      Core P#0\n        PU P#0\n        PU P#1\n";
        assert_eq!(parse_lstopo_text(physical).unwrap().cpus.len(), 2);
    }

    #[test]
    fn tabs_count_as_indent() {
        let tabs = "Machine\n\tPackage L#0\n\t\tL3 L#0 (16MB)\n\t\t\tL2 L#0 (512KB) + L1d L#0 (32KB) + L1i L#0 (32KB) + Core L#0\n\t\t\t\tPU L#0 (P#0)\n\tHostBridge\n\t\tPCIBridge\n";
        assert_eq!(only_cpu(tabs), sizes(32, 32, 512, 16384));

        let mixed = "Machine\n \tPackage L#0\n \t\tL3 L#0 (16MB)\n \t\t\tL2 L#0 (512KB) + Core L#0\n \t\t\t\tPU L#0 (P#0)\n";
        assert_eq!(only_cpu(mixed).l3_kb, 16384);
    }

    #[test]
    fn malformed_input_is_tolerated() {
        let huge = "Machine\n  Package L#0\n    L3 L#0 (9999999GB)\n      L2 L#0 (9999999MB) + Core L#0\n        PU L#0 (P#0)\n";
        let cpu = only_cpu(huge);
        assert_eq!(cpu.l3_kb, u32::MAX);
        assert_eq!(cpu.l2_kb, u32::MAX);

        let noisy = "Machine\n  Package L#0\n    L3 L#0 (16MB)\n      gibberish without ids\n      Core L#0\n        PU L#0 (P#0)\n        PU without numbers\n";
        assert_eq!(parse_lstopo_text(noisy).unwrap().cpus.len(), 1);

        assert!(parse_lstopo_text("").is_err());
        assert!(parse_lstopo_text("  HostBridge\n    PCI 01:00.0 (VGA)\n").is_err());
    }

    #[test]
    fn sizes_need_a_plain_number_and_unit() {
        assert_eq!(first_size_kb("32KB"), 32);
        assert_eq!(first_size_kb("16MB"), 16384);
        assert_eq!(first_size_kb("1GB"), 1048576);
        assert_eq!(first_size_kb("L2 L#0 (512KB)"), 512);
        assert_eq!(first_size_kb("1.5MB"), 0);
        assert_eq!(first_size_kb("16,384KB"), 0);
        assert_eq!(first_size_kb("16XB"), 0);
        assert_eq!(first_size_kb("no size here"), 0);
    }

    #[test]
    fn io_and_depth_lines_are_ignored() {
        for line in [
            "HostBridge",
            "PCIBridge L#1",
            "PCI 01:00.0 (VGA)",
            "Block(Disk) \"nvme0n1\"",
            "Network L#0 (Address=aa) \"eth0\"",
            "depth 0: 1 Machine (type #0)",
            "Special depth -4: 7 Bridge (type #14)",
        ] {
            assert!(is_ignored_line(line), "{line}");
        }
        for line in ["Package L#0", "L3 L#0 (16MB)", "PU L#0 (P#0)"] {
            assert!(!is_ignored_line(line), "{line}");
        }
    }

    #[test]
    fn words_need_bounds() {
        assert!(contains_word("L3 L#0", "L3"));
        assert!(!contains_word("L3Cache", "L3"));
        assert!(contains_word("PU L#0", "PU"));
        assert!(!contains_word("CPU", "PU"));
        assert!(!contains_word("Score", "Core"));
        assert!(!contains_word("DielectricFoo", "Die"));
    }
}
