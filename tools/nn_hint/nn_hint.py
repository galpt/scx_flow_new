#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Offline hint replay with integer math only and no scheduler use.
# Reads raw frame rows or harness rows and prints a clamped hint.
# Batch mode replays many files and reports proxy error plus
# saturation plus shard stability plus taxonomy with integer math only.
# Proxy maps hint minus offset to burst tenths as a placeholder
# with no accuracy claim and calibration still required.
# Burst sums cpu plus gpu tenths. Taxonomy maps burst to zero
# for lat plus one for batch plus two for idle with shares four
# hundred plus one hundred plus twenty report only.
# Lestat frametime maps to duplicated tenths with header detect
# for probe versus frametime with integer math only.
# The model keeps two hidden units with rectified outputs and
# saturates at the share bounds. It never writes vd and makes
# no faster claim over averaging. Delete this dir to remove it.
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
import csv
import json
import sys

W1 = [[3, -2], [2, 4]]
B1 = [1, -1]
W2 = [2, 3]
B2 = 0
LO = 1
HI = 10000


def tenths_from_ms_num(v):
    # Tenths of ms from a JSON number with no float math.
    # Uses the decimal text with integer digits only.
    s = repr(v)
    neg = False
    if s.startswith("-"):
        neg = True
        s = s[1:]
    if "e" in s or "E" in s:
        # Scientific form never appears in raw frames; treat as zero.
        return 0
    if "." in s:
        whole_s, frac_s = s.split(".", 1)
    else:
        whole_s, frac_s = s, ""
    whole = 0
    for ch in whole_s:
        if "0" <= ch <= "9":
            whole = whole * 10 + (ord(ch) - 48)
    tenth = 0
    if frac_s and "0" <= frac_s[0] <= "9":
        tenth = ord(frac_s[0]) - 48
    out = whole * 10 + tenth
    return -out if neg else out


def parse_tenths_ms(text):
    # Tenths of ms from a micros decimal string with integers only.
    # Whole micros // 100; the frac is below one tenth and drops.
    s = text.strip()
    if s.startswith("-"):
        s = s[1:]
    if not s:
        return 0
    if "." in s:
        whole_s, _ = s.split(".", 1)
    else:
        whole_s = s
    whole = 0
    for ch in whole_s:
        if "0" <= ch <= "9":
            whole = whole * 10 + (ord(ch) - 48)
    return whole // 100


def tenths_from_ms_str(text):
    # Tenths of ms from an ms decimal string with integers only.
    # Whole part times ten plus first frac digit with no float math.
    s = text.strip()
    neg = False
    if s.startswith("-"):
        neg = True
        s = s[1:]
    if not s:
        return 0
    if "." in s:
        whole_s, frac_s = s.split(".", 1)
    else:
        whole_s, frac_s = s, ""
    whole = 0
    for ch in whole_s:
        if "0" <= ch <= "9":
            whole = whole * 10 + (ord(ch) - 48)
    tenth = 0
    if frac_s and "0" <= frac_s[0] <= "9":
        tenth = ord(frac_s[0]) - 48
    out = whole * 10 + tenth
    return -out if neg else out


def relu(x):
    return x if x > 0 else 0


def hint_for(cpu_ms_x10, gpu_ms_x10):
    h0 = relu(W1[0][0] * cpu_ms_x10 + W1[0][1] * gpu_ms_x10 + B1[0])
    h1 = relu(W1[1][0] * cpu_ms_x10 + W1[1][1] * gpu_ms_x10 + B1[1])
    out = W2[0] * h0 + W2[1] * h1 + B2
    # Scale down with shifts only to keep integer math.
    out = (out >> 4) + 100
    if out < LO:
        return LO
    if out > HI:
        return HI
    return out


def hint_for_w(cpu_ms_x10, gpu_ms_x10, w1, b1, w2, b2):
    # Parameter sweep helper with explicit weights and integer math.
    # Global placeholder weights stay unchanged. Caller passes
    # bounded deltas only. Shifts plus clamps match hint_for.
    h0 = relu(w1[0][0] * cpu_ms_x10 + w1[0][1] * gpu_ms_x10 + b1[0])
    h1 = relu(w1[1][0] * cpu_ms_x10 + w1[1][1] * gpu_ms_x10 + b1[1])
    out = w2[0] * h0 + w2[1] * h1 + b2
    out = (out >> 4) + 100
    if out < LO:
        return LO
    if out > HI:
        return HI
    return out


def abs_int(x):
    return -x if x < 0 else x


def burst_for(cpu_ms_x10, gpu_ms_x10):
    # Burst proxy in tenths of ms with integer add only.
    # Sums both inputs. Negative sums clamp to zero.
    s = cpu_ms_x10 + gpu_ms_x10
    return s if s > 0 else 0


def proxy_for(hint):
    # Placeholder map from hint to burst tenths with integer add.
    # Removes the fixed offset. Uncalibrated with no accuracy claim.
    return hint - 100


def taxonomy_for(burst):
    # Burst class in tenths with integer compare only.
    # At most 66 maps to lat zero. At most 91 maps to batch one
    # which stays the default. Above maps to idle two.
    # Report only with no scheduler use and no accuracy claim.
    if burst <= 66:
        return 0
    if burst <= 91:
        return 1
    return 2


def share_for(tax):
    # Share step for a burst class with integer constants only.
    # Lat maps to four hundred. Batch maps to one hundred which
    # stays the default. Idle maps to twenty. Report only.
    if tax == 0:
        return 400
    if tax == 2:
        return 20
    return 100


def mean_int(vals):
    # Integer mean with floor divide and no float math.
    if not vals:
        return 0
    total = 0
    for v in vals:
        total = total + v
    return total // len(vals)


def pctl_int(sorted_vals, pct):
    # Integer percentile from a sorted list with floor index.
    # pct holds 0 to 100. Index uses floor divide only.
    n = len(sorted_vals)
    if n == 0:
        return 0
    if pct < 0:
        pct = 0
    if pct > 100:
        pct = 100
    idx = (n * pct) // 100
    if idx >= n:
        idx = n - 1
    return sorted_vals[idx]


def is_tmp_path(path):
    # Refuse any report path outside the temp dir with string checks.
    # Dotsplit refuses parent escapes with no filesystem call.
    if not path:
        return False
    if path == "/tmp":
        return False
    if not path.startswith("/tmp/"):
        return False
    for part in path.split("/"):
        if part == "..":
            return False
    return True


def load_frames(path):
    with open(path) as f:
        data = json.load(f)
    rows = []
    for fr in data.get("frames", []):
        # Tenths of ms as integers with no float math.
        c10 = tenths_from_ms_num(fr.get("cpu", 0))
        g10 = tenths_from_ms_num(fr.get("gpu", 0))
        rows.append((c10, g10))
    return rows


def load_harness(path):
    rows = []
    with open(path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            # Probe p99 in us scaled to tenths of ms with integer
            # decimal parse and no float.
            p99 = row.get("probe_p99_us", "0") or "0"
            whole = parse_tenths_ms(p99)
            rows.append((whole, whole))
    return rows


def load_lestat(path):
    # Lestat frametime rows in ms mapped to duplicated tenths.
    # Finds the fps header with frametime then parses each row
    # with integer digits only and no float math. Preamble lines
    # plus blank lines plus dash lines stay skipped report only.
    rows = []
    with open(path, newline="") as f:
        text = f.read()
    lines = text.splitlines()
    header_idx = -1
    header_fields = []
    for idx in range(len(lines)):
        line = lines[idx]
        if "frametime" in line and "fps" in line:
            header_idx = idx
            header_fields = [h.strip() for h in line.split(",")]
            break
    if header_idx < 0:
        return rows
    ft_pos = -1
    for pos in range(len(header_fields)):
        if header_fields[pos] == "frametime":
            ft_pos = pos
    if ft_pos < 0:
        return rows
    for idx in range(header_idx + 1, len(lines)):
        raw = lines[idx].strip()
        if not raw:
            continue
        if raw.startswith("-"):
            continue
        parts = lines[idx].split(",")
        if ft_pos >= len(parts):
            continue
        f10 = tenths_from_ms_str(parts[ft_pos])
        if f10 < 0:
            f10 = 0
        rows.append((f10, f10))
    return rows


def load_any(path):
    if path.endswith(".json"):
        return load_frames(path)
    # Auto detect csv kind by header text with string search only.
    # Frametime without probe maps to lestat rows with duplicated
    # tenths. Probe headers plus old headers map to harness rows
    # for compat with no float use and no scheduler import.
    with open(path, newline="") as f:
        head = f.read(8192)
    has_probe = False
    has_frame = False
    if "probe_p99_us" in head:
        has_probe = True
    if "frametime" in head:
        has_frame = True
    if has_frame and not has_probe:
        return load_lestat(path)
    return load_harness(path)


def shard_avgs(hints, nshards):
    # Contiguous shard means with floor divide and no float math.
    # Shards split in input order. Short tails join the last shard.
    n = len(hints)
    if n == 0 or nshards <= 0:
        return []
    if nshards > n:
        nshards = n
    if nshards > 16:
        nshards = 16
    base = n // nshards
    rest = n - base * nshards
    out = []
    pos = 0
    for i in range(nshards):
        size = base + (1 if i < rest else 0)
        total = 0
        for k in range(size):
            total = total + hints[pos + k]
        pos = pos + size
        if size > 0:
            out.append(total // size)
    return out


def baseline_errors(bursts):
    # Averaging baseline errors with running integer mean only.
    # First row has no prior so it starts from the second row.
    # Report only with no threshold and no accuracy claim.
    errs = []
    total = 0
    count = 0
    for b in bursts:
        if count > 0:
            pred = total // count
            errs.append(abs_int(pred - b))
        total = total + b
        count = count + 1
    return errs


def sweep_means(rows):
    # Bounded sweep over placeholder weights with integer math.
    # Each variant moves one entry by one with no larger step.
    # Returns name plus mean proxy error pairs report only.
    bursts = []
    for c10, g10 in rows:
        bursts.append(burst_for(c10, g10))
    variants = [
        ("base", [[3, -2], [2, 4]], [1, -1], [2, 3], 0),
        ("w00_up", [[4, -2], [2, 4]], [1, -1], [2, 3], 0),
        ("w00_dn", [[2, -2], [2, 4]], [1, -1], [2, 3], 0),
        ("w01_up", [[3, -1], [2, 4]], [1, -1], [2, 3], 0),
        ("w01_dn", [[3, -3], [2, 4]], [1, -1], [2, 3], 0),
        ("w10_up", [[3, -2], [3, 4]], [1, -1], [2, 3], 0),
        ("w11_up", [[3, -2], [2, 5]], [1, -1], [2, 3], 0),
        ("o0_up", [[3, -2], [2, 4]], [1, -1], [3, 3], 0),
        ("o1_up", [[3, -2], [2, 4]], [1, -1], [2, 4], 0),
    ]
    out = []
    for name, w1, b1, w2, b2 in variants:
        errs = []
        for idx in range(len(rows)):
            c10, g10 = rows[idx]
            h = hint_for_w(c10, g10, w1, b1, w2, b2)
            errs.append(abs_int(proxy_for(h) - bursts[idx]))
        out.append((name, mean_int(errs)))
    return out


def build_lines(rows, per_file, nshards):
    # Batch report lines with integer math only and no float use.
    # First line keeps the old rows plus avg_hint form for compat.
    # Later lines add proxy error plus saturation plus stability
    # plus sweep against the averaging baseline report only.
    # Taxonomy plus share lines stay report only with no threshold
    # and no accuracy claim and calibration still required.
    hints = []
    bursts = []
    for c10, g10 in rows:
        hints.append(hint_for(c10, g10))
        bursts.append(burst_for(c10, g10))
    avg = mean_int(hints)
    errs = []
    for i in range(len(rows)):
        errs.append(abs_int(proxy_for(hints[i]) - bursts[i]))
    serr = sorted(errs)
    mean_err = mean_int(errs)
    p50_err = pctl_int(serr, 50)
    p99_err = pctl_int(serr, 99)
    berrs = baseline_errors(bursts)
    sberr = sorted(berrs)
    bmean = mean_int(berrs)
    bp50 = pctl_int(sberr, 50)
    bp99 = pctl_int(sberr, 99)
    sat = 0
    for h in hints:
        if h == LO or h == HI:
            sat = sat + 1
    sat_pm = (sat * 1000) // len(rows) if rows else 0
    avgs = shard_avgs(hints, nshards)
    smin = avgs[0] if avgs else 0
    smax = avgs[0] if avgs else 0
    for v in avgs:
        if v < smin:
            smin = v
        if v > smax:
            smax = v
    spread = smax - smin
    spread_pm = (spread * 1000) // avg if avg > 0 else 0
    sweeps = sweep_means(rows)
    best_name = sweeps[0][0] if sweeps else "base"
    best_mean = sweeps[0][1] if sweeps else 0
    for name, val in sweeps:
        if val < best_mean:
            best_mean = val
            best_name = name
    tax_lat = 0
    tax_batch = 0
    tax_idle = 0
    for b in bursts:
        t = taxonomy_for(b)
        if t == 0:
            tax_lat = tax_lat + 1
        elif t == 2:
            tax_idle = tax_idle + 1
        else:
            tax_batch = tax_batch + 1
    share_lat = share_for(0)
    share_batch = share_for(1)
    share_idle = share_for(2)
    lines = []
    lines.append(f"rows {len(rows)} avg_hint {avg}")
    lines.append(f"mean_err {mean_err} p50_err {p50_err} p99_err {p99_err}")
    lines.append(f"baseline_mean_err {bmean} baseline_p50 {bp50} baseline_p99 {bp99}")
    lines.append(f"sat_count {sat} sat_permille {sat_pm}")
    lines.append(f"shards {len(avgs)} shard_min {smin} shard_max {smax} shard_spread {spread} shard_spread_permille {spread_pm}")
    sweep_bits = []
    for name, val in sweeps:
        sweep_bits.append(f"{name}={val}")
    lines.append("sweep " + " ".join(sweep_bits))
    lines.append(f"sweep_best {best_name} sweep_best_mean {best_mean}")
    lines.append(f"taxonomy lat {tax_lat} batch {tax_batch} idle {tax_idle}")
    lines.append(f"share lat {share_lat} batch {share_batch} idle {share_idle}")
    lines.append(f"files {len(per_file)}")
    for path, count, favg in per_file:
        lines.append(f"file {path} rows {count} avg_hint {favg}")
    return lines


def main():
    args = sys.argv[1:]
    report = ""
    nshards = 2
    inputs = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--report":
            i = i + 1
            if i >= len(args):
                print("missing report path", file=sys.stderr)
                return 2
            report = args[i]
        elif a == "--shards":
            i = i + 1
            if i >= len(args):
                print("missing shards count", file=sys.stderr)
                return 2
            digits = args[i]
            val = 0
            for ch in digits:
                if "0" <= ch <= "9":
                    val = val * 10 + (ord(ch) - 48)
            nshards = val
            if nshards < 1:
                nshards = 1
            if nshards > 16:
                nshards = 16
        elif a == "--sweep":
            # Accepted for explicit calibration runs. Sweep already
            # ships in every report so the flag changes nothing.
            pass
        elif a.startswith("--"):
            print(f"unknown flag {a}", file=sys.stderr)
            return 2
        else:
            inputs.append(a)
        i = i + 1
    if not inputs:
        print("use nn_hint.py PATH.json|PATH.csv [more ...] [--report /tmp/file] [--shards N] [--sweep]", file=sys.stderr)
        return 2
    if report and not is_tmp_path(report):
        print("report path must stay under /tmp", file=sys.stderr)
        return 2
    rows = []
    per_file = []
    for path in inputs:
        part = load_any(path)
        total = 0
        for c10, g10 in part:
            rows.append((c10, g10))
        for c10, g10 in part:
            total = total + hint_for(c10, g10)
        favg = total // len(part) if part else 0
        per_file.append((path, len(part), favg))
    if not rows:
        print("no rows", file=sys.stderr)
        return 1
    lines = build_lines(rows, per_file, nshards)
    for line in lines:
        print(line)
    if report:
        with open(report, "w") as f:
            for line in lines:
                f.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
