#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Offline hint replay with integer math only and no scheduler use.
# Reads raw frame rows or harness rows and prints a clamped hint.
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


def main():
    if len(sys.argv) != 2:
        print("use nn_hint.py PATH.json|PATH.csv", file=sys.stderr)
        return 2
    path = sys.argv[1]
    if path.endswith(".json"):
        rows = load_frames(path)
    else:
        rows = load_harness(path)
    if not rows:
        print("no rows", file=sys.stderr)
        return 1
    total = 0
    for c10, g10 in rows:
        total += hint_for(c10, g10)
    avg = total // len(rows)
    print(f"rows {len(rows)} avg_hint {avg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
