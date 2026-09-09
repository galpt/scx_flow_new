#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
#
# Run the periodic EDF harness across load levels.
# Each level calibrates thread count for a target use
# on the host CPU count with average burst plus period.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_C="${HERE}/harness.c"
HARNESS_BIN="${HERE}/harness"
OUTDIR="${OUTDIR:-${HERE}/results}"
DURATION="${DURATION:-60}"
REPEATS="${REPEATS:-5}"
QUICK="${QUICK:-0}"

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required tool $1" >&2
        exit 1
    }
}

need gcc
need nproc
need python3

echo "building harness"
gcc -O2 -Wall -Wextra -pthread "${HARNESS_C}" -o "${HARNESS_BIN}"

NCPU="$(nproc)"
echo "host CPUs ${NCPU}"
mkdir -p "${OUTDIR}"

# Topology dump for variance context.
{
    echo "nproc ${NCPU}"
    echo "uname $(uname -srmv)"
    echo "kernel $(uname -r)"
    lscpu 2>/dev/null || echo "lscpu unknown"
    cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u || echo "governor unknown"
} > "${OUTDIR}/topology.txt"

# Average burst 9ms over average period 220ms gives
# per thread use near 0.0409. Thread count follows
# target use times CPU count over per thread use.
calc_n() {
    local target="$1"
    python3 -c "import math; print(int(round(float('${target}') * ${NCPU} * 220.0 / 9.0)))"
}

if [ "${QUICK}" = "1" ]; then
    LEVELS="1.0"
    DURATION="2"
    REPEATS="1"
else
    LEVELS="0.5 0.75 0.95 1.0 1.2 1.5"
fi

SUMMARY="${OUTDIR}/summary.csv"
STATS="${OUTDIR}/summary_stats.csv"
echo "target_u,nthreads,ncpu,wall_secs,released,completed,completion,offered_util,exact_util,effective_util,nvcsw,nivcsw,repeat,seed" > "${SUMMARY}"

for target in ${LEVELS}; do
    N="$(calc_n "${target}")"
    echo "level target ${target} threads ${N} duration ${DURATION} repeats ${REPEATS}"
    for rep in $(seq 1 "${REPEATS}"); do
        seed="${rep}"
        prefix="${OUTDIR}/u${target}_rep${rep}"
        "${HARNESS_BIN}" -n "${N}" -d "${DURATION}" -s "${seed}" -o "${prefix}"
        # Append one line with target plus repeat plus seed.
        tail -n 1 "${prefix}.csv" | awk -v t="${target}" -v r="${rep}" -v s="${seed}" -F, 'NR==1 {print t","$0","r","s}' >> "${SUMMARY}.tmp"
    done
done

# Merge header plus rows with target first.
{
    head -n 1 "${SUMMARY}"
    cat "${SUMMARY}.tmp"
} > "${SUMMARY}.new"
mv "${SUMMARY}.new" "${SUMMARY}"
rm -f "${SUMMARY}.tmp"

# Per level mean plus 95 CI across repeats.
python3 - "${SUMMARY}" "${STATS}" <<'PY'
import csv
import math
import sys
src = sys.argv[1]
dst = sys.argv[2]
groups = {}
with open(src, newline='') as f:
    r = csv.DictReader(f)
    for row in r:
        t = row['target_u']
        groups.setdefault(t, []).append(row)
cols = ['completion', 'offered_util', 'exact_util', 'effective_util', 'nvcsw']
with open(dst, 'w', newline='') as f:
    w = csv.writer(f)
    head = ['target_u', 'n']
    for c in cols:
        head += ['mean_' + c, 'ci95_' + c]
    w.writerow(head)
    for t in sorted(groups, key=float):
        rows = groups[t]
        n = len(rows)
        out = [t, n]
        for c in cols:
            xs = [float(x[c]) for x in rows]
            m = sum(xs) / n
            if n > 1:
                var = sum((v - m) ** 2 for v in xs) / (n - 1)
                s = math.sqrt(var)
                ci = 1.96 * s / math.sqrt(n)
            else:
                ci = 0.0
            out += [f'{m:.6f}', f'{ci:.6f}']
        w.writerow(out)
PY

# QUICK smoke self check keeps exact near offered.
if [ "${QUICK}" = "1" ]; then
    python3 - "${STATS}" <<'PY'
import csv
import sys
path = sys.argv[1]
with open(path, newline='') as f:
    rows = list(csv.DictReader(f))
assert len(rows) == 1, "quick expects one row"
offered = float(rows[0]['mean_offered_util'])
exact = float(rows[0]['mean_exact_util'])
assert offered > 0, "offered must be positive"
ratio = exact / offered
assert 0.5 <= ratio <= 2.0, f"exact {exact} not within 2x of offered {offered}"
print(f"quick exact check pass offered {offered:.4f} exact {exact:.4f} ratio {ratio:.4f}")
PY
fi

echo "wrote ${SUMMARY}"
echo "wrote ${STATS}"
cat "${STATS}"
ls -lh "${OUTDIR}" | head -n 20
