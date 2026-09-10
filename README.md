# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this README at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.2.8`
- `scx/build.rs` BPF build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` maps, shared helpers, ops table
- `scx/src/bpf/select_cpu.bpf.c` placement with group plus mask
- `scx/src/bpf/enqueue.bpf.c` routing, insert, group, and kick
- `scx/src/bpf/dispatch.bpf.c` own, group park, and peer drains
- `scx/src/bpf/lifecycle.bpf.c` running, stopping, classifier,
  enable, disable, exit, dequeue
- `scx/src/main.rs` frontend and run loop
- `scx/src/bpf_intf.rs` generated bindings for the shared header
- `scx/src/bpf_skel.rs` generated skeleton for the BPF object
- `scx/src/snapshot.rs` metrics and dashboard snapshots
- `scx/src/flow.rs` facade that reexports the helpers
- `scx/src/flow_slice.rs` slice plus estimate helpers
- `scx/src/flow_edf.rs` deadline plus runtime plus frontier
- `scx/src/flow_select.rs` placement plus steal plus mask
- `scx/src/flow_group.rs` groups plus classifier plus parks
- `scx/src/flow_tests_edf.rs` tests for S1 to S3 plus slice,
  estimate, EDF order, frontier, dispatch, steal, mask, and
  config
- `scx/src/flow_tests_group.rs` tests for split plus parks plus
  classifier plus isolation plus inflate
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` display only per-CPU cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page with group
- `tools/install_scx_flow.sh` overlay build installer
- `tools/edf_harness/harness.c` periodic load plus probe worker
- `tools/edf_harness/run.sh` calibration plus sweep plus control
- `tools/edf_harness/README.md` harness note with light p95
- `LICENSE` full license text, a real file

## Design

### Order and deadlines

Each CPU keeps an ordered queue with a fixed slice at 1ms.
Queues hold EDF order first with arrival order for ties.
The deadline adds clamped virtual time and scaled estimate.
The weight is fixed at 1024. The kernel
queue orders by deadline with the slice as the slice.
Our own EDF design uses per-CPU ordered queues plus
vruntime fairness plus the fixed slice.

### Fixed slice

The slice is fixed at 1ms with no knob.
Fresh tasks join with the slice so the start stays neutral.
Estimates hold the last burst clamped at 1ns to 1 second.
The deadline still
uses the full clamped estimate.

### Fairness

The sleeper cap keeps lag at one slice
behind the frontier, so a waking task gains at most one
slice of advantage with wrap safe order. Blocked tasks
complete at once. Runnable tasks requeue ordered with a
refreshed estimate. Virtual time moves forward by scaled
runtime and the frontier moves forward while work stays
queued. An idle reset bounds to waking virtual time with
no zero use, so new arrivals never inherit stale time.

### Placement

Placement uses any idle CPU in the group and mask,
then the prior CPU in the group, the current CPU in the
group, and the first allowed CPU in the group. Pinned tasks
and tasks that cannot move stay local with 8ms extra for
pinned hog. Empty masks park in order in the task group.
Frequency plus LLC plus CPU cards stay display only and never
shape placement.
Pinned subsets such as Lestat 16 plus 16 stay in mask.
Single-CPU Konaka never leaves. Two groups use a per CPU
table when ready, else halves with extra to hog and a single
CPU keeps all light. The table sorts live CPUs by capacity
plus frequency plus id, then interleaves even slots to light
and odd slots to hog. Uniform hosts keep ready cleared with
halves fallback. Capacity plus max frequency seed the table
when spread tops 10pct, else halves applies.

### Dispatch

Dispatch drains the local queue first, then the group park,
then idle steals from same group peers only. Own keeps no
group check, so a pinned single entry still runs where its
mask allows. Park rechecks each task group on mask pass
candidates with NULL as light plus immediate skip, so a
stale cross entry never moves. Peer keeps donor group plus
mask plus depth with no task recheck due to verifier jump
plus BSS bounds. Tier 2 uses park only immediate halves
with 995k under 1M. Each pass visits every queued task in
the local and park queues in order and moves live tasks
when allowed, including exiting tasks so they run to exit,
and skips past dead, foreign and failed heads, so every
pass moves at least one task when movable work exists
there. An idle CPU with no moved work steals past unmovable
leftovers, while a busy CPU with moved work steals only
when both queues are empty. Idle steals visit at most 8
same group peers with a rotating cursor and take the first
task in a peer queue that allows the thief when the donor
holds at least two tasks. Cross group peers are skipped
with no cross move and no counter. Cross group picks in
select plus enqueue count group skip. Park cross tasks
count group skip at once per task. Isolation follows enqueue
placement plus thief park choice plus donor group check,
with pinned single entries kept by the mask. Perf hints set
1024 for light and hog at init plus running with a weak
guard as best effort. One policy keeps both groups at max
since groups use dedicated CPUs, so hog frequency cannot
harm light latency, and the old half cap punished hogs
twice with no measurement.

### Kicks

Kicks wake idle
targets only when the queue was empty with a mask check and
no busy preemption. The queue length check uses at most one
queued task after insert.

### Counts and queues

Counts cover inserts, requeues,
completions, park moves, steal moves and kicks, plus EDF
enqueued, EDF clamped, EDF ordered, group demote, group
promote, pinned inflate, and group skip. Per-CPU queues use
ids `0x4000` plus the CPU id with up to 1024 CPUs. Two park
queues use ids `0x5000` for light and `0x5001` for hog for
tasks with no allowed CPU in the group. The watchdog
is 30 seconds. Ops name is `flow`. Task state stays at 48B
with wake hits at off 46. Per-CPU state stays at 24B.
Counters stay at 128B. Burn moves light to hog at 16ms in
a 32ms window or one burst at 4ms quiet down to 1ms floor
during flood. Depth sums light per CPU queued tasks with
table depth 0 to 1 to 4ms, depth 2 to 3 to 2ms, depth 4
plus to 1ms. Per task worst case is the 1ms floor during
flood. Eight short blocks below
1ms with low burn move hog to light at once. Middle window
keeps wake hits with no reset. Burn breaks the wake streak,
so gaming stays hard. Slow 64 wins near 2s stays intact.

### Measurement

For A/B comparison, install
one build, measure the same workload, then install the other
build and compare with no other change. The harness probe
plus the control flag support baseline comparison with no
scheduler change in the harness. For 4.2.8 compare light p95
from the probe plus schbench with the same workload.

### Limits

Version stays in
4.2 line at `4.2.8`. Weight stays 1024 with no knob.
Groups stay fixed at two with no knob. The slice
stays fixed at 1ms.

### History

The `4.2.6`
cleanup removes frozen `fast_hits`, `linger_boosts` and
`reuse_hits` with no behavior change, shrinking
`flow_stats` from `120B` to `96B`. The `4.2.7` strip keeps
a pure EDF core with a fixed slice at 1ms, task at 32B,
per-CPU at 24B, and counters at 96B. The `4.2.8` step adds
two strict groups with burn only moves, task at 48B, and
counters at 128B. The `4.2.6` base is
the last stable line. The `4.3.x` plus `4.4.0` lines were
tried and failed with stalls and were abandoned.

## Build

Full builds need a workspace checkout since path deps use
`../../../rust`. Copy `scx` into the workspace and build.

```
# 1. Copy the scheduler into a workspace checkout
rsync -a scx/ WS/scheds/experimental/scx_flow/

# 2. Build from inside the workspace so path deps resolve
cargo build --manifest-path WS/scheds/experimental/scx_flow/Cargo.toml
```

Alternatively, run `tools/install_scx_flow.sh WS` which overlays,
builds in release mode and installs the binary.

## Installer

`tools/install_scx_flow.sh` takes the workspace checkout
path and defaults to `/tmp/scx-workspace`. It needs
`cargo`, `clang`, `rsync` and `git`. The script always
starts fresh. It removes the workspace path, fetches the
upstream workspace at the pinned ref, so no stale tree is
ever reused on any run.

```bash
# 1. Stop the loader before replacing the binary
sudo systemctl stop scx_loader 2>/dev/null || true

# 2. Run the installer, it rebuilds the workspace fresh
# (first run downloads the upstream tree, takes a while)
sudo bash tools/install_scx_flow.sh /tmp/scx-workspace

# 3. Confirm the version
/usr/local/bin/scx_flow --version

# 4. Start the loader again
sudo systemctl start scx_loader

# 5. If the loader stays idle, start the scheduler by hand
sudo scxctl start --sched flow --mode auto

# 6. Confirm the scheduler is enabled
sleep 2; cat /sys/kernel/sched_ext/state

# 7. Confirm the ops string mentions flow
cat /sys/kernel/sched_ext/root/ops

# 8. Watch the loader log during testing
journalctl -u scx_loader -f
```

The script downloads the `sched-ext/scx` workspace at
the pinned ref `7cec98c51376a9d38b05a1e39e30cf7e5909cf16`
into the workspace path when missing, then overlays
`scx` into `scheds/experimental/scx_flow`, builds in
release mode and installs to `/usr/local/bin`. Without
root it copies the binary to the repo dir instead.
Expect version `4.2.8`, state `enabled` and ops
containing `flow`. To roll back, stop the loader,
restore the prior binary and start the loader again.
Set `CLEAN` to `1` to remove the workspace target dir
only after a good install with no clean on failure.
A clean rebuild fetches plus builds from scratch and
takes a while on first run with a fresh download. The
script keeps a single shell file with pinned ref plus
fresh remove plus fetch plus overlay plus release plus
install.

## Harness

`tools/edf_harness` holds a periodic load worker with
calibration plus sweep plus summary plus probe plus control.
Each worker draws start jitter plus period plus execution
with no scheduler use. One probe
wakes each 10ms and records wake delay as a light baseline
for light p95 comparison with the same workload.
All threads run with the default policy with no realtime use.
The binary is built on each run with no checked in binary.
See `tools/edf_harness/README.md` for levels plus metrics
plus outputs. A value of 100 percent is a measured rate
at feasible use only with no guarantee. There is no
threshold on 98.5. Use `stress-ng` only as background load
plus `cyclictest` plus `schbench` as cross checks with
no threshold.

## Run

```
# 1. Run with defaults
scx_flow

# 2. Print stats once per second
scx_flow --stats 1

# 3. Run the stats printer only
scx_flow --monitor 1

# 4. Run without the dashboard
scx_flow --no-webui
```

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`.

## Checks

```
# 1. Formatting must be clean
cargo fmt --check

# 2. Lints must be clean for the package
cargo clippy --all-targets -- -D warnings

# 3. Unit tests must pass
cargo test
```

## License

See `LICENSE`.
