# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this README at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.2.19`
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
- `scx/src/flow_preempt.rs` delay plus granule plus rate
- `scx/src/flow_tests_edf.rs` tests for S1 to S3 plus slice,
  estimate, weight, EDF order, frontier, dispatch, steal,
  mask, and config
- `scx/src/flow_tests_group.rs` tests for split plus parks plus
  classifier plus isolation plus inflate
- `scx/src/flow_tests_preempt.rs` tests for delay plus
  granule plus rate plus fail closed
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` display only per-CPU cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page with group plus delay
- `tools/install_scx_flow.sh` overlay build installer
- `tools/edf_harness/harness.c` periodic load plus probe worker
- `tools/edf_harness/run.sh` calibration plus sweep plus control
- `tools/edf_harness/README.md` harness note with light p95
- `LICENSE` full license text, a real file

## Design

### Order and deadlines

Each CPU keeps an ordered queue plus one park queue per
group. Earliest deadline runs first with arrival order
for ties. The deadline adds clamped virtual time and a
scaled burst estimate at live weight from nice. Exiting
tasks run at once on this CPU via local with no order
wait. Falls back when this CPU is not allowed. The math
lives in `scx/src/bpf/intf.h`, inserts in
`scx/src/bpf/enqueue.bpf.c`.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice so the start stays neutral. Estimates hold
the last burst clamped at 1ns to 1 second.

### Fairness

A waking task gains at most a weight scaled cap in 125us
to 8ms over the frontier, so sleep never buys priority.
Virtual time moves forward with scaled runtime while work
stays queued and resets to waking time on idle, so new
arrivals never inherit stale time. The rules live in
`scx/src/bpf/lifecycle.bpf.c`.

### Placement

Order is waker CPU when idle in group, free core in group,
any idle in group, prior, current, then least queued
in group, then first allowed, and the task mask
always wins. Least picks lowest queued depth with
lowest id on ties. An idle core cannot
stack, so locality is free. Every other case keeps
current behavior. Groups split physical cores with
siblings kept together and cache local shares where
the hardware allows. Online ranks seed by id with offline
light inert, skewed forces ready one, dense full keeps
prior state. Strict when ready is zero, best
effort when ready is one. The order lives in
`scx/src/bpf/select_cpu.bpf.c` plus
`scx/src/bpf/enqueue.bpf.c`, seeding in
`scx/src/topology.rs`.

### Dispatch

Order is local queue, group park, then steals from peers
with mask checks. An idle thief with no moved plus no own
left may rescue a lone queued task past unmovable park
leftovers, busy thieves keep depth 2. Every pass moves at
least one task when movable work exists. Dispatch uses
halves while placement uses the live table seeded by
online rank. Snapshot covers online only. The drains live
in `scx/src/bpf/dispatch.bpf.c`.

### Kicks

Idle targets with at most 2 queued are kicked with a mask
check. Busy targets need latched delay arm 16 stand 8
in 32us units plus deserved woken deadline before
frontier plus quarter granule weight aware with 64us
floor plus same group plus mask plus atomic rate claim
with one kick per slice alone, bounded extra on
overlap. Frontier is the service floor, so beating
it by granule proves earliness with no occupant
state. Short heavy granule is stricter, tempering
the deadline lead, net easiness is deadline math.
Quarter bounds theft near 25% of a slice, floor
at 64us covers switch cost. Uses woken weight only.
Total plus five reasons cover all fail-closed busy
no-kicks in branch order armed plus deserved plus group
plus mask plus rate. One coalesced count covers q2 idle
skips in 50us at 200B. Second queued to idle in 50us
skips when not pinned with no slide, single queued
always kicks, deep stays quiet, pinned never skips.
Delay persists across idle, delay shows stale
when idle. A missed wakeup is rescued on the next
insert while deep queues stay quiet. Park sends
no kick and the next pass collects it. Disarmed
stays idle only. See `scx/src/bpf/intf.h` plus
`scx/src/bpf/main.bpf.c` plus
`scx/src/bpf/enqueue.bpf.c` plus
`scx/src/flow_select.rs`.

### Counts and queues

Counters cover inserts, completions, steals, kicks,
preempt kicks plus total skips plus five split reasons
plus coalesced, EDF order events, group moves, and
skips. The dashboard shows them per group and per CPU
with delay dots plus rates and a one-click JSON log
download at `/api/snapshot`. The payload lives in
`scx/src/stats.rs`, `scx/src/webui.rs` and
`scx/ui/index.html`.

### Measurement

For A/B comparison, install
one build, measure the same workload, then install the other
build and compare with no other change. The harness probe
plus the control flag support baseline comparison with no
scheduler change in the harness.

### Limits

Weight follows nice from minus 20 to 19 with center 1024
and no knob. Groups stay fixed at two with no knob. The
slice stays fixed at 1ms. Delay arms at 16 stands at 8
in 32us units with 1/8 decay and one kick per slice.
Granule is quarter scaled slice floored at 64us.

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
Expect version `4.2.19`, state `enabled` and ops
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
