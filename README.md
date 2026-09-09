# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this README at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.2.5`
- `scx/build.rs` BPF build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` maps, shared helpers, ops table
- `scx/src/bpf/select_cpu.bpf.c` placement and LLC idle
- `scx/src/bpf/enqueue.bpf.c` routing, insert, and kick
- `scx/src/bpf/dispatch.bpf.c` own, park, and peer drains
- `scx/src/bpf/lifecycle.bpf.c` running, stopping, enable,
  disable, exit, dequeue
- `scx/src/main.rs` frontend and run loop
- `scx/src/snapshot.rs` metrics and dashboard snapshots
- `scx/src/flow.rs` facade that reexports the helpers
- `scx/src/flow_mean.rs` mean plus estimate plus slice
- `scx/src/flow_edf.rs` deadline plus runtime plus frontier
- `scx/src/flow_select.rs` placement plus steal plus mask
- `scx/src/flow_tests_edf.rs` tests only with S1 to S3
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` trimmed per-CPU cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page
- `tools/install_scx_flow.sh` overlay build installer
- `tools/edf_harness/harness.c` periodic load worker
- `tools/edf_harness/run.sh` calibration plus sweep
- `tools/edf_harness/README.md` harness note
- `LICENSE` full license text, a real file

## Design

### Order and deadlines

Each CPU keeps an ordered queue with a per-CPU mean slice.
Queues hold EDF order first with arrival order for ties.
The deadline adds clamped virtual time and scaled estimate.
The weight is fixed at 1024 with no custom heap. The kernel
queue orders by deadline with the mean as the slice.

### Mean slice

The per-CPU mean is the sum over unfinished work divided by
the count with the running task included. The seed is 8ms
with a floor of 500us and a ceiling of 32ms. Fresh tasks join
with the current mean so the mean stays neutral. Estimates
hold the last burst clamped at 1ns to 1 second with no
smoothing. Mean accounting caps each sample at 32ms so one
long burst never dominates the mean while the deadline still
uses the full estimate.

### Fairness

The sleeper cap keeps lag at one slice
behind the frontier, so a waking task gains at most one
slice of advantage with wrap safe order. Each grant stores
the mean at insert time. Blocked tasks complete and release
at once. Runnable tasks requeue ordered with a refreshed
estimate. Virtual time moves forward by scaled runtime and
the frontier moves forward while work stays queued. An idle
reset bounds to waking virtual time with no zero use, so new
arrivals never inherit stale time.

### Placement

Placement reuses the idle
prior CPU first with no count, then the LLC idle CPU, then
any idle CPU, then the prior and current CPUs.

### Dispatch

Dispatch
drains the local queue first, then the park queue, then
idle steals from peers. Each pass visits every queued task
in the owned and park queues in order and moves live tasks
with no move failure when allowed, including exiting tasks
so they run to exit, and skips past dead, foreign and failed
heads, so every pass moves at least one task when movable
work exists there. An idle CPU with no moved work steals past
unmovable leftovers, while a busy CPU with moved work steals
only when both queues are empty. Idle steals visit at most
8 peers with a rotating cursor and take the first task in a
peer queue that allows the thief when the donor holds at
least two tasks, moving past dead, foreign and failed heads
to rescue movable work behind a bad head.

### Kicks and hints

Kicks wake idle
targets only when the queue was empty with a mask check and
no busy preemption. Equal estimates skip the mean write.
Hints use only estimate against mean. Stops restore the low
hint when the CPU goes idle.

### Counts and queues

Counts cover inserts, requeues,
completions, park moves, steal moves, kicks, frozen fast hits,
frozen linger boosts and frozen reuse hits at zero, plus EDF
enqueued, EDF clamped and EDF ordered. Per-CPU queues use ids
`0x4000` plus the CPU id with up to 1024 CPUs. The park queue
uses id `0x5000` for tasks with no allowed CPU. The watchdog
is 30 seconds. Ops name is `flow`.

### Measurement

For A/B comparison, install
one build, measure the same workload, then install the other
build and compare with no other change.

### Limits

Version stays in
4.2 line with no Pi path. Pi is deferred with no kill and
no Pi use. Weight stays 1024 with no knob and no new maps
plus no new queue ids plus no new option.

### iEDF++

The revert gate
is `FLOW_GATE_IEDF` with batch plus grace plus shed plus
guard behind it. The paper improved EDF is `iEDF`, this
release proposes `iEDF++` with `M1` same deadline batching,
`M2` overrun grace, `M3` fair overload shed, `M4` idle
frontier guard, all behind `FLOW_GATE_IEDF`. The map is
`M1=batch/M2=grace/M3=shed/M4=guard`. Batch window is 96us in a 64 to 128 window
tiny past 500us floor, so sticky batching keeps warmth with
no fair loss. Grace is 50us tiny past 120ms least period,
so late accounting stays prompt with no kill. The harness
cancels, the scheduler never kills. Shed keeps order in park
with owner none plus grant plus frontier and no kill. Guard
keeps old on zero with no stale zero use. A value of 100
percent is a measured rate at feasible use only with no
guarantee. There is no gate on 98.5.

### History

The 4.2.2 landing
holds refactor content plus behavior content in one diff
with no struct size change in the refactor part and the
gate plus M1 to M4 in the behavior part with no new maps
plus no new queue ids plus no new option. The map is
`M1=batch/M2=grace/M3=shed/M4=guard`.

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
Expect version `4.2.5`, state `enabled` and ops
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
calibration plus sweep plus summary. Each thread draws
start jitter plus period plus execution with priority
recorded only and no scheduler use. See
`tools/edf_harness/README.md` for levels plus metrics
plus outputs. A value of 100 percent is a measured rate
at feasible use only with no guarantee. There is no
gate on 98.5. Use `stress-ng` only as background load
plus `cyclictest` plus `schbench` as cross checks with
no gate.

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

## References

1. Xiaojie Li and Xianbo He, The improved EDF scheduling algorithm for embedded real-time system in the uncertain environment, Proc. ICACTE, 2010, pp. V4-563 to V4-566. Read online at [ResearchGate](https://www.researchgate.net/publication/251952726_The_improved_EDF_scheduling_algorithm_for_embedded_real-time_system_in_the_uncertain_environment).
