# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this README at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.1.0`
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
- `scx/src/flow.rs` pure helpers with unit tests
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` trimmed per-CPU cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page
- `tools/install_scx_flow.sh` overlay build installer
- `LICENSE` full license text, a real file

## Design

Each CPU keeps an ordered queue with a per-CPU mean slice.
Queues hold short estimates first with arrival order for ties.
The per-CPU mean is the sum over unfinished work divided by
the count with the running task included. The seed is 8ms
with a floor of 500µs and a ceiling of 32ms. Fresh tasks join
with the current mean so the mean stays neutral. Estimates
hold the last burst clamped at 1ns to 1 second with no
smoothing. Mean accounting caps each sample at 32ms so one
long burst never dominates the mean while order still uses
the full estimate. Tiny bursts at most one quarter of the
mean run at once on the local queue when the target is idle
and empty. A run just past its grant and within one eighth
above it earns one ordered head start with no chain. Each
grant stores the mean at insert time. Blocked tasks
complete and release at once. Runnable tasks requeue ordered
with a refreshed estimate. Placement reuses the idle prior
CPU first with a reuse count, then the LLC idle CPU, then
any idle CPU, then the prior and current CPUs. Dispatch
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
to rescue movable work behind a bad head. Kicks wake idle
targets only when the queue was empty with a mask check and
no busy preemption. Equal estimates skip the mean write.
Hints use only estimate against mean. Stops restore the low
hint when the CPU goes idle. Counts cover inserts, requeues,
completions, park moves, steal moves, kicks, fast hits,
linger boosts and reuse hits. Per-CPU queues use ids `0x4000`
plus the CPU id with up to 1024 CPUs. The park queue uses id
`0x5000` for tasks with no allowed CPU. The watchdog is 30
seconds. Ops name is `flow`.

## Build

Full builds need a workspace checkout since path deps use
`../../../rust`. Copy `scx` into the workspace and build:

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
path and defaults to `/tmp/opencode/scx`. It needs
`cargo`, `clang` and `rsync`, plus a workspace with a
`rust` dir.

```bash
# 1. Stop the loader before replacing the binary
sudo systemctl stop scx_loader 2>/dev/null || true

# 2. Run the installer with a workspace checkout
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

The script overlays `scx` into
`scheds/experimental/scx_flow`, builds in release mode
and installs to `/usr/local/bin`. Without root it copies
the binary to the repo dir instead. Expect version
`4.1.0`, state `enabled` and ops containing `flow`. To
roll back, stop the loader, restore the prior binary
and start the loader again.

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
