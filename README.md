# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this README at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

> [!NOTE]
> The `main` branch can be unstable. Stable versions will use `archive/*` branch names.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.0.3`
- `scx/build.rs` BPF build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` BPF core and ops table
- `scx/src/main.rs` frontend and run loop
- `scx/src/flow.rs` pure helpers with unit tests
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` trimmed per CPU cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page
- `tools/install_scx_flow.sh` overlay build installer
- `LICENSE` full license text, a real file

## Design

Two tiers share the work. Tier zero is interactive with
a five hundred microsecond slice and direct placement
to the target DSQ. Head inserts carry wakeups and tail
inserts carry requeues. Tier one is batch with an eight
millisecond slice through one shared DSQ ordered by
vruntime. The batch DSQ uses id `0x2000` and the park
DSQ uses id `0x2001` for tasks with no allowed CPU. New
tasks start in tier zero. Estimates hold the last burst
clamped at one nanosecond to one second with no
smoothing. A runnable task that burns the full slice
moves down one tier at once. The burn check compares
the burst against the stored grant. Blocked tasks build
a streak of short bursts below one millisecond. Three
short blocks move up one tier with the streak capped at
seven. Dispatch serves eight tier zero runs per tier
one run when both tiers hold work. An idle kick is sent
on every insert with a valid target. A narrow busy
preemption covers tier zero wakeups against tier one
runners with a per CPU gap of one millisecond. New
batch tasks join at the vruntime floor. Running batch
tasks advance by the burst with saturation.
Counts use atomics with saturation on gauges.
Inserts and runs count per tier. Moves, gated serves,
kicks and preemptions count across tiers.
The watchdog is thirty thousand milliseconds. Ops name
is `flow`.

## Build

Full builds need a workspace checkout since path deps use
`../../../rust`. Copy `scx` into the workspace and build:

```
rsync -a scx/ WS/scheds/experimental/scx_flow/
cargo build --manifest-path WS/scheds/experimental/scx_flow/Cargo.toml
```

Or run `tools/install_scx_flow.sh WS` which overlays,
builds in release mode and installs the binary.

## Installer

`tools/install_scx_flow.sh` takes the workspace checkout
path and defaults to `/tmp/opencode/scx`. It needs
`cargo`, `clang` and `rsync`, plus a workspace with a
`rust` dir. Stop the running scheduler first:

```
sudo systemctl stop scx_loader 2>/dev/null || true
sudo bash tools/install_scx_flow.sh /tmp/scx-workspace
/usr/local/bin/scx_flow --version
sudo systemctl start scx_loader
sleep 2
cat /sys/kernel/sched_ext/state
cat /sys/kernel/sched_ext/root/ops
```

The script overlays `scx` into
`scheds/experimental/scx_flow`, builds in release mode
and installs to `/usr/local/bin`. Without root it copies
the binary to the repo dir instead. Expect version
`4.0.3`, state `enabled` and ops containing `flow`. To
roll back, stop the loader, restore the prior binary
and start the loader again.

## Run

```
scx_flow
scx_flow --stats 1
scx_flow --monitor 1
scx_flow --no-webui
```

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`.

## Checks

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

See `LICENSE`.
