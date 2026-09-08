# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this readme at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.0.1`
- `scx/build.rs` BPF build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` BPF core and ops table
- `scx/src/main.rs` front end and run loop
- `scx/src/flow.rs` pure helpers with unit tests
- `scx/src/config.rs` validated constants with tests
- `scx/src/stats.rs` stats server and web snapshot
- `scx/src/topology.rs` trimmed per cpu cards
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page
- `tools/install_scx_flow.sh` overlay build installer
- `LICENSE` full license text, a real file

## Design

Three queues per cpu. Queue ids use base `0x1000`
plus cpu times three plus queue index, plus one park
queue per queue index. New tasks start in queue zero.
Each queue keeps FIFO order. Each queue keeps its own
mean for the slice. Queue zero seeds at one millisecond
and clamps to five hundred microseconds and four
milliseconds. Queue one seeds at two milliseconds and
clamps to one millisecond and eight milliseconds.
Queue two seeds at eight milliseconds and clamps to
four milliseconds and thirty two milliseconds.
Estimates hold the last burst clamped at one nanosecond
to one second with no smoothing. A runnable task that
burns the full slice moves down one queue. Blocked
tasks and short runs hold the queue. A head age past
five hundred milliseconds lifts the queue past strict
order and moves the task up one queue. Enqueue keys
the cpu off the selected cpu, then the first allowed
cpu, then the park. Dispatch moves up to thirty two
tasks in strict queue order with the age override.
Steal scans up to sixty four checks in queue order with
rotation and a mask guard. An idle wakeup kick asks
an idle target to collect work at once.
Counts use saturating means with compare and swap.
Placements, moves down and moves up count per queue.
Requeues, steals, dispatches and kicks count across
queues.
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
`4.0.1`, state `enabled` and ops containing `flow`. To
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
