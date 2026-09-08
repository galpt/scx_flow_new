# scx_flow_new

This repo holds the flow scheduler source in `scx`, plus the
installer in `tools` and this readme at the root. The layout
matches an overlay build. The `scx` dir copies into a
workspace at `scheds/experimental/scx_flow` and builds there.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.0.0`
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

## Breaking note in 4.0.0

Version stays at `4.0.0` by user decision, but this
release breaks prior behavior. The prior three queues
per cpu are now one ordered queue per cpu. Queue ids use
base `0x1000` plus cpu with stride one. Counters now use
placements and requeues, with per level placements and
demotions removed. The dashboard payload now uses live
mean, total queued, per cpu depths and head and tail
ages, with per level means and depths removed. Old
dashboards and old stat readers need an update.

## Design

One ordered queue per cpu. Queue ids use base `0x1000`
plus cpu with stride one, plus a global park. Inserts
order by estimate only. Unknown estimates map to key
zero and sort at the front. Known estimates map to the
clamped estimate and sort ascending. Equal keys keep
insert order. The slice follows the live global mean
only, so the grant is independent of the key. The mean
covers all accounted tasks, seeded at two milliseconds
and clamped to five hundred microseconds and thirty two
milliseconds. Estimates clamp at one nanosecond to one
second. Running tasks stay counted. A release happens
exactly once on block, dequeue, disable and exit. A
runnable requeue refreshes the sum and reinserts in
order. There is no demote step. Enqueue keys the queue
off the selected cpu, then the first allowed cpu, then
the global park. Dispatch drains the local queue in a
batch of thirty two. Steal scans in one pass of sixty
four checks with rotation and a mask guard. There is no
guarantee slot and no preempt kick. Counts use
saturating means with compare and swap. Dispatches count
local and remote moves. Steals count remote moves. The
watchdog is thirty thousand milliseconds. Ops name is
`flow`.

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
`4.0.0`, state `enabled` and ops containing `flow`. To
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
