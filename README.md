# scx_flow_new

Overlay repo for the flow scheduler. `scx` copies into a
workspace at `scheds/experimental/scx_flow` and builds there.
`tools` holds the installer. License in `LICENSE`.

## Layout

- `scx/Cargo.toml` package `scx_flow` at `4.4.0`
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/` maps, placement, and dispatch
- `scx/src/main.rs` frontend and run loop
- `scx/src/snapshot.rs` metrics and dashboard snapshots
- `scx/src/stats.rs` counters and web payload
- `scx/src/rapl.rs` package energy reads
- `scx/src/webui.rs` loopback dashboard server
- `scx/ui/index.html` dashboard page
- `tools/install_scx_flow.sh` overlay build installer
- `tools/edf_harness/` load probe with its own README

## Build

Copy `scx` into a workspace checkout and build there.
Scheduler behavior is documented in `scx/README.md`.
The installer pins upstream
`6752d59a4297d8918e8fd4d7237b50e2fceb1d14`.

```bash
sudo bash tools/install_scx_flow.sh /tmp/scx-workspace
/usr/local/bin/scx_flow --version
```

Expect version `4.4.0`, state `enabled`, ops with `flow`.

Breaking change from `4.3.x` needs a scheduler restart
with no live transition. Queue ids, lanes, slices, duty,
preempt classes, steal order, and dashboard JSON all changed,
see `scx/README.md`.

## Checks

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run from inside the workspace so path deps resolve.

## License

See `LICENSE`.
