# scx_flow_new

Overlay repo for the flow scheduler. `scx` copies into a
workspace at `scheds/experimental/scx_flow` and builds there.
`tools` holds the installer. License in `LICENSE`.

## Layout

- `scx/Cargo.toml` package `scx_flow`
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/` maps, placement, and dispatch
- `scx/src/main.rs` frontend and run loop
- `scx/src/bpf_intf.rs`, `scx/src/bpf_skel.rs` generated bindings and skeleton
- `scx/src/rust/config.rs` constant validation
- `scx/src/rust/flow/` scheduling order plus admission with facade in `mod.rs`
- `scx/src/rust/snapshot.rs` counters plus dashboard view with per CPU pids
- `scx/src/rust/stats.rs` counters plus dashboard view with raw counters
- `scx/src/rust/topology.rs` online plus node view for the seed
- `scx/src/rust/webui.rs` loopback dashboard with page plus JSON
- `scx/ui/index.html` dashboard page with counters plus cards plus download
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

Expect the current version, state `enabled`, ops with `flow`.

This scheduler needs a restart from prior releases
with no live transition. Queue ids, slice, dispatch order, and stats follow
this scheduler, see `scx/README.md`.

## Checks

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run from inside the workspace so path deps resolve.

## License

See `LICENSE`.
