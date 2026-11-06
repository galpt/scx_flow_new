# scx_flow_new

Overlay repo for the flow scheduler. `scx` copies into a
workspace at `scheds/experimental/scx_flow` and builds there.
`tools` holds the installer. License in `LICENSE`.

## Layout

- `scx/Cargo.toml` package manifest
- `scx/build.rs` build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` queues, placement, and dispatch
- `scx/src/bpf/` nine area headers in one directory
- `scx/src/bpf/lib` is not present: helpers come from workspace headers
- `scx/src/main.rs` frontend and run loop
- `scx/src/stats.rs` counters and server view
- `scx/src/bpf_intf.rs`, `scx/src/bpf_skel.rs` generated bindings and skeleton
- `scx/README.md` scheduler behavior
- `tools/install_scx_flow.sh` overlay build installer
- `tools/test_install_guard.sh` installer checks
- `tools/edf_harness/` load probe with its own README

## Build

Copy `scx` into a workspace checkout and build there.
Scheduler behavior is documented in `scx/README.md`.
The installer pins fork
`e7b3a219617472cf78880ac424714e52c932db61`.

```bash
sudo bash tools/install_scx_flow.sh /tmp/scx-workspace
/usr/local/bin/scx_flow --version
```

Expect the current version, state `enabled`, ops with `flow`.

A reinstall from a prior release needs a restart. Queue ids, slice,
dispatch order, and stats follow this scheduler, see `scx/README.md`.

## Checks

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Run from inside the workspace so path deps resolve.

## License

See `LICENSE`.
