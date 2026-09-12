# scx_flow

EDF scheduler for Linux in Rust with a BPF core, running
inside sched_ext. One ordered queue per CPU, fixed 1ms
slice, two groups for light waits and hog burn. Knob-free.
The version is in `Cargo.toml`.

## Behavior

Order, slice, fairness, placement, dispatch, kicks,
governor mode, and cpuperf are documented at the exact
code. Start with `src/bpf/intf.h`, then `src/bpf/main.bpf.c`,
`src/bpf/select_cpu.bpf.c`, `src/bpf/enqueue.bpf.c`,
`src/bpf/dispatch.bpf.c`, and `src/bpf/lifecycle.bpf.c`.
Rust mirrors live in `src/flow_slice.rs`, `src/flow_edf.rs`,
`src/flow_select.rs`, `src/flow_group.rs`, and
`src/flow_preempt.rs`, with the facade in `src/flow.rs`.
Energy probing is in `src/rapl.rs` plus `src/snapshot.rs`,
served through `src/stats.rs`, `src/webui.rs`, and
`ui/index.html`. Tests sit beside the code in
`src/flow_tests_*.rs` plus module test blocks.

## Web UI

Loopback port `50005` with a unix socket fallback at
`/tmp/scx_flow.sock`. Shows group depths, move rates,
per-CPU cards, energy savings with a live trace, and a
JSON download. `--no-webui` disables it.

## Run

```
scx_flow
scx_flow --stats 1
scx_flow --monitor 1
scx_flow --no-webui
```

## Checks

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Builds need a workspace checkout since path deps use
`../../../rust`. Needs a kernel with sched_ext enabled.

## License

See `LICENSE`.
