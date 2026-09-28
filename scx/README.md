# scx_flow

scx_flow is a Linux deadline scheduler in Rust with a BPF core and one fixed quantum.

### Ordering

One deadline queue per CPU plus one shared overflow tail orders by deadline. Global holds homeless tasks. Arrivals key past runtime, last deadline, now, and the served floor with a slack capped at twice the quantum, so order carries weight. Runtime grows by scaled time at stop. See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### Hierarchy

Hierarchy rows hold share plus pool by id with lazy refill and overflow parks for throttled work. One timer refills hinted pools and wakes parks. The gated pass moves starved parks with a leaf flag check. See `src/bpf/cgroup.bpf.c`.

### Placement

Placement prefers idle, then the shallowest same cache peer, then the previous CPU. Dispatch drains own, then steal, then global plus overflow, then gated in one batch at `32`. Steal runs only with an empty local queue. See `src/bpf/select_cpu.bpf.c`, `src/bpf/dispatch.bpf.c`, and `src/rust/stats.rs`.

### Reporting

Scheduling stays fixed without options. Reporting uses `--stats`, `--monitor`, and `--no-webui`. The dashboard serves loopback port `50005` with rates, per CPU pids, and a snapshot download. `--no-webui` disables it.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps plus helpers plus ops table live in `src/bpf/main.bpf.c` with splits in `src/bpf/main/`, `src/bpf/enqueue/`, and `src/bpf/dispatch/`, plus `select_cpu`, `lifecycle`, and `cgroup` ops files.
- Runtime mirrors with tests live in `src/rust/flow_runtime.rs` plus mirrors in `flow_edf.rs`, `flow_select.rs`, `flow_slice.rs`, `flow_slot.rs`, `flow_preempt.rs`, and `flow_cgrp.rs`, with facade in `flow.rs` and validation in `config.rs`.
- Snapshots plus stats plus dashboard live in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, and `ui/index.html`.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `48B` plus `8B` plus `8B` plus `48B` plus `136B` across task, CPU, topology, hierarchy, and counters.
- Needs kernels, `7.2` series and up.
