# scx_flow

scx_flow is a Linux deadline scheduler in Rust with a BPF core and one fixed quantum.

## Overview

Each CPU owns one deadline queue. Overflow is shared, and global holds homeless tasks.

Every arrival keys past the later of runtime, last deadline, now, and the served floor, with a slack capped at twice the quantum. Task weight folds nice with hierarchy share to depth 8.

Runtime advances by scaled time at stop with the cached share. Cold or zero shares fold to base. Each CPU tracks a floor of served runtime, so a long sleep never earns credit.

Throttled hierarchies park in overflow. One timer refills hinted pools and wakes parks. The gated pass moves starved parks with a leaf flag check.

Placement prefers idle, then the shallowest same cache peer, then the previous CPU. Dispatch drains own, then steal, then global plus overflow, then gated. Steal runs only with an empty local queue.

Running counts once per claim. Stopping charges raw time plus pool drain. Moves carry deadline plus runtime.

## Configuration

Scheduling stays fixed without options. Reporting only uses `--stats`, `--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port 50005. `--no-webui` disables it.

## Code map

Rules live in `src/bpf/intf.h`. Maps live in `src/bpf/main.bpf.c` plus `src/bpf/main/`. Placement lives in `src/bpf/select_cpu.bpf.c`. Inserts live in `src/bpf/enqueue.bpf.c` plus `src/bpf/enqueue/`. Drains live in `src/bpf/dispatch.bpf.c` plus `src/bpf/dispatch/`. Lifecycle lives in `src/bpf/lifecycle.bpf.c`. Hierarchy lives in `src/bpf/cgroup.bpf.c`. Rust mirrors live in `src/rust/flow_runtime.rs`, `src/rust/flow_edf.rs`, `src/rust/flow_select.rs`, `src/rust/flow_preempt.rs`, `src/rust/flow_slot.rs`, and `src/rust/flow_cgrp.rs`, with the facade in `src/rust/flow.rs`. Constant validation lives in `src/rust/config.rs`.

## Limitations

Hotplug needs a restart. State is `48B` plus `8B` plus `8B` plus `48B` plus `136B` for task, CPU, topology, hierarchy, and counters. Needs kernels, `7.2` series and up.
