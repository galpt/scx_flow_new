# scx_flow

scx_flow is a Linux deadline scheduler in Rust with a BPF core and one fixed quantum.

## Overview

### Queues

Each CPU owns one deadline queue at `0x6800` plus id, overflow at `0x7000` is shared, global holds homeless tasks. See `src/bpf/intf.h`.

### Deadlines

Every arrival steps past the later of now and last deadline, the step shrinks as weight grows. Nice folds into weight. See `src/bpf/enqueue.bpf.c`.

### Preemption

A busy CPU kicks only for a strictly earlier deadline. Equal or later arrivals pace at slice expiry. Pinned arrivals never kick. See `src/bpf/enqueue.bpf.c`.

### Placement

Order is waker idle, any idle, shallowest same cache peer over bound `8` when strictly shallower than previous, then previous, then first. See `src/bpf/select_cpu.bpf.c`.

### Dispatch

Order is own queue at `12`, one peer steal of one task, global plus overflow at `4`, then a gated pass. See `src/bpf/dispatch.bpf.c`.

### Steal

Steal runs only with an empty local queue. Sibling wins first, then same cache domain, then a gated move past `2ms`. See `src/bpf/dispatch.bpf.c`.

### Accounting

Running stamps segment start, stopping charges raw time and counts one requeue or completion, disable plus exit charge a leftover once. See `src/bpf/lifecycle.bpf.c`.

### Counters

Counters stay at `104B` with `13` live fields. JSON carries live counters only, slice reads the fixed quantum. See `src/stats.rs`.

## Configuration

Scheduling stays fixed without options. Reporting only uses `--stats`, `--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port `50005` with rates, per CPU pids, and a snapshot download. `--no-webui` disables it.

## Code map

- Queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_select.rs`, `src/flow_preempt.rs`,
  `src/flow_slot.rs`
- Facade: `src/flow.rs`
- Tests: inline `tests` modules in each mirror
- Constant validation: `src/config.rs`
- Generated bindings and skeleton: `src/bpf_intf.rs`,
  `src/bpf_skel.rs`
- Snapshot and topology: `src/snapshot.rs`,
  `src/topology.rs`
- Stats and dashboard payload: `src/stats.rs`,
  `src/webui.rs`, `ui/index.html`

## Limitations

- Live means below the attach snapshot. Hotplug needs a restart.
- Releases need a restart. State is `24B` plus `8B` plus `104B`.
- Needs kernels, `7.2` series and up.
