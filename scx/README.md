# scx_flow

scx_flow is a Linux deadline scheduler in Rust with a BPF core and one global tree.

### Ordering

One global tree orders queued tasks by deadline then sequence. Arrivals key past virtual runtime or the dispatch floor with one tick, and runtime grows by scaled execution at stop, so order carries weight. See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### Hierarchy

Hierarchy rows hold share plus pool by id with lazy refill and a FIFO ring for throttled parks. See `src/bpf/cgroup.bpf.c`.

### Placement

Placement is a hint over waker idle, any idle, idlest cache peer, previous, then first. Dispatch drains tree, park ring, then global in one batch at `16`. A busy CPU kicks only for an earlier deadline, and parks kick idle CPUs only. See `src/bpf/select_cpu.bpf.c`, `src/bpf/dispatch.bpf.c`, and `src/rust/stats.rs`.

### Reporting

The `10ms` timer applies one cache domain transition past a `16ms` gap. Scheduling stays fixed without options. Reporting uses `--stats`, `--monitor`, and `--no-webui`. The dashboard serves loopback port `50005` with rates, per CPU pids, and a snapshot download. `--no-webui` disables it.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps plus helpers plus ops table live in `src/bpf/main.bpf.c` with splits in `src/bpf/main/`, `src/bpf/enqueue/`, and `src/bpf/dispatch/`, plus `select_cpu`, `lifecycle`, and `cgroup` ops files.
- Rust mirrors with tests live in `src/rust/flow_*.rs` with facade in `flow.rs` and validation in `config.rs`.
- Snapshots plus stats plus dashboard live in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, and `ui/index.html`.

## Limitations

- Live set stays below attach snapshot, so hotplug needs a restart.
- Releases need a restart.
- State is `64B` plus `8B` plus `8B` plus `48B` plus `24B` plus `128B` across task, CPU, topology, hierarchy, frequency, and counters.
- Frequency hints need a switching governor, else counts rise with no clock move.
- Needs kernels, `7.2` series and up.
