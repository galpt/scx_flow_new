# scx_flow_new

Overlay repo for the flow scheduler. `scx` copies into a
workspace at `scheds/experimental/scx_flow` and builds there.
`tools` holds the installer. License in `LICENSE`.

## Layout

- `scx/Cargo.toml` package manifest
- `scx/build.rs` build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` queues, placement, and dispatch
- `scx/src/bpf/` eight area headers in one directory
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

## Lifecycle

Tasks enter through init_task with the birth cgroup id and a weight
hint read from init args. Enqueue places by virtual time into one of
four per LLC queues and one fallback queue. Enqueue reads the weight
map by id on every insert, so a weight change applies to the next
enqueue. A missing entry, a zero id, a zero value, or a full map
reads as the default share. The burst estimate keeps half of the old
value and adds half of the fresh sample. It starts from a
fixed seed and is clamped to a floor and a ceiling. The estimate
and the wait age select one of four queues. Long waits lower the
estimate and very long waits reset it. Latency tasks queue with an
earlier key while the stored time is left unchanged. Pinned and
exiting tasks use the local queue first. Pinned tasks wait on the
allowed local queue with a single slice. Exiting tasks use a short
slice on the allowed local queue and the queue for their target
otherwise. Other tasks join the queue for their target with a single
slice. Running records the per CPU snapshot with reserved zero and
the queue and clears the queued bit. Dispatch already dropped the
gauge for shared moves and local inserts were never counted. Stopping
folds burnt time into the estimate through the half blend. Tick
refreshes the remaining slice. Dequeue drops the gauge on cancel.
Exit records through the exit info helper. Cgroup init, move, set
weight, and exit keep shares current. Reads that miss fall back to
the default. Ownership is held through the queued bit. A requeue
that finds the bit set is dropped and counted as a duplicate. Each
enqueue sends at most one idle wake. A wake goes only to an idle
target, else it counts a skip with no wake. A mask change on a queued
task keeps the queue and wakes the new owner when the owner is usable,
counting the wake.

A CPU that arrives late needs a restart. CPU and LLC tables are
written once at init within fixed bounds, so an offline or added CPU
after start does not reshape the tables. The same restart rule covers
the pinned path.

## Verifier budgets

All BPF loops are bounded with fixed caps. LLC walks stop at the LLC
count, and init walks stop at fixed CPU and LLC bounds. Virtual time
adds saturate at the top. The per LLC floor keeps fresh times unique
through a short compare and swap loop. Weight scaling splits used
nanos into slice units and rest so the multiply stays in range, then
caps at the top. Short job smoothing uses integer math that keeps
half of the old value and adds half of the sample. The
latency offset subtracts one fixed slice with saturation at zero. The
queued gauge drops through a short compare and swap loop that never
goes below zero and writes back the last value on contention. Wakes go
only to idle targets with no preempt. A busy target counts a skip with
no wake. The exiting slice stays at
one thousand nanos. Stats count twenty one counters in struct order
at 168 bytes with total matching penalty and extra combined per
award. The build carries a thin glue and eight area headers with
sixteen ops and stacks at or below five hundred twelve bytes.

## Reinstall safety

A reinstall from a prior release needs a restart. The installer
always starts from a fresh workspace. It refuses empty, root,
relative, whitespace, glob, dotdot escape, symlink, shared CI tree at
/tmp/opencode, bare /tmp, non allowlisted /tmp paths, home, usr, and
var trees, then fetches the pinned fork ref and verifies the head
before checkout. The overlay lib is byte identical with symlink
handling for lib and license, then builds and installs the binary.
After a good install only, an opt in clean may remove the workspace
target dir.

## Kernel support

The installer requires kernel 6.12 or newer for the cgroup weight hooks,
since cgroup init order against task init before 6.12 is unverified and
would stick defaults. The scheduler README recommends 7.2 or newer for
sched_ext. The two numbers differ by intent: 6.12 is the minimum for the
hooks, 7.2 is the recommendation for the subsystem. A missing entry,
a zero id, a zero value, or a full weight map reads as default and keeps
prior behavior.

## Cargo lock note

The overlay `scx/Cargo.lock` still records the prior package entry and is
left as is. It is never hand edited. CI assembles the workspace and
runs `cargo update -p scx_flow` to sync the entry, then builds and tests
with `--locked`. Local builds follow the same sync before any locked
check, so the file on disk never drifts into the binary.
