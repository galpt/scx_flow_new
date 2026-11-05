# scx_flow_new

Overlay repo for the flow scheduler. `scx` copies into a
workspace at `scheds/experimental/scx_flow` and builds there.
`tools` holds the installer. License in `LICENSE`.

## Layout

- `scx/Cargo.toml` package manifest
- `scx/build.rs` build helper
- `scx/src/bpf/intf.h` shared constants and helpers
- `scx/src/bpf/main.bpf.c` queues, placement, and dispatch
- `scx/src/bpf/flow/` per area headers with no vendored sources
- `scx/src/bpf/lib` is absent: helpers come from workspace headers
- `scx/src/bpf/lib/minheap.bpf.c` shared heap
- `scx/src/bpf/lib/sdt_alloc.bpf.c` shared alloc
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
`b0efa3f614c0187df4cb3202d7b514d401f77d2a`.

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

## Lifecycle

Tasks enter through init_task with the birth cgroup cached as a hint,
then enqueue places by virtual time into the per LLC
queue. Stopping records a yield bit into the three bit task history, and
enqueue reads two of three early yields as latency else a hog with fresh
tasks neutral as hogs. Latency tasks take the queue key minus one fixed
slice one shot with stored time staying raw, while pinned plus exiting
bypass with prior behavior. Running records the per CPU snapshot plus the
latency flag and clears the queued flag, stopping folds burnt nanos into
the frequency hint, tick refreshes the remaining slice, dequeue clears
the queued flag, and exit records through the exit info helper. Cgroup
init, move, set weight, and exit keep weight shares current with fail
open reads as default. Single ownership holds through the queued flag
with no loss, and exiting tasks use a minimal slice on an allowed local
queue with fallback to the LLC queue. The kick compares boosted keys on
both sides with frozen gap plus tail, and an old wait that steps the
hold down counts an age rescue.

Hotplug needs a restart. CPU and LLC tables are seeded once at init with
fixed bounds, so an offline or added CPU after start never reshapes the
tables. The same restart rule covers the pinned path.

## Verifier budgets

All BPF loops are bounded with fixed caps. LLC walks
stop at the LLC count, and init walks stop at fixed CPU and LLC bounds.
Virtual
time adds one fixed slice with saturation at max and never wraps. Weight
scaling splits used nanos into slice units plus rest so the multiply never
overflows, then caps at max. Frequency smoothing uses bounded integer math
only with three parts prior plus one part fresh. The history classifier
uses bit math only with no loop, and the latency offset subtracts one
fixed slice with zero saturation one shot. Stats count twenty one
counters in struct order at 168 bytes with total meeting penalty
plus extra per award. No new
map, struct, helper, or branch was added for documentation.

## Reinstall safety

Reinstall needs a restart from prior releases with no live transition.
The installer always starts from a fresh workspace, refuses empty, root,
relative, whitespace, glob, dotdot escape, symlink, shared CI tree at
/tmp/opencode, bare /tmp, non allowlisted /tmp paths, home, usr, and var
trees, then fetches the pinned fork ref and verifies the head before
checkout. Overlay lib stays byte identical with symlink handling for lib
plus license, then builds and installs the binary. After a good install
only, an opt in clean may remove the workspace target dir.

## Kernel support

The installer requires kernel 6.12 or newer for the cgroup weight hooks,
since cgroup init order against task init before 6.12 is unverified and
would stick defaults. The scheduler README recommends 7.2 or newer for
sched_ext. The two numbers differ by design: 6.12 is the minimum for the
hooks, 7.2 is the recommendation for the subsystem. A miss, zero id, zero
value, or full weight map reads as default with prior behavior kept.

## Cargo lock note

The overlay `scx/Cargo.lock` still records the prior package entry and is
stale by design. It is never hand edited. CI assembles the workspace and
runs `cargo update -p scx_flow` to sync the entry, then builds and tests
with `--locked`. Local builds follow the same sync before any locked
check, so the stale file never drifts into the binary.
