# scx_flow

scx_flow is our own EDF scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per-CPU with a fixed slice at
1ms plus two groups for light waits and hog burn, strict
on uniform hosts and best effort on hetero hosts.
It is deliberately knob-free. It uses per-CPU ordered
EDF plus vruntime fairness plus the fixed slice.

## Overview

### Order and deadlines

Tasks wait in per-CPU ordered queues, plus one park queue per
group for tasks with no allowed CPU. Queues hold EDF order
first with arrival order for ties. The deadline adds clamped
virtual time and scaled estimate with a fixed weight of 1024.
The kernel queue orders by deadline with the slice as the
slice.

### Fixed slice

The slice is fixed at 1ms with no knob.
Fresh tasks join with the slice, so the start stays neutral.
Estimates hold the last burst clamped at 1ns to 1 second.

### Fairness

Sleeper lag is capped at one slice behind the
frontier, so a waking task gains at most one slice of advantage
with wrap safe order. Virtual time moves forward by scaled
runtime and the frontier moves forward while work stays queued.
An idle reset bounds to waking virtual time with no zero use.
Blocked tasks complete at once. Runnable tasks requeue ordered
with a refreshed estimate.

### Groups

Two groups use a per CPU table when ready, else halves
with extra to hog and a single CPU keeps all light. Odd
counts give the extra CPU to hog in both views, so
interleave matches halves counts. Short slices clamp
with no pad, so missing entries never fake hetero. The
`4.2.9` admission seeds the table only when capacity or
max frequency spread tops 10pct, else halves applies.
The `4.2.10` rule builds cores from thread siblings lists
with union find, then splits cores with extra to hog.
Siblings stay in one group. First half of cores is light
with the rest hog. One core with more than one CPU falls
back to halves, so no group stays empty. One LLC splits
cores globally. Two plus N LLCs split cores in each LLC,
so each cache domain stays balanced. Cores take the LLC
of the least id. Missing LLC folds to one domain with no
pad. All singleton cores bypass LLC and use halves plus
interleave exactly, so SMT off keeps prior state. Hetero
cores interleave by max capacity plus max frequency plus
least id with even slots to light and odd slots to hog
and the extra core to hog. The same table is reused with
no new tables. Task state stays at 48B with wake hits at
off 46. Per-CPU state stays at 24B. Counters stay at 136B.
Uniform hosts keep ready cleared when the core view matches
halves, else ready set. Hetero hosts keep ready set. Strict
on uniform hosts. Best effort on hetero hosts. Dispatch
uses halves. Placement uses live table. Snapshot mirrors
the live table when ready, else halves with no trap.
Machines with one thread per core keep halves plus
interleave exactly with preference as no-op and no trap.
Burn moves light to hog at 16ms in a 32ms window or one burst
at 4ms quiet down to 1ms floor during flood and returns
hog to light after 4ms low for 64 wins near 2s
or 8 short blocks below 1ms with burn below 4ms. Depth
sums light per CPU queued tasks with halves depth 0 to
1 to 4ms, depth 2 to 3 to 2ms, depth 4 plus to 1ms. Per
task worst case is the 1ms floor during flood. A burst
at the allowance clears wake hits. A short with burn at
or past 4ms clears wake hits. A hot window at or past
16ms clears wake hits. A middle window at the end clears
wake hits with low runs. A low window below 4ms keeps
wake hits. A window in progress keeps wake hits.
Cold tasks join light with a 4x gap against flaps.

### Placement

Placement uses a free core idle CPU in the group and mask,
then any idle CPU in the group and mask, then the prior CPU,
the current CPU, and the first allowed
CPU in the group. Tier A prefers a free core. Tier B prefers
any idle in the group. Placement only with no dispatch use.
Table is reused with no new tables. Singletons treat all
idle as free, so Tier A is a no-op with prior order and no
trap. The scan stays minimal with one extra idle pick and
no loop. Pinned tasks and tasks that cannot move stay
local with 8ms extra for pinned hog. Empty
masks park in order in the task group. Live frequency plus
CPU cards stay display only and never shape placement.
Max frequency plus capacity plus LLC plus siblings seed groups.
Pinned subsets such as Lestat 16 plus 16 stay in mask.
Single-CPU Konaka never leaves. Mask respect keeps every
choice inside the task mask.

### Dispatch

Dispatch drains the local queue first, then the group park,
then idle steals from peers with mask only. Own keeps no
group check, so a pinned single entry still runs where its
mask allows. Park drains the thief group park only with no
task recheck, so a stale cross entry may move on hetero
hosts with strict on uniform hosts. Peer keeps mask
plus depth with idle rescue and no task recheck, so a
depth 1 donor moves only when the thief is idle with no
moved plus no own left plus no park left. Busy thieves
keep depth 2. Tier 0 models also donor asleep rescue. BPF
ships thief idle only due to verifier jump at 1000001 on
asleep check, with donor asleep handled by idle kick.
Tier 3 holds park only by construction due to verifier
jump at 1000001 on donor check in the steal loop. Strict
park on uniform hosts. Best effort peer plus hetero hosts.
Dispatch uses halves. Placement uses live table. Each pass
visits every queued task in the local and park queues in
order and moves live tasks when allowed, including exiting
tasks so they run to exit, and skips past dead, foreign
and failed heads, so every pass moves at least one task
when movable work exists there. An idle CPU with no moved
work steals past unmovable leftovers, while a busy CPU
with moved work steals only when both queues are empty.
Idle steals scan peers only with a rotating cursor and
take the first task in a peer queue that allows the thief
when the donor meets min depth. Cross group tasks may move
with no counter. A cross task in any donor may move on
both uniform and hetero hosts. A stale cross task in the
group park may move on hetero hosts. Cross group picks in
select plus enqueue count group skip. Isolation follows
enqueue placement plus thief park choice with peer best
effort across groups, with pinned single entries kept by
the mask. Perf hints set
1024 for light and hog at init plus running
with a weak guard as best effort. One policy keeps both
groups at max since groups use dedicated CPUs, so hog
frequency cannot harm light latency, and the old half cap
punished hogs twice with no measurement.

### Kicks

Idle targets are kicked even with queued work
with a mask check and no busy preemption. Park sends no kick
with no live allowed CPU after fallback, and the next dispatch
pass collects it.

The slice math and the queue rules live in
`src/bpf/intf.h`, maps plus helpers plus the ops table in
`src/bpf/main.bpf.c`, placement in
`src/bpf/select_cpu.bpf.c`, inserts in
`src/bpf/enqueue.bpf.c`, drains in
`src/bpf/dispatch.bpf.c`, and lifecycle plus classifier in
`src/bpf/lifecycle.bpf.c`, the Rust mirrors
in `src/flow_slice.rs` plus `src/flow_edf.rs` plus
`src/flow_select.rs` plus `src/flow_group.rs` with a thin
facade in `src/flow.rs`
and tests for S1 to S3 plus slice, estimate, EDF order,
frontier, dispatch, steal, mask, groups, classifier,
and config in
`src/flow_tests_edf.rs` plus `src/flow_tests_group.rs`,
constant validation in
`src/config.rs`, generated bindings in `src/bpf_intf.rs`
plus the generated skeleton in `src/bpf_skel.rs`, and
snapshot plus topology in `src/snapshot.rs` plus
`src/topology.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with a 30 second watchdog. Version
is `4.2.9` in 4.2 line. Weight stays 1024 with no
knob. The slice stays fixed at 1ms.
Task state stays at 48B with wake hits at off 46.
Per-CPU state stays at 24B. Counters stay at 136B. The
`4.2.6` base is the last stable line. The `4.3.x` plus
`4.4.0` lines were tried and failed with stalls and were
abandoned. The `4.2.7` strip keeps a pure EDF core with
the fixed slice. The `4.2.8` step adds two groups with
burn only moves, strict on uniform hosts and best effort
on hetero hosts. The `4.2.9` step keeps task at 48B plus
per-CPU at 24B plus counters at 136B with idle singleton
rescue plus idle kick rescue plus running owner clear and
no new knob.

## Typical Use Cases

- Latency-sensitive applications. Short deadlines run first,
  so wakeups and frame work rarely wait behind long work.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with ordered queues while short arrivals keep draining
  first.

## Production Ready?

Yes on uniform hosts. Hetero hosts get best effort
grouping, see Limitations.

## Configuration

The scheduler is deliberately knob-free. The
scheduling constants are compile-time values in
`src/bpf/intf.h`, and no command-line option changes
the scheduling behavior. Groups stay fixed at two with
no knob. The runtime footprint depends
only on the reporting options, which are `--stats`,
`--monitor` and `--no-webui`. See `src/config.rs` and
`src/flow.rs` for the checked values and the unit tests
for slice fixed, estimate clamp, EDF order, sleeper cap,
frontier order, ordered inserts, progress guarantee, steal
bounds, donor depth, kick check, mask respect, groups,
classifier, display only
cards and config checks. For A/B comparison, install one build,
measure the same workload, then install the other build and
compare with no other change.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line and a per-CPU grid with group plus running
estimates and fixed slices, plus groups tiles for light
depth, hog depth, allowance, demote rate, promote rate,
wake rate, steal rate, and skip rate, plus system tiles
for EDF enqueued, EDF clamped, EDF ordered, demote,
promote plus wake promote, pinned inflate, and group
skip, plus version plus topology, with no
authentication, since the loopback address is the trust
boundary. A download button fetches `/api/snapshot`
with version plus timestamp plus topology plus per CPU
plus all counters and saves it as a timestamped file
with a blob save on loopback only.
`--no-webui` disables it. Empty states show an empty CPU
data card when no data has arrived.

## Queues

Each CPU keeps one ordered queue. Per-CPU queues use ids
`0x4000` plus the CPU id with up to 1024 CPUs. Two park queues
use ids `0x5000` for light and `0x5001` for hog and hold tasks
with no allowed CPU in the task group.

## Slices

Each CPU serves a fixed slice at 1ms. Per task
estimates hold the last burst clamped at 1ns
to 1 second. Fresh tasks join with the
slice, so the start stays neutral. Sleeper lag is capped
at one slice behind the frontier with wrap safe order.

## Insert and dispatch

Enqueue places each task on the selected CPU in the group
when allowed, then the first allowed CPU in the group,
then the group park. Pinned
tasks keep their CPU with the group moved to the live
group of that CPU and 8ms extra for pinned hog. Tasks
that cannot
move stay on the current CPU. Narrow opposite masks fall back
to the first allowed CPU with the group moved to match. Each
insert computes the
frontier and the slice, clamps virtual time to at most
one slice behind the frontier with wrap safety, scales
the estimate with a fixed weight of 1024, and stores the
deadline for the kernel queue with the slice as the slice.
Running keeps the entry. Blocking completes it at once.
Disable and exit count one completion plus clear running
only on owner match. Stopping adds burn to
a 32ms window and moves light to hog at 16ms burn or one
burst at 4ms quiet down to 1ms floor during flood and hog
to light after 4ms low for 64 wins near 2s. Depth sums
light per CPU queued tasks with table depth 0 to 1 to 4ms,
depth 2 to 3 to 2ms, depth 4 plus to 1ms. Per task worst
case is the 1ms floor during flood.
Dispatch drains the
local queue first, then the group park, then idle steals
from peers with mask only. Own keeps no group check. Park
drains the thief group park only with no task recheck, so a
stale cross entry may move on hetero hosts with strict on
uniform hosts. Peer keeps mask plus depth with idle rescue
and no task recheck, so a depth 1 donor moves only when
the thief is idle with no moved plus no own left plus no
park left. Busy thieves keep depth 2. Tier 0 models also
donor asleep rescue. BPF ships thief idle only due to
verifier jump at 1000001 on asleep check, with donor asleep
handled by idle kick. Strict park on uniform hosts. Best
effort peer plus hetero hosts. Dispatch uses halves.
Placement uses live table. Each pass moves up to 32 tasks
across local, park and steal. Each move in the local and
park queues moves live tasks when allowed, including
exiting tasks so they run to exit, and skips dead, foreign
and failed tasks, so one head never blocks later work
there. Steals take the first task in a peer queue that
allows the thief when the donor meets min depth. Cross
group tasks may move with no counter. A cross task in any
donor may move on both uniform and hetero hosts. A stale
cross task in the group park may move on hetero hosts.
Cross group picks in select plus enqueue count group skip.
Isolation follows enqueue placement plus thief park choice
with peer best effort across groups, with pinned single
entries kept by the mask. An idle CPU with no moved work
steals past unmovable leftovers, while a busy CPU with
moved work steals only when both queues are empty. An idle
kick is sent even with queued work to a CPU in the task
mask with no busy preemption. Park sends no kick with no
live allowed CPU after fallback, and the next dispatch
pass collects it.

## CPU choice

CPU choice prefers a free core idle CPU in the group and
mask, then any idle CPU in the group and mask, then the prior
CPU in the group when allowed, then the current CPU
in the group when allowed,
then the first allowed CPU in the group. Tier A prefers a
free core. Tier B prefers any idle in the group. Placement
only with no dispatch use. Singletons treat all idle as
free with prior order and no trap. Pinned tasks stay in
place. Tasks that cannot move stay on the current CPU.
Live frequency plus
CPU cards stay display only and never shape placement.
Max frequency plus capacity plus LLC plus siblings seed groups.
Idle
choice is rechecked in the mask and group. A final choice
without an allowed CPU in the group falls back to the group
park in enqueue with narrow opposite moved to match. Enqueue
reuses the selected CPU in the group when
allowed, then the first allowed CPU in the group, then the
group park.
Tasks that cannot move use the per-CPU queue. The path
uses only public helpers.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover inserts, requeues, completions,
park moves, steal moves, idle kicks, inserts without
state, EDF enqueued, EDF clamped, EDF ordered, group demote,
group promote plus wake promote, pinned inflate, and
group skip. Wake promote is the fast subset of promote
by 8 short blocks. Park moves
count dispatch moves from the group park. Steal moves count
dispatch moves from peer queues. Kicks count idle
wakeup kicks sent even with queued work. EDF
enqueued counts deadline inserts. EDF clamped counts sleeper
caps to one slice. EDF ordered counts kernel queue inserts
in order. Demote counts light to hog moves by burn. Promote
counts hog to light moves after low wins plus wake hits.
Pinned inflate counts
pinned hog deadlines with extra. Group skip counts cross group
picks skipped for isolation. Snapshot adds version plus
timestamp plus topology plus light depth plus hog depth
plus allowance for the page plus the JSON log with back
compat defaults.

## Measuring Wakeup Latency

To measure the wakeup latency the scheduler delivers
with cyclictest, pin the measurement threads to
dedicated CPUs with `-a`, use the monotonic clock
(`-c 0`), and the performance governor, and move the
device IRQs off the measured CPUs. For percentiles, run
schbench with two message threads (`-m 2`) on an otherwise
quiet machine. The harness probe wakes each 10ms and records
wake delay as a light baseline with no realtime use. For
4.2.9 compare light p95 from the probe plus schbench with
the same workload and no other change.

## Limitations

- Idle wakeup kick. Wakeups join in EDF order and kick an
  idle target even with queued work to collect at once.
  Park sends no kick with no live allowed CPU after
  fallback, and the next dispatch pass collects it.
- Queues stay per-CPU with two groups. Idle CPUs collect
  group park work and steal peer work with mask only with
  idle rescue for depth 1 when the thief is idle with no
  moved plus no own left plus no park left, else depth 2.
  Tier 0 models also donor asleep rescue. BPF ships thief
  idle only due to verifier jump at 1000001 on asleep
  check, with donor asleep handled by idle kick. Park
  trusts enqueue placement plus thief park choice with no
  task recheck due to verifier jump at 1000001 on donor
  check, so stale cross entries may move on hetero hosts
  with strict park on uniform hosts and best effort peer.
  Own plus park moves keep order with mask respect.
- Groups use a per CPU table when ready, else halves with
  extra to hog. Odd counts give the extra CPU to hog in
  both views. Short slices clamp with no pad. A single
  CPU keeps all light with no peer scan through the same
  path. Cores split with extra to hog with siblings kept
  in one group. One LLC splits globally. Two plus N LLCs
  split in each LLC. All singleton cores use halves plus
  interleave exactly. Uniform hosts keep ready cleared when
  the core view matches halves, else ready set. Hetero hosts
  keep ready set with core interleave by max capacity plus
  max frequency plus least id. Strict on uniform hosts. Best
  effort on hetero
  hosts. Dispatch uses halves. Placement uses live table.
  Placement prefers a free core idle plus any idle in the
  group with singletons as no-op. Snapshot mirrors the live
  table when ready, else halves
  with no trap.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- Unknown frequency stays unknown. Hosts that report
  zero show freq unknown on the dashboard and in the
  start log, with no effect on placement. Live frequency plus
  CPU cards stay display only and never shape
  placement. Max frequency plus capacity plus LLC plus
  siblings seed groups. Perf hints keep 1024 for light and hog as best
  effort with a weak guard at init plus running. One policy
  keeps both groups at max since groups use dedicated CPUs.
- Machines with one thread per core keep halves plus
  interleave exactly with preference as no-op and no trap.
  A single CPU
  host runs with no peer scan through the same path.
- Needs a kernel with sched_ext enabled.
