# Changelog

## 5.0.16

WS-only accounting with fresh zero plus q scaled burn plus one add per epoch.

Culprit is a burn score that reads fresh tasks at middle with q two on
no evidence while the burn denom stays at one base slice under extended
awards, plus a hold that steps once per stop and once per tick so a burn
that ticks at zero remain then stops counts twice. A fresh task holds an
unearned extra quantum, a partial extended burn self limits by luck of
the clamp rather than by award fraction, and the hold escapes late or
double counts at the edge. The fix reads fresh score zero with q one
until the first count, amending the locked fresh fifty q two rule since
no burn has been seen yet, scales the burn denom with the pad award q in
one through three else one with saturation so growth needs a full
awarded burn with raw top while a partial burn still decays, steps the
hold by the award q on the stop edge only with one add per epoch capped
at twice the pop retry bound while the tick keeps remain with no step,
keeps voluntary plus empty wait precedence through decay with separate
growth plus decay counts, and wires harness missed counts plus a strict
one hundred twenty second full burn plus probe mode with at least three
repeats each for probe plus control plus a y_join template with share
open until the per award log lands. Task state keeps seventy two bytes
with pad carrying q plus hold, per CPU rows keep score plus shadow plus
separate growth plus decay counts, counters stay at twenty four extra
award plus twenty five total quanta for two hundred eight bytes with
zero through twenty three frozen, fallback equals four plus five plus
six, steal equals nine plus ten, total equals fifteen plus twenty four.
Knob free with saturation and no wrap, append only stats, pinned FIFO
with bypass, frozen order, restart only for hotplug plus reinstall.
Slice runs one slice times q with no weight scale on extra and no order
shift, steal preserves slice length, escape still fires at the pop retry
bound. TrackB ringbuf stays deferred on verifier budget with no new map
or program, so Y stays open on deltas only with books checkable.

Version syncs Cargo plus installer plus guard to 5.0.16 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.15 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is workspace only with no live mutation, no force, no
reboot, and no push: live load stays untouched with the scheduler state
disabled. Guard plus fmt plus clippy plus build plus test plus smoke
plus veristat twenty six of twenty six pass with stack max one hundred
sixty at or below five hundred twelve bytes, dispatch insn unchanged at
fourteen thousand two hundred forty eight with enqueue slightly down at
seventeen thousand nine hundred fifty seven. Rollback stays append only.

Correction against fresh workspace evidence at
/tmp/opencode/ws-slices/veristat-fresh.csv with verbose at
/tmp/opencode/ws-slices/veristat-fresh-verbose.txt, twenty six of twenty
six pass: global stack max is two hundred twenty four on flow enqueue
with flow dispatch plus flow init at one hundred sixty and flow stopping
at forty eight, all at or below five hundred twelve bytes; dispatch
holds at fourteen thousand two hundred forty eight insn with enqueue at
eighteen thousand sixty insn. The one hundred sixty figure above scopes
to dispatch plus init only, and the seventeen thousand nine hundred fifty
seven figure is superseded by the fresh eighteen thousand sixty measure.
Design five point zero point sixteen locks only twenty six of twenty six
plus five hundred twelve bytes, so code versus design stays pass with no
code change from this narrative correction.

Base is archive/5.0.15 at 12129f383738bb1a75da392cab5f152e75dd93e6 with
no other tree change.

## 5.0.15

Bounded extra quanta with hysteresis plus scaled debt and single source hold.

Culprit is a shared queue where a full burn hog holds the head while the
debt stays at one slice for up to three slices of run, the hold mixes per
CPU score with per task sticky, and the running clamp drops long slices.
The fix awards one base plus zero through two extra quanta from a per CPU
burn score with top engage plus sticky hold plus middle bands, scales the
overrun debt to q with saturating adds so a three quantum burn pays three
slices, single sources the hold in the task pad with score staying per CPU
and slice length preserved across dispatch with a pinned guard, clamps
running at three quanta with no drop, wires band locks at compile time
with raw max use, keeps extra tails add only with total equals penalty
plus extra, fixes harness percentile rank plus calloc cleanup, syncs the
core offset banner, and documents queued plus no context plus exit dump
plus pre init plus shadow ring plus cross CPU races as accepted with live
soak plus share log plus WS perf deferred open with no live run here.

Task state keeps seventy two bytes with pad carrying q plus hold, per CPU
rows keep score plus hold shadow plus separate growth plus decay counts,
counters append twenty four extra award plus twenty five total quanta for
two hundred eight bytes with zero through twenty three frozen, fallback
equals four plus five plus six, steal equals nine plus ten, total equals
fifteen plus twenty four. Knob free with saturation and no wrap, append
only stats, pinned FIFO with bypass, frozen order, restart only for
hotplug plus reinstall. Fallback keeps raw keys with no boost if the
verifier regresses. Slice runs one slice times q with no weight scale on
extra and no order shift.

Version syncs Cargo plus installer plus guard to 5.0.15 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.14 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat twenty six of twenty six pass with stack at or
below five hundred twelve bytes and hot path growth accepted as a feature
waiver with WS perf still owed. Rollback stays append only.

Base is archive/5.0.14 at f0543c160 with no other tree change.

## 5.0.14

Latency boost with three bit history plus one slice offset and four tail counters.

Culprit is a shared queue where batch burns keep the head while short
sleeps wait behind large virtual time with no record of past yields. A
task that sleeps early looks the same as a task that burns the full
slice, so interactive wakes queue behind hogs with no offset and no
count, and the preempt gap test compares raw times where a one slice
lead never fires. The fix keeps a three bit shift history per task that
records a yield bit at stop with fresh tasks starting neutral as hogs,
classifies a task as latency sensitive when at least two of three bits
show early yields else holds it as a hog, subtracts one fixed slice from
the queue key for latency tasks only with one shot and no accumulation
while the stored virtual time plus deadline keep the raw value, compares
boosted keys on both sides of the preempt test with frozen gap plus tail
so latency wins ties by one slice while hog versus hog keeps the old
rule plus streak escape unchanged, and counts latency boosts plus hog
holds plus latency preempts plus age rescues on the tail with zero
through nineteen frozen. Pinned plus exiting bypass the classifier with
prior behavior. The enqueue stamp never shifts with the offset and
forward coalescing keeps pid plus virtual time plus owner with one kick
per enqueue capped at twice the pop retry bound.

Task state reuses the pad for the history byte for seventy two bytes
with no size change. Running state reuses the reserved byte for the
latency flag for forty eight bytes with no size change. Counters add
latency boost plus hog hold plus latency preempt plus age rescue at
twenty plus twenty one plus twenty two plus twenty three for one hundred
ninety two bytes with zero through nineteen frozen. Docs for zero
through nineteen stay frozen with the new tail append only. No new map
with bounds at one thousand twenty four plus sixty four plus eight plus
thirty two plus four thousand ninety six. Cgroup plus frequency plus
steal plus maps plus main stay frozen with strict priority lowest boosted
virtual time strand A, fixed slice of one millisecond, retry of four,
and imbalance of three. Userspace folds the new tails with serde defaults
plus length guards at one sixty eight plus one seventy six plus one
eighty four plus one ninety two plus interval deltas and regenerates
bindings only.

Knob free with no new tunable, verifier fail closed on guards versus fail
open on weights with saturation and no wrap, append only stats, pinned
FIFO with bypass, frozen order, and restart only for hotplug plus
reinstall. Fallback keeps raw keys with no boost if the verifier
regresses. Slice, scale, weight, order, local drain, exiting minimal,
and arena touch stay frozen with clean room code and plain prose
comments.

Enqueue keeps one target for inserts plus boosted keys for latency tasks
plus raw keys for hogs plus pinned plus exiting bypass. Preempt keeps the
frozen threshold plus tail with boosted both sides plus latency preempt
counts. Dispatch keeps pair then LLC then fallback drain with bounded
retries and no loss plus forward keys boosted both sides. Stats keep
offsets zero through nineteen frozen with tail twenty latency boost plus
twenty one hog hold plus twenty two latency preempt plus twenty three age
rescue append only, fallback equals four plus five plus six, steal equals
nine plus ten, and gauges use set only. Boost charges no queue and the
enqueue stamp never shifts virtual time. Userspace folds all tails with
length guards plus compat defaults and interval deltas as counters, so
harness can correlate boost growth with latency placement plus preempt
growth with hog displacement plus rescue growth with old wait decay.
Slice, scale, weight, order, local drain, exiting minimal, and arena
touch stay frozen with clean room code and plain prose comments.

Version syncs Cargo plus installer plus guard to 5.0.14 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.13 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat twenty six of twenty six pass with stack at or
below five hundred twelve bytes and insn within two percent. Rollback
stays append only.

Base is archive/5.0.13 at b2300bcc6 with no other tree change.

## 5.0.13

Pinned hold escape with streak plus orphan plus forward visibility.

Culprit is a local hold on a single LLC host under full burn plus a mask
move with no constrained wake. Sixteen burn threads hold every CPU at
large virtual time while a pinned wait on CPU zero with zero virtual time
waits in the local queue through a mask move, and the owner keeps burning
with tail idle wakes that never preempt. The watchdog reports a runnable
stall past twenty three seconds on CPU zero with the pinned task queued
and the holder running, and the forward plus mask paths leave no count.
The fix keeps a pinned fast path that preempts past the tail with no gap
check since a pinned wait cannot run elsewhere, turns an idle wake into a
preempt when the streak reaches the pop retry bound of four with an escape
count, stamps the enqueue time with the monotonic clock with no virtual
time shift, keeps the penalty on non pinned carry with no remain only,
keeps pair spill plus occupancy plus queued guard identical, keeps the
queued mask path on the queue with no rewrite through the constrained
wake plus an orphan count, decays the hold on an old wait and clears it
on a pinned start, steps the hold with saturation on full burns at stop
plus tick, keeps blocked plus frequency behavior, writes the raw sample
into a four entry shift ring with the smooth plus hint plus apply
identical, and counts head forwards on the dispatch LLC with order frozen.

Task state adds enqueue time at the tail for seventy two bytes. Running
state adds hold streak plus reserved for forty eight bytes. Frequency
state adds four raw samples for forty eight bytes. Counters add escape
plus orphan plus forward at seventeen plus eighteen plus nineteen for one
hundred sixty bytes with zero through sixteen frozen. Docs for zero
through sixteen stay frozen with the new tail append only. No new map
with bounds at one thousand twenty four plus sixty four plus eight plus
thirty two plus four thousand ninety six. Guards plus virtual time plus
cgroup plus steal plus main stay frozen with strict priority lowest
virtual time strand A, fixed slice of one millisecond, retry of four,
and imbalance of three. Userspace folds the new tails with serde defaults
plus length guards plus interval deltas and regenerates bindings only.

Knob free with no new tunable, verifier fail closed on guards versus fail
open on weights with saturation and no wrap, append only stats, pinned
FIFO with penalty skip, frozen order, and restart only for hotplug plus
reinstall. Fallback keeps kick plus escalation with no hist if the
verifier regresses. Slice, scale, weight, order, local drain, exiting
minimal, and arena touch stay frozen with clean room code and plain prose
comments.

Guards keep first allowed plus constrained target failing closed with no
move. Enqueue keeps one target for inserts plus pinned fast path on the
local queue plus constrained elsewhere. Dispatch keeps pair then LLC then
fallback drain with bounded retries and no loss plus forward counts.
Stats keep offsets zero through sixteen frozen with tail seventeen escape
plus eighteen orphan plus nineteen forward append only, fallback equals
four plus five plus six, steal equals nine plus ten, and gauges use set
only. Escape charges the enqueue LLC, orphan uses the queued LLC, forward
uses the dispatch LLC, and the enqueue stamp never shifts virtual time.
Userspace folds all tails with length guards plus compat defaults and
interval deltas as counters, so harness can correlate escape growth with
hold ends plus orphan growth with mask moves plus forward growth with head
blocks. Slice, scale, weight, order, local drain, exiting minimal, and
arena touch stay frozen with clean room code and plain prose comments.

Version syncs Cargo plus installer plus guard to 5.0.13 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.12 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat twenty six of twenty six pass with stack at or
below five hundred twelve bytes and insn within two percent. Rollback
stays append only.

Base is archive/5.0.12 at 79ab39f90 with no other tree change.

## 5.0.12

Overrun hardening with one extra slice plus blocked visibility.

Culprit is a carry that keeps the head when it always burns the full
slice, plus no count for stops that leave the task still runnable. A
task with no remain requeues at the charged time and can hold the head
across consecutive burns, and a stop with runnable true waits elsewhere
with no attribution. The fix adds one extra fixed uniform slice with
saturation on a non pinned carry with no remain, so a full burn pays one
more quantum with no wrap and no knob, and counts overrun plus penalty
one to one on the enqueue LLC as event versus cost. The postponed vtime
moves the hog behind the head: the pair floor steps it past the sequence
and LLC order uses the larger vtime directly, while the steal walk keeps
reclaiming idle time work conserving. Uniform is intentional with no
scaled variant: the base charge already scales by weight, so default pays
one slice, heavy pays a hundredth and light pays a hundred, and one
uniform extra slice doubles default, multiplies heavy a hundredfold to
break its hold, and adds one percent to light that already sits behind.
A scaled penalty would keep the heavy hog near the head and preserve the
domino. Saturated at max the vtime stays capped while the count still
grows for visibility. The monotonic last plus one floor stays after the
penalty on the pair path only so the pair sequence stays unique. A stop
that leaves the task still runnable counts blocked on the cached LLC with
no fresh lookup and no vtime penalty, covering preemptions plus slice
expiry plus migrations, with invalid cache falling back to zero. Pinned
reaches the carry but skips the penalty and stays at the scaled charge
with prior behavior and local FIFO placement so its vtime never orders
shared queues, exiting bypasses through early returns and stays byte
identical. Pair mode stays strict priority and picks the lowest vtime
with ties to strand A. Saturated vtime, fail closed guards versus fail
open weights, single ownership through the queued flag, frozen steal
order, and append only stats stay unchanged.

Real subset versus deferred under knob free plus verifier plus priority
only bounds. Landed here is implicit deadline throttling through uniform
postponement plus floor, blocked non penalization with forward plus victim
wakes as progress, hierarchical steal as reclaim plus push pull analogue,
and folded tail counters for harness proof. Deferred with fallback is per
task period plus deadline inputs with no ABI so period stays one slice,
global admission with no reject so dampening stands in, bandwidth plus PI
inheritance with no lock graph so non penalization plus wakes stand in,
global heap with no unbounded search so bounded hierarchy stands in, and
timers plus GRUB reclaim with no async path so enqueue time postponement
plus work conserving steal stand in.

Guards keep first allowed plus constrained target failing closed with no
move. Enqueue keeps one target for inserts plus kicks. Dispatch keeps
pair then LLC then fallback drain with bounded retries and no loss.
Stats keep offsets 0 through 13 frozen with tail 14 overrun plus 15
domino penalty one to one plus 16 blocked append only, fallback equals
4 plus 5 plus 6, steal equals 9 plus 10, and gauges use set only.
Overrun plus penalty charge the enqueue LLC while blocked uses the cached
LLC with zero fallback, and the transient zero remain refreshes at running
time. Userspace folds all three tails with len guards plus compat defaults
and interval deltas as counters, so harness can correlate overrun growth
with head movement. Slice, scale, weight, order, local drain, exiting minimal, and
arena touch stay frozen with clean room code and plain prose comments.

Version syncs Cargo plus installer plus guard to 5.0.12 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.11 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat pass. Rollback stays append only.

Base is archive/5.0.11 at 08c67194 with no other tree change.

## 5.0.11

Pinned affinity stall true fix with constrained wakes plus head repair.

Culprit is a stale wake split plus a blocked shared head. A wake that
kicks the enqueue hint while the task waits on another allowed CPU never
wakes the owner, and a shared queue whose head cannot run on the thief
never wakes the owner either. Both leave an allowed task queued while
the owner stays idle. The fix keeps one constrained target for inserts
plus kicks, forwards one idle wake per blocked head with no move no loss,
wakes the victim owner on a steal bounce, sanitizes the select hint plus
result to never leave the mask, and reclamps the cached queue affinity
when the mask changes with no fresh virtual time.

Guards add first allowed plus constrained target failing closed to minus
one with no move. Enqueue computes one target and uses it for the pinned
local insert plus the shared fallback kick. Preempt adds a constrained
kick that preempts when eligible else wakes idle and skips only on minus
one or disallowed, keeping both wrappers. Dispatch adds a forward kick
that wakes the head owner once per queue on a disallowed head with no
move no loss, covering own plus remote plus fallback queues. Steal wakes
the victim owner on a disallowed bounce with no counter move and no loss.
Select sanitizes the previous CPU before the shared pick and the result
after so neither leaves the mask. Set cpumask reclamps the cached LLC
plus strand, preserves virtual time plus deadline plus generation plus
queued state with no fresh assign, and keeps the minimal slice for
exiting. Main wires the new hook with flags plus timeout plus name
frozen. Stats reuse idle plus skip with no new counter and no bound
change. Slice, scale, weight, order, local drain, exiting minimal, and
arena touch stay frozen with clean room code and plain prose comments.

Hypotheses close as H-A stale no kick primary fixed by the constrained
target plus kick, H-D head blocked companion fixed by forward plus victim
kicks, H-B orphan hook fixed by the additive mask hook with enqueue plus
dispatch as fallback when the hook never fires, H-C duplicate audit kept
as counted drop with no loss and no fix. Gates Q1 plus Q2 plus Q3 plus Q5
attach evidence with the disposition stated here.

Version syncs Cargo plus installer plus guard to 5.0.11 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.
Rollback retains the prior 5.0.10 snapshot append only. The exit dump
length flag stays optional with default zero preserving dump size.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat 26 of 26 pass. Rollback stays append only.

Base is archive/5.0.10 at 09852d2a with no other tree change.

## 5.0.10

Docs plus gates release with no scheduler logic change.

Top README appends lifecycle, hotplug, virtual time budgets, reinstall
safety, kernel 7.2 versus 6.12, and Cargo lock stale notes with the
scheduler README kept byte identical. Docs add lifecycle plus verifier
budgets as additive narrative with no knob, map, struct, helper, or
branch change.

Flow headers keep banner plus rationale comments only across 11 headers
plus main plus intf plus build. Bytecode plus ELF deltas stay in comment
plus line info only with no opcode, branch, map, struct, or helper change.

Guard adds scaffold only asserts for docs, top README notes, flow plus
core banners, scheduler README sha plus lines, harness presence, and the
changelog entry while keeping deleted mirror plus property harness
refuses. CI pins a Guard step before format with no new jobs, keeping
fmt plus clippy plus build plus test plus smoke plus veristat order.

Version syncs Cargo plus installer plus guard to 5.0.10 with the fork ref
b0efa3f614c0187df4cb3202d7b514d401f77d2a plus fork galpt/scx frozen. The
overlay Cargo lock stays stale by design and syncs through cargo update
minus p scx_flow before any locked build. The installer still requires
6.12 plus for cgroup hooks while 7.2 plus stays the subsystem
recommendation. Reinstall needs a restart with no live transition.

Verification is build plus verify only with no live mutation, no force,
no reboot, and no push. Guard plus fmt plus clippy plus build plus test
plus smoke plus veristat 25 of 25 plus QUICK harness smoke pass. Rollback
stays append only to the prior live 5.0.9 snapshot.

Base is archive/5.0.9 at 0a44075 with top README 55, scheduler README 17,
harness README 162, flow 11 headers, main 73, intf 175, build 50.
