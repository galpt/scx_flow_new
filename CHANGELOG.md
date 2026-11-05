# Changelog

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
