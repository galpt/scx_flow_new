# Verifier budgets

This note documents the verifier budgets as built with pinned escape
plus hist cover. It is narrative only with no opcode, branch, map,
struct, or helper change beyond the appended tails.

All BPF loops are bounded. Dispatch pops retry at most four times per
queue, which covers a burst of stale plus exiting entries with one pop
plus one lookup per attempt. Pair walks stop at the configured pair count
within a hard cap of 32, LLC walks stop at the LLC count within a hard
cap of 64, and init walks stop at fixed CPU plus LLC bounds of 1024 plus
64 plus 8 nodes. No loop depends on input length.

Capacity is fixed with no knob. Per pair capacity is four times CPU count
with a floor of eight, which keeps about one KiB per pair on a 16 CPU
host with margin. The static area is eight pages created once before the
first pair use, and overflow takes a fresh block with no reuse. A single
LLC host creates no pair by design, so depth plus cap gauges stay zero
there. The weight map holds 4096 entries with no eviction, and a full map
misses to default with no stall.

Virtual time is saturated. Adding one fixed slice of one million nanos
caps at max on overflow with no wrap, and weight scaled charges split
used nanos into slice units plus rest so the multiply never overflows,
then cap at max with a monotonic last plus one floor on the pair path
only. The overrun penalty reuses the same fixed uniform slice with the
same saturation and no knob as implicit deadline throttling: base charge
scales by weight while the extra quantum stays fixed, so default doubles,
heavy multiplies a hundredfold to leave the head, and light already sits
behind on base charge. A scaled penalty would keep the heavy hog near the
head. The postponed vtime moves behind the pair sequence through the floor
and behind LLC order directly, steal reclaims idle time work conserving,
and saturated max keeps the vtime capped while the count still grows.
Pinned skips the penalty through one extra condition with no new branch
shape, exiting bypasses through early returns. Slice never scales, preempt
needs a gap of at least five hundred thousand nanos past a tail of one
hundred twenty five thousand nanos, and the exiting slice stays at one
thousand nanos. The transient zero remain on overrun refreshes at running
time from the kernel slice.

Frequency hints are neutral for placement with bounded integer math only.
Sampling caps the raw ratio at full speed then blends three parts prior
plus one part fresh, writes the raw sample into a four entry shift ring
with newest at zero for sizing, and the band asks full speed at or above
three quarters, half speed at or below one quarter, else keeps the smoothed
value. Time uses monotonic nanos with zero plus missing plus reversed
guards that keep the prior level. Smooth plus hint plus apply stay
identical with integer math and a bound of four.

Stats offsets 0 through 16 stay frozen for compat with an append only tail
through 19, fallback equals pair full plus duplicate plus stale, and steal
equals pair plus LLC. Overrun counts events and penalty counts slices one
to one by design on the enqueue LLC, blocked counts still runnable stops
with no penalty on the cached LLC with zero fallback, covering preemptions
plus slice expiry plus migrations. Escape counts streak preempts on the
enqueue LLC, orphan counts mask change kicks on the queued LLC, forward
counts head forwards on the dispatch LLC. Userspace folds all tails with
len guards so harness can correlate overrun growth with head movement
plus escape growth with hold ends.
The penalty adds one straight line condition with saturating adds and no new
loop, map, or program. Deferred with fallback is per task period plus
deadline with no ABI so period stays one slice, global admission with no
reject so dampening stands in, bandwidth plus PI inheritance with no lock
graph so non penalization plus forward plus victim wakes stand in, global
heap with no unbounded search so bounded hierarchy stands in, and timers
plus reclaim with no async path so enqueue postponement plus work conserving
steal stand in. The build carries 25 programs with 20 baseline plus
5 cgroup plus task init programs, all passing with no new program added
for documentation. Bytecode plus ELF differences from comment edits land
in comment plus line info only.
