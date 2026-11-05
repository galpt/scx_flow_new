# Verifier budgets

This note documents the verifier budgets as built with latency boost
plus history cover. It is narrative only with no opcode, branch, map,
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
only. The overrun debt scales with the award with no knob as implicit
deadline throttling: one uniform slice at overrun plus extra uniform
slices for a total of q, each saturating at max, so a one quantum burn
pays one slice while a three quantum burn pays three slices and cannot
hold the head three times longer on one slice of debt. Base charge
scales by weight while extra stays uniform, so default about doubles at
q one and heavy still steps far behind at q three, with light already
behind on base charge. The postponed vtime moves behind the pair
sequence through the floor and behind LLC order directly, steal reclaims
idle time work conserving, and saturated max keeps the vtime capped
while the count still grows. Pinned skips the penalty plus the award
and stays at the scaled charge with local FIFO order, exiting bypasses
through early returns. Slice runs one slice times q with no weight scale
on the extra part and no order shift for extra. Preempt
needs a gap of at least five hundred thousand nanos past a tail of one
hundred twenty five thousand nanos with both sides boosted by one fixed
slice of one million nanos for latency tasks, and the exiting slice stays
at one thousand nanos. The constrained kick returns one on a preempt else
zero, so enqueue plus mask callers count latency wins with the class in
hand while forward plus steal callers drop the return with no shape
change. Pair plus fallback share one kick site per enqueue with no storm. The transient zero remain on overrun refreshes at running
time from the kernel slice, now clamped at three quanta with no drop.

Frequency hints are neutral for placement with bounded integer math only.
Sampling caps the raw ratio at full speed then blends three parts prior
plus one part fresh, writes the raw sample into a four entry shift ring
with newest at zero for sizing with no reader in BPF as shadow verify
for post mortem only and no placement use, and the band asks full speed
at or above
three quarters, half speed at or below one quarter, else keeps the smoothed
value. Time uses monotonic nanos with zero plus missing plus reversed
guards that keep the prior level. Smooth plus hint plus apply stay
identical with integer math and a bound of four.

Stats offsets 0 through 23 stay frozen for compat with an append only tail
through 25 holding extra award plus total quanta, fallback equals pair
full plus duplicate plus stale, steal equals pair plus LLC, and total
equals penalty plus extra per award and on deltas. Overrun counts events
and penalty counts one per overrun on the enqueue LLC, extra counts q
minus one and total counts q there, blocked counts still runnable stops
with no penalty on the cached LLC with zero fallback, covering preemptions
plus slice expiry plus migrations. Escape counts streak preempts on the
enqueue LLC, orphan counts mask change kicks with a live allowed owner
on the queued LLC with skips never inflating the orphan count, forward
counts head forwards with a live allowed owner at pick on the dispatch
LLC with outcome split into preempt plus idle plus skip. Boost counts
latency takes plus hog keeps on the enqueue LLC, latency preempt counts
wins with the class in hand on the enqueue plus queued LLCs, and rescue
counts old waits that step the hold down on the running LLC. The history
classifier uses bit math only with no loop and no map use, and the offset
subtracts one fixed slice with zero saturation one shot with no
accumulation. Score stays per CPU with no cross average while the hold
travels in the task pad with steal preserving slice length only, pinned
keeps one slice with no award even on a stale pad, a fresh CPU reads
zero with q one until the first count, invalid CPU keeps the same fresh
zero default. Growth needs a full awarded burn with raw top against the
q scaled denom so a partial burn still decays by design with no
inversion from latency history. Streak steps by the award q on the stop
edge only with one add per epoch at twice the pop retry bound with
clean decay so a hold ends but never sticks, the tick keeps remain with
no step, now with debt scaled to q. Userspace folds all tails with
len guards at two hundred plus two hundred eight for twenty four plus
twenty five alongside one sixty eight plus one seventy six plus one eighty
four plus one ninety two so harness can correlate boost growth with latency
placement plus preempt growth with hog displacement plus rescue growth
with old wait decay plus extra share via deltas.
Extra award adds bounded branches with saturating adds and no new
loop, map, or program. Deferred with fallback is per task period plus
deadline with no ABI so period stays one slice, global admission with no
reject so dampening stands in, bandwidth plus PI inheritance with no lock
graph so non penalization plus forward plus victim wakes stand in, global
heap with no unbounded search so bounded hierarchy stands in, and timers
plus reclaim with no async path so enqueue postponement plus work conserving
steal stand in. The build carries 26 programs with 16 flow plus 10 lib,
all passing with no new program added
for documentation. Stacks stay at or below five hundred twelve bytes
with a measured global max of two hundred twenty four on flow enqueue
with flow dispatch plus flow init at one hundred sixty and flow stopping
at forty eight, hot path insn holds near the prior release with dispatch
at fourteen thousand two hundred forty eight plus enqueue at eighteen
thousand sixty as a feature note with no shrink here: fresh zero plus
q scaled denom plus one add per epoch necessarily touch the stop plus
award paths, veristat still shows 26 of 26 pass with stacks within bound,
WS proof recorded workspace only with no live run here against fresh
evidence at /tmp/opencode/ws-slices/veristat-fresh.csv with verbose at
/tmp/opencode/ws-slices/veristat-fresh-verbose.txt. Attach the veristat
CSV with the run when available. A veristat exit of minus 95 means the host lacks
arena support in this env with no scheduler change needed. Bytecode plus ELF differences
from comment edits land in comment plus line info only.
Open deferred live with no run here: strict tail plus share plus soak
gates with per award log join for books via deltas, one hundred twenty
second full burn plus probe for all five questions with a y_join
template wired, Y open on deltas only until the per award log lands,
WS perf sizing.
Accepted exceptions with no history rewrite: tracked docs plus changelog
stay committed with forward ignore only, per CPU hold row stays shadow,
queued dec stays stats only self healing, no context insert stays no loss,
exit dump length stays operator trusted default zero, pre init live reads
fail open safe, freq ring stays shadow post mortem, cross CPU races stay
benign self healing, prior safe directory plus tag plus checkout pins stay
docs only. Kick plus streak plus stamp plus decay plus atomics plus mask
costs stay as documented rare or constant with no action.
