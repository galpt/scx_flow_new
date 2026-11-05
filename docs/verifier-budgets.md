# Verifier budgets

This note documents the verifier budgets as built. It is narrative
only with no code change.

All BPF loops are bounded. Dispatch walks LLC queues within a hard
cap of 64, init walks stop at fixed CPU plus LLC bounds of 1024
plus 64 plus 8 nodes, and the per LLC node seeding walk at init
nests LLC times CPU within the same bounds. No loop depends on
input length.

Capacity is fixed. The weight map holds 4096 entries with no
eviction, and a full map misses to default with no stall. Queues
are kernel dispatch queues with no per queue sizing in the
scheduler.

Virtual time is saturated. Adding one fixed slice of one million
nanos caps at max on overflow with no wrap, and weight scaled
charges split used nanos into slice units plus rest so the
multiply never overflows, then cap at max with a per LLC last
plus one floor. The overrun debt scales with the award: one
uniform slice at overrun plus extra uniform slices for a total of
q, each saturating at max, so a one quantum burn pays one slice
while a three quantum burn pays three slices. Base charge scales
by weight while extra stays uniform, so default about doubles at
q one and heavy still steps far behind at q three, with light
already behind on base charge. The postponed time moves behind
the floor, idle CPUs reclaim the wait, and saturated max keeps the
time capped while the count still grows. Pinned skips the penalty
plus the award and stays at the scaled charge with local FIFO
order, exiting bypasses through early returns. Slice runs one
slice times q with no weight scale on the extra part. Preempt
needs a gap of at least five hundred thousand nanos past a tail
of one hundred twenty five thousand nanos with both sides shifted
by one fixed slice of one million nanos for latency tasks, and
the exiting slice stays at one thousand nanos. The constrained
kick returns one on a preempt else zero, so enqueue plus mask
callers count latency wins with the class in hand. The transient
zero remain on overrun refreshes at running time from the kernel
slice, clamped at three quanta.

Frequency hints are neutral for placement with bounded integer
math only. Sampling caps the raw ratio at full speed then blends
three parts prior plus one part fresh, writes the raw sample into
a four entry shift ring with newest at zero for sizing with no
reader in BPF as post mortem shadow only and no placement use,
and the band asks full speed at or above three quarters, half
speed at or below one quarter, else keeps the smoothed value.
Time uses monotonic nanos with zero plus missing plus reversed
guards that keep the prior level.

Stats count twenty one counters in struct order at 168 bytes with
total meeting penalty plus extra per award and on deltas. Overrun
counts events and penalty counts slices one to one, extra counts
q minus one and total counts q there, blocked counts still
runnable stops with no penalty on the cached LLC, covering
preemptions plus slice expiry plus migrations. Escape counts
streak preempts on the enqueue LLC, orphan counts mask change
kicks with a live allowed owner on the queued LLC, forward counts
head forwards with a live allowed owner at pick on the dispatch
LLC. Boost counts latency takes plus hog keeps on the enqueue
LLC, latency preempt counts wins with the class in hand on the
enqueue plus queued LLCs, and rescue counts old waits that step
the hold down on the running LLC. The history classifier uses bit
math only with no loop and no map use, and the shift takes one
fixed slice with zero saturation one shot with no accumulation.
Score stays per CPU with no cross average while the hold travels
in the task pad, pinned keeps one slice with no award even on a
stale pad, a fresh CPU reads zero with one quantum until the
first count, invalid CPU keeps the same fresh zero default.
Growth needs a full awarded burn with a top raw step against the
q scaled denom so a partial burn still decays. Streak steps by
the award on the stop edge only with one add per run at twice the
streak bound with clean decay, the tick keeps remain with no
step, with debt scaled to q. Userspace folds all tails with len
guards at 152 plus 160 plus 168 bytes.

The build carries 17 programs with 16 flow plus 1 probe, all
passing with stacks at or below five hundred twelve bytes.
Bytecode plus ELF differences from comment edits land in comment
plus line info only.
