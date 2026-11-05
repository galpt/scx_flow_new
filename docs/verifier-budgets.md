# Verifier budgets

This note documents the verifier budgets as built in 5.0.9.
It is narrative only with no opcode, branch, map, struct, or helper change.

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
then cap at max with a monotonic last plus one floor. The overrun
penalty reuses the same fixed slice with the same saturation and no
knob. Slice never scales, preempt needs a gap of at least five hundred
thousand nanos past a tail of one hundred twenty five thousand nanos,
and the exiting slice stays at one thousand nanos.

Frequency hints are neutral for placement with bounded integer math only.
Sampling caps the raw ratio at full speed then blends three parts prior
plus one part fresh, and the band asks full speed at or above three
quarters, half speed at or below one quarter, else keeps the smoothed
value. Time uses monotonic nanos with zero plus missing plus reversed
guards that keep the prior level.

Stats offsets 0 through 13 stay frozen for compat with an append only tail
through 16, fallback equals pair full plus duplicate plus stale, and steal
equals pair plus LLC. Overrun plus penalty count full slice burns on the
enqueue LLC and blocked counts still runnable stops on the cached LLC.
The penalty adds one straight line branch with saturating adds and no new
loop, map, or program. The build carries 25 programs with 20 baseline plus
5 cgroup plus task init programs, all passing with no new program added
for documentation. Bytecode plus ELF differences from comment edits land
in comment plus line info only.
