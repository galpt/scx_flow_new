# Lifecycle

Tasks are seeded at init_task with the birth cgroup id and a clamped
weight hint. The enqueue path reads the live weight map by id, so a
weight change lands on the next enqueue with no move needed, and a
miss, zero id, zero value, or full map reads as default. The task
cache stays a hint for move plus init and never serves alone.

Enqueue places by virtual time. A requeued task with a live
generation carries its remaining slice with a weight scaled charge,
else a fresh time steps past the per LLC floor with a scaled gap
and saturation so times stay unique. Stopping records a yield bit
into the three bit task history with fresh zero reading as a hog,
and enqueue reads two of three early yields as latency else a hog
with pinned plus exiting bypassing. A latency task takes the queue
key minus one fixed slice one shot with the stored time plus
deadline staying raw, so the shift never accumulates and the stamp
never moves it. A carry that burnt the full slice postpones by the
award length with saturation and counts overrun plus penalty, so a
task that always burns the full slice cannot hold the head. Pinned
reaches the carry but skips the penalty and stays at the scaled
charge, exiting bypasses through early returns. Pinned tasks wait
in the allowed local queue only, exiting tasks use a minimal slice
on an allowed local queue with fallback to the LLC queue, and all
other tasks join the LLC queue for their target. The transient zero
remain on overrun refreshes at running time from the kernel slice.

Running records the per CPU snapshot plus the latency flag from the
history with pinned always zero, assigns the next generation, and
clears the queued flag. A pinned start clears the hold since the
wait reached the CPU, while a start with an old enqueue steps the
hold down by one and counts a rescue on the running LLC. A tall
hold clamps to twice the streak bound. Stopping folds burnt nanos
into the smoothed frequency hint and counts a stop that leaves the
task still runnable as blocked on the cached LLC with no time
shift. A stop with no remain steps the hold by the pad award
capped at twice the streak bound, while a clean stop steps the
hold down one. The step runs on the stop edge only with one add
per run. An invalid cached LLC falls back to zero. The same stop
scores the burn on its CPU: a fresh CPU reads zero with one
quantum until the first count, a voluntary stop plus an empty wait
take decay first, and a burn accounts used against the pad award
length times one slice with saturation, so only a full awarded
burn with a top raw step grows while a partial burn decays with
separate growth plus decay counts. The same stop records the yield
bit for the next classify. Enqueue stamps the wait start with the
monotonic clock, and a zero clock reads as unknown with running
treating zero as no age out. The frequency ring keeps the last
four raw samples for post mortem sizing with no reader in BPF.

Pinned local wakes use the fast path that preempts past the tail
with no gap check plus a streak cover that turns an idle wake into
a preempt at the bound. The constrained kick compares shifted keys
on both sides and returns one on a preempt, so enqueue plus mask
callers count latency wins with the class in hand while forward
wakes keep the preempt count. Forward wakes keep progress when the
head cannot run on the thief, with a forward count for attempts
with a live allowed owner at pick on the dispatch LLC and no move,
no valid owner keeping coalescing with no forward count so a
future valid head retries. A mask change on a queued task keeps
the queue with no rewrite and wakes the owner through the pinned
fast path for pinned waits else the constrained path with an
orphan count only on a live allowed kick. A mask change wake for
a latency task uses the shifted key and counts a latency win on a
preempt with the class in hand. Tick keeps remain with no streak
step and refreshes the remaining slice. Dequeue clears the queued
flag. Exit records through the exit info helper. Single ownership
holds through the queued flag with duplicate requeues dropped and
no loss.

Cgroup init seeds one weight entry and never aborts creation, exit
drops the entry so a reused id never reads stale, set weight
updates or creates with clamp, move caches the destination hint,
and init_task seeds the birth hint. All creation paths return zero
on bad input so load plus task plus cgroup creation never fails
from shares.

Hotplug needs a restart. CPU, LLC, and node tables are seeded once
at init, so an offline or added CPU after start never reshapes the
tables. The same restart rule covers the pinned plus exiting
paths. Reinstall needs a restart from prior releases with no live
transition, following the installer fresh workspace plus allowlist
plus pinned ref checks.
