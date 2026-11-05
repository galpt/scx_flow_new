# Lifecycle

This note documents the task and cgroup lifecycle as built in 5.0.9.
It is narrative only with no knob, map, struct, helper, or branch change.

Tasks are seeded at init_task with the birth cgroup id and a clamped
weight hint. The enqueue path reads the live weight map by id, so a plain
weight change lands on the next enqueue with no move needed, and a miss,
zero id, zero value, or full map reads as default with prior behavior kept.
The task cache stays a hint for move plus init and never serves alone.

Enqueue places by virtual time. A requeued task with a live generation
carries its remaining slice with a weight scaled charge, else a fresh
virtual time steps past the pair sequence with a scaled gap and a last
plus one floor with max saturation so the sequence stays unique. A non
pinned carry that burnt the full slice with no remain adds one extra
fixed uniform slice with saturation and counts overrun plus penalty one
to one on the enqueue LLC, so a task that always burns the full slice
cannot hold the head. The postponed vtime steps behind the pair sequence
through the floor and behind LLC order directly, while steal reclaims idle
time work conserving. Uniform is intentional: base charge scales by weight
while the extra quantum stays fixed, so heavy hogs pay a large relative
cost and light hogs already sit behind on base charge alone. Pinned
reaches the carry but skips the penalty and stays at the scaled charge
with prior behavior, exiting bypasses through early returns. Pinned
tasks wait in the allowed local queue only, exiting tasks use a minimal
slice on an allowed local queue with fallback to the LLC queue, and all
other tasks try the pair queue then spill to the LLC queue. The transient
zero remain on overrun refreshes at running time from the kernel slice.

Running records the per CPU snapshot, assigns the next generation, and
clears the queued flag. Stopping folds burnt nanos into the smoothed
frequency hint and counts a stop that leaves the task still runnable as
blocked on the cached LLC with no fresh lookup and no vtime penalty, so
blocking never shifts the deadline. Runnable covers preemptions plus slice
expiry plus migrations, and an invalid cached LLC falls back to zero with
no loss. Forward plus victim wakes keep progress when the head cannot run
on the thief, and hierarchical steal reclaims idle time as the bounded
push pull analogue. Tick refreshes the remaining slice. Dequeue clears the
queued flag. Exit records through the exit info helper. Single ownership
holds through the queued flag with duplicate requeues dropped and no loss.

Cgroup init seeds one weight entry and never aborts creation, exit drops
the entry so a reused id never reads stale, set weight updates or creates
with clamp, move caches the destination hint, and init_task seeds the
birth hint. All creation paths return zero on bad input so load plus task
plus cgroup creation never fails from shares.

Hotplug needs a restart. CPU, LLC, pair, and node tables are seeded once
at init with fixed bounds, so an offline or added CPU after start never
reshapes the tables. The same restart rule covers the pinned plus exiting
plus steal paths. Reinstall needs a restart from prior releases with no
live transition, following the installer fresh workspace plus allowlist
plus pinned ref checks.
