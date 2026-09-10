# EDF harness

The harness measures periodic completion on the host.
It runs workers with start jitter plus period plus
execution and one probe with 10ms
wakes and counts completion plus use plus switches plus
probe delay with no scheduler change. All threads run
with the default policy with no realtime use. The binary
is built on each run with no checked in binary.

## Workload

Each worker draws start jitter uniform 0 to 1ms once,
then each job draws period uniform 120 to 320ms with
deadline equal to period and execution uniform 2 to
16ms with no scheduler use. Weight stays
1024. The scheduler never kills. The harness
counts a miss when wall completion passes release plus
deadline. The slice in the scheduler is fixed at 1ms
with no knob. The probe wakes each 10ms and
records wake delay as a light baseline with no realtime
use. The control flag marks baseline runs for A and B
comparison with no scheduler change in the harness.

Each job burns execution with a spin then sleeps to
the next release. A miss skips sleep and releases at
once. Duration is 60 seconds with 5 repeats per load
level. Use `QUICK=1` for a short smoke with 2 seconds
and 1 repeat at target 1.0 only. Use `CONTROL=1` to mark
runs as control for baseline comparison.

## Calibration

Average burst 9ms over average period 220ms gives per
thread use near 0.0409. Thread count follows target
use times CPU count over per thread use. On 16 CPUs
the counts are near 196 for 0.5 plus 293 for 0.75 plus
372 for 0.95 plus 391 for 1.0 plus 469 for 1.2 plus
587 for 1.5. The script reads host CPUs with `nproc`
so other hosts scale the same way.

```bash
# Short smoke, 2 seconds and 1 repeat
QUICK=1 OUTDIR=/tmp/edf_quick bash tools/edf_harness/run.sh

# Full sweep, 60 seconds and 5 repeats per level
bash tools/edf_harness/run.sh

# Control baseline for A and B comparison
CONTROL=1 OUTDIR=/tmp/edf_control bash tools/edf_harness/run.sh

# Custom duration plus repeats plus output dir
DURATION=10 REPEATS=3 OUTDIR=/tmp/edf_test bash tools/edf_harness/run.sh
```

## Outputs

Each run writes one CSV plus one JSON with the same
prefix. Each CSV plus JSON holds exact use alongside
offered use plus probe delay plus control plus scheduler
state. The summary CSV merges all runs with target
plus repeat plus seed. The stats CSV holds one row per
target with count plus mean plus 95 CI for completion
plus offered use plus exact use plus effective use plus
switches plus probe delay.

Mean is sum over count. Sample spread uses divisor count
minus one. Half width is `1.96 times s over sqrt n` with
`s` sample spread and `n` repeat count with zero width
when count is one. Topology dump holds `nproc` plus
`lscpu` plus kernel plus governor plus scheduler plus
control in `topology.txt`. Variance is the per target CI
in the stats CSV.

Metrics use offered use equal to released execution
over wall over CPU count plus exact use equal to mean
per job execution over period times thread count over
CPU count plus completion equal to completed over
released plus effective use equal to completed execution
over wall over CPU count plus switches from voluntary
switches summed over threads plus probe average and max
delay in microseconds from the 10ms probe. Exact use is
mean per job ratio times thread count over CPU count with
no wall sampling. Offered use matches exact use on average
with no extra sampling.

A value of 100 percent is a measured rate at feasible
use only with no guarantee. There is no threshold on 98.5.
Report topology plus variance with each run. Use
`stress-ng` only as background load plus `cyclictest`
plus `schbench` as cross checks with no threshold.

## Results (4.2.4 vs 4.2.5)

Comparison of `4.2.4` against `4.2.5` with the
same workload plus the same host CPUs plus the same
governor. Light protocol uses `DURATION=15` plus
`REPEATS=2` on 16 CPUs with governor `performance`
and seeds `1` plus `2` where repeat equals seed plus `n=2`.
Each row holds one target use with repeat count plus
means plus build plus seeds. Topology plus variance
ship with each run in `topology.txt` plus the stats
CSV.

| target_u | n | mean_completion ± ci95 | mean_exact | mean_effective | governor | build | seeds |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0.5 | 2 | 1.0000 ± 0.0000 | 0.5425 | 0.4957 | performance | 4.2.4 | 1,2 |
| 0.75 | 2 | 1.0000 ± 0.0000 | 0.8095 | 0.7412 | performance | 4.2.4 | 1,2 |
| 0.95 | 2 | 1.0000 ± 0.0000 | 1.0279 | 0.9337 | performance | 4.2.4 | 1,2 |
| 1.0 | 2 | 0.9661 ± 0.0202 | 1.0804 | 0.9364 | performance | 4.2.4 | 1,2 |
| 1.2 | 2 | 0.6584 ± 0.0056 | 1.2989 | 0.6426 | performance | 4.2.4 | 1,2 |
| 1.5 | 2 | 0.5532 ± 0.0000 | 1.6222 | 0.5402 | performance | 4.2.4 | 1,2 |
| 0.5 | 2 | 1.0000 ± 0.0000 | 0.5425 | 0.4941 | performance | 4.2.5 | 1,2 |
| 0.75 | 2 | 1.0000 ± 0.0000 | 0.8094 | 0.7382 | performance | 4.2.5 | 1,2 |
| 0.95 | 2 | 1.0000 ± 0.0000 | 1.0281 | 0.9357 | performance | 4.2.5 | 1,2 |
| 1.0 | 2 | 0.9782 ± 0.0081 | 1.0804 | 0.9493 | performance | 4.2.5 | 1,2 |
| 1.2 | 2 | 0.6571 ± 0.0030 | 1.2985 | 0.6400 | performance | 4.2.5 | 1,2 |
| 1.5 | 2 | 0.5482 ± 0.0013 | 1.6228 | 0.5327 | performance | 4.2.5 | 1,2 |

At target use at or below 0.95 both builds complete
all jobs with a measured rate of 100 percent. At 1.0
the means are 0.9661 plus 0.9782 with overlapping
intervals so the gap is noise at `n=2`. Overload
falls the same way in both builds to near 0.66 at
1.2 plus near 0.55 at 1.5. Switches stay comparable
across targets on 16 CPUs with governor
`performance`. Build `4.2.5` is a non regression
plus reads neutral against build `4.2.4`. No `4.2.7`
measurement exists yet. Build `4.2.7` keeps the same
workload plus a 10ms probe plus control plus scheduler
state ready for A and B comparison.

A value of 100 percent is a measured rate at feasible
use only with no guarantee. There is no threshold on 98.5.

## Files

- `harness.c` periodic worker plus probe plus CSV plus JSON
- `run.sh` calibration plus sweep plus summary plus control
- `README.md` this note
