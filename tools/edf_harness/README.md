# EDF harness

The harness measures periodic completion on the host.
It runs threads with start jitter plus period plus
execution plus priority class and counts completion
plus use plus switches with no scheduler change.

## Workload

Each thread draws start jitter uniform 0 to 1ms once,
then each job draws period uniform 120 to 320ms with
deadline equal to period and execution uniform 2 to
16ms plus priority class round robin 0 to 2. Priority
is recorded only with no scheduler use. Weight stays
1024 with no Pi use. Pi is deferred with no kill and
no Pi path. The scheduler never kills. The harness
cancels a job only by counting a miss when wall
completion passes release plus deadline. Grace in the
scheduler is 50us tiny past 120ms least period with
no kill. Batch window in the scheduler is 96us in a
64 to 128 window tiny past 500us floor with no fair
loss. The paper improved EDF is `iEDF`, this release
proposes `iEDF++` with `M1` same deadline batching, `M2`
overrun grace, `M3` fair overload shed, `M4` idle frontier
guard, all behind `FLOW_GATE_IEDF`. The map is
`M1=batch/M2=grace/M3=shed/M4=guard`.

Each job burns execution with a spin then sleeps to
the next release. A miss skips sleep and releases at
once. Duration is 60 seconds with 5 repeats per load
level. Use `QUICK=1` for a short smoke with 2 seconds
and 1 repeat at target 1.0 only.

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

# Custom duration plus repeats plus output dir
DURATION=10 REPEATS=3 OUTDIR=/tmp/edf_test bash tools/edf_harness/run.sh
```

## Outputs

Each run writes one CSV plus one JSON with the same
prefix. Each CSV plus JSON holds exact use alongside
offered use. The summary CSV merges all runs with target
plus repeat plus seed. The stats CSV holds one row per
target with count plus mean plus 95 CI for completion
plus offered use plus exact use plus effective use plus
switches.

Mean is sum over count. Sample spread uses divisor count
minus one. Half width is `1.96 times s over sqrt n` with
`s` sample spread and `n` repeat count with zero width
when count is one. Topology dump holds `nproc` plus
`lscpu` plus kernel plus governor in `topology.txt`.
Variance is the per target CI in the stats CSV.

Metrics use offered use equal to released execution
over wall over CPU count plus exact use equal to mean
per job execution over period times thread count over
CPU count plus completion equal to completed over
released plus effective use equal to completed execution
over wall over CPU count plus switches from voluntary
switches summed over threads. Exact use is mean per job
ratio times thread count over CPU count with no wall
sampling. Offered use matches exact use on average with
no extra sampling.

A value of 100 percent is a measured rate at feasible
use only with no guarantee. There is no gate on 98.5.
Report topology plus variance with each run. Use
`stress-ng` only as background load plus `cyclictest`
plus `schbench` as cross checks with no gate.

## Files

- `harness.c` periodic worker plus CSV plus JSON
- `run.sh` calibration plus sweep plus summary
- `README.md` this note
