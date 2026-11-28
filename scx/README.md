# scx_flow

## What

scx_flow is a knob-free latency score scheduler on sched_ext. Each LLC owns one kernel virtual deadline DSQ for shared tasks and each CPU owns one for pinned tasks, plus one fallback FIFO DSQ. Wakeups inherit scores between wakers and workers with log scale runtime compression, and long bursts cost more virtual time. Placement claims idle cores atomically (largest L3 for urgent tasks > core group > LLC > node) with direct local dispatch on won idle CPUs and in place slice continuation. Slices are bounded and track a ten millisecond window with boost for long frame runs, and urgent tasks shorten a peer's slice without an IPI. Active cores run at maximum frequency and idle cores decay to half on a timer.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Built-in Modes

Started without a flag, scx_flow runs its default logic, which suits most machines. Each mode below is turned on with its flag, and only one mode can be used at a time.

### `--helicoprion`

This mode was made for the [helicoprion](https://github.com/Seafoam-Labs/helicoprion) benchmark. It works for daily use, but `--performance` or `--lowlatency` is the better choice, since far more users have tested those two modes. Feedback on this mode may be shared with other developers to help improve their schedulers and, where possible, the benchmark itself.

### `--performance`

This mode builds on the default logic and tunes it for steadier performance under load, such as higher frame rates while background work runs. Busy CPUs avoid deep idle states, so it uses more power.

### `--lowlatency`

This mode builds on `--performance` and tunes it further for lower and steadier latency under heavy load. When every CPU is busy, a latency critical task that wakes up preempts a task that computes instead of waiting in a queue, the preempted task then resumes on the same CPU, and no CPU enters a deep idle state, so it uses the most power.

The table below shows `cyclictest -m -q -D 60 -i 1000 -t 4 -h 400 --policy=other` on an AMD Ryzen 7 6800H (8 cores, 16 threads, one 16 MiB L3 cache) running Linux 7.3 with a 1000 Hz tick, while `stress-ng --cpu 16` kept every CPU busy. Each value is the median of three 60 second runs.

| Latency (µs) | p50 | p99 | p99.9 |
|---|---|---|---|
| `--performance` | 58 | 66 | 106 |
| `--lowlatency` | 55 | 61 | 77 |

## Production Ready?

scx_flow keeps gaining new ideas and improvements, and each release is checked for stability so that it can run on production machines such as workstations and servers. Contributors are encouraged to stress test their changes before sending a pull request.

## Limitations

- Hotplug reloads it.

## Credits

scx_flow is made possible by the support we received from the sched_ext community. Credit goes to the developers and contributors whose work inspired it and who helped with its development.
