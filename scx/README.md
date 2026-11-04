# scx_flow

## What

scx_flow places tasks by virtual time. Each LLC maps to one strand of a pair queue. The pair queue is a DHQ that runs in strict priority mode and picks the lowest virtual time first with ties going to strand A. When a pair is full or imbalanced the task goes to the per LLC queue. Dispatch checks the local pair first, then pairs on the same node, then pairs on other nodes, then LLC queues. A wakeup preempts the running task when its virtual time is smaller by at least 500000 nanos and the running slice has more than 125000 nanos left, else it wakes an idle CPU. Slice is 1000000 nanos. A requeued task keeps its remaining slice with virtual time advanced through the per pair sequence.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open and other apps in the background.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
- Moving from 5.0.2 or 5.0.1 needs a restart with no live transition.

## Speed hint

The scheduler sends a per CPU speed hint to the governor. Stop folds burnt share into a smoothed level with three parts prior plus one part fresh. Start maps the smoothed level through a band and sets one CPU only. At or above three quarters it asks for full speed so a busy core stays ready. At or below one quarter it asks for half speed so an idle core rests but stays awake. Between the bands it keeps the smoothed value to avoid rapid flips. There are no knobs. The hint needs the schedutil governor plus hardware and driver support. If the verifier or policy rejects the setter the scheduler still places and dispatches with no hint. The hint never changes placement, virtual time, deadline, slice, or dispatch order. Stats stay four counters. No power claim is made since governors and hardware vary and harness runs vary.

## Policy

Placement stays earliest virtual time first. Lower virtual time runs earlier with deadline equal to virtual time plus 1ms and ties going to strand A with no history. A static RMS policy with shorter period higher was rejected for this tree since it needs period and release tracking with inference and extra state and a second key, fits the pair queue poorly, costs a larger change, and the current harness favors the dynamic form. A future additive hint may live inside virtual time with no replacement of the current policy.
