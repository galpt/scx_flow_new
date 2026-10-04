# Changelog

## 4.8.1

- Cut schbench RPS cost with no order change. Select keeps idle first early exit with one `ktime` for previous plus SSF plus BSF, pow2 masking for cursor math, and BSF capped at `4` peers for at most `12` checks per pass. Dispatch hoists four queue hints once with per tier runnable gates plus Q1 only local fast path plus per peer empty skip plus cursor cache on steal success with the `4` to `8` window kept. Enqueue hoists eligibility to one minimum read for bypass plus kick. Perf stays transition only with one `ktime` per op. Queues stay `1042` with `64B` plus `16B` plus PRIQ plus mask wins plus bounded visits plus signed order plus kernel doc, and mirrors plus property checks track BSF `4` plus wrap plus Q1.
- Keep single weighting through one shared band with `0` scoping to defaults and zero sentinel to acquire. Moves plus disable plus enable plus exit invalidate the cached id, so reused pids never read stale with no double count.
- Tier takes the fair key with local plus node drain, so busy nodes hold local with no wait. Pinned tasks recompute the deadline from predictor plus hint with no stale reuse. Deviation trains from the new average, so margins track the fresh mean with no lagging bound.
- Preempt keeps strict one kick per wait with every hold counted in skipped and bypass gated on fair plus eligibility with no storm. Running claims the pid with compare and swap, minimum folds with bounded retry, negative lag maps to zero, sparse nodes fold safe, and perf polls node with no machine walk. Docs plus mirrors plus UI track the new shape with 50 word subsections, 1042 queue checks, and fifteen counters with preempt cards. No `dhq.h` plus no `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.8.0

- Reshape into per logic files with `intf.h` truth plus `main.bpf.c` maps plus ops only plus `cgroup.bpf.c` gate plus `weight.bpf.c` nice table plus `calc_delta_fair` plus `vtime.bpf.c` ledger plus min plus `edf.bpf.c` deadline plus eligibility plus `task_placement.bpf.c` SSF scan in `O(VISIT)` with `VISIT` at `8` plus steal plus thin `select_cpu` plus `enqueue` with `insert_vtime` plus overflow FIFO plus `preempt` lead plus tail with at most one kick plus `dispatch` bounded drain plus steal plus fail open plus `lifecycle` charge only in stopping plus per CPU `stats` with no shared modify plus optional `timer` decay. Queues grow to `1042` with overflow FIFO, visits fall to `8` with steal `4` to `8` and placement `8`, scaler moves to one divide with a `40` entry nice table centred at `128`, and Rust mirrors plus `edf_harness` property checks track the shape with `1042` queue plus `8` visit plus `120B` stats checks.
- Keep single weighting through one shared band with `0` scoping to defaults and zero sentinel to acquire. Moves plus disable plus enable plus exit invalidate the cached id, so reused pids never read stale with no double count.
- Tier takes the fair key with local plus node drain, so busy nodes hold local with no wait. Pinned tasks recompute the deadline from predictor plus hint with no stale reuse. Deviation trains from the new average, so margins track the fresh mean with no lagging bound.
- Preempt keeps strict one kick per wait with every hold counted in skipped and bypass gated on fair plus eligibility with no storm. Running claims the pid with compare and swap, minimum folds with bounded retry, negative lag maps to zero, sparse nodes fold safe, and perf polls node with no machine walk. Docs plus mirrors plus UI track the new shape with 50 word subsections, 1042 queue checks, and fifteen counters with preempt cards. No `dhq.h` plus no `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.7.6

- Scale to `1024` CPUs plus `16` nodes plus `8192` hints plus `2048` cache with `1041` queues. Dispatch drains local plus node plus machine plus steal in fair order with one move per tier capped by slots and `64` shared visits with resume. Steal scans `8` to `16` peers proportional to remaining visits with mask wins and local counting, so stats stay at `120B`. Placement scans `16` peers with the same bound.
- Keep single weighting through one shared band with `0` scoping to defaults and zero sentinel to acquire. Moves plus disable plus enable plus exit invalidate the cached id, so reused pids never read stale with no double count.
- Tier takes the fair key with local plus node drain, so busy nodes hold local with no wait. Pinned tasks recompute the deadline from predictor plus hint with no stale reuse. Deviation trains from the new average, so margins track the fresh mean with no lagging bound.
- Preempt keeps strict one kick per wait with every hold counted in skipped and bypass gated on fair plus eligibility with no storm. Running claims the pid with compare and swap, minimum folds with bounded retry, negative lag maps to zero, sparse nodes fold safe, and perf polls node with no machine walk. Docs plus mirrors plus UI track the new shape with 50 word subsections, 1041 queue checks, and fifteen counters with preempt cards. No `dhq.h` plus no `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.7.5

- Add per task weight via set weight with clamped base plus stacked effective share of task times hint over 128. Enqueue plus stopping plus leftover charge use the effective share for scaled delta plus virtual deadline with no extra store, and the shared band helper serves cgroup plus task paths on powers of two.
- Add busy preempt counters with preempt kicks on sent preempts plus preempt skipped on margin plus tail plus eligibility holds. Stats grow from `104B` to `120B` with 15 counters, and all four kick points keep one kick per wait with no storm.
- Docs plus mirrors plus UI track the new shape with 50 word subsections, 521 queue checks, share combine plus effective tests, and fifteen counters with preempt cards. No `fair.c` helper text is copied and the queue order stays in kernel priority queues.

## 4.7.4

- Drop the overflow tail for 521 queues with local plus node plus machine only. Every wait rejoins a tier queue in fair order with a fallback deadline plus a tier insert, dispatch drops the overflow scan plus its account, and stats fall from `120B` to `104B` with 13 counters and no parks.
- Add vruntime fairness at `64B` task plus `16B` CPU with release evicted and 32 bit predictor fields. Weight scales with banded shifts and no divide, vruntime advances by scaled service, lag clamps at `2ms`, eligibility gates kicks, virtual deadline adds eligible plus request over weight, and fair vtime takes min deadline plus virtual deadline. Lifecycle stopping plus disable plus exit charge plus advance plus fold the minimum, and the timer leftover matches.
- Share bands map light shares to long periods plus small weights while heavy shares map to short periods plus large weights on powers of two. Enqueue copies the clamped weight uniformly for cgroup plus root tasks with neutral on miss. Placement keeps the slowest sufficient CPU with near minimum tiebreak on minima within `64` units, and deadline helpers add a CPU minimum read plus a fair drain check with the bypass on fair time.
- Docs plus mirrors plus UI track the new shape with 50 word subsections, 521 queue checks, fair tests, and thirteen counters with no overflow cards. No `fair.c` helper text is copied and the queue order stays in kernel priority queues.

## 4.7.3

- Gate first with queue depth early out in dispatch plus select plus enqueue. Tiers leave at once on empty with no RCU hold, idle hits pay no state cost, and rejects pay no alloc. Static tier order stays local plus node plus machine plus overflow with the probe plus move held in failopen through one shared gate.
- Idle direct bypass takes idle targets straight to local with one kick only when tiers hold no queued work or the target drains before the deadline, so wakeups skip the tier plus dispatch hop with no EDF bypass. The bypass skips move counts, so admits vs moves drift expected. Requeues plus last expiry reuse the cached hint with no cgroup acquire and pace with no occupant lookup with stale reuse to next fresh wakeup, and a zero deadline keeps the previous CPU with no 8 peer scan. Cold tasks use the fresh hint period with no stale use, and missing state parks with no gate count.
- Hierarchy id cache with 1024 entries pays one hash lookup on hit with no acquire, and stays ABA safe via clear on migrate plus enable plus task exit with weight reads staying fresh. Full tables cap at 1024 with fail to the acquire path and no eviction. Frequency keeps transition only sets through one cached compare with live plus bound before the cap.
- Snapshot counts live pids for the on CPU gauge with no BPF counter and 2N map reads per poll, so hot paths pay no atomic. Branches carry likely plus unlikely with the expected path first and no fair.c helper.
- Fixed slice at `1ms` with sixteen slices per `16ms` period. Task state at `64B` with no virtual runtime and no nice table.
- Dispatch moves uncapped to remaining dispatch slots with no batch plus no flood plus no step plus no tier probes. Tiers plus overflow skip uniformly through the shared move with mask wins on drain. Visits cap at `64` per pass regardless of moves with resume next pass, so one pass never holds RCU across the whole queue while staying work conserving across passes. No consumable slots leaves at once with no scan.
- Joins carry no admission bound and no stored share. Every join counts one admit with rejects staying zero for wire compat and real rejects in gate_rejects while the deadline predictor stays. Past saturation at `100%` utilization the core still drains best effort in deadline order with miss cascade expected.
- EDF order via kernel priority queue with the deadline as vtime and no lag compensation.
- Docs plus validation track the new shape. No `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.7.2

- Fixed slice at `1ms` with sixteen slices per `16ms` period. Task state at `64B` with no virtual runtime and no nice table.
- Dispatch moves uncapped to remaining dispatch slots with no batch plus no flood plus no step cap plus no tier probes. Tiers plus overflow skip uniformly through the shared move with mask wins on drain. Visits cap at `64` per pass regardless of moves with resume next pass, so one pass never holds RCU across the whole queue while staying work conserving across passes. No consumable slots leaves at once with no scan.
- Joins carry no admission bound and no stored share. Every join counts one admit with rejects staying zero for wire compat while the deadline predictor stays. Past saturation at `100%` utilization the core still drains best effort in deadline order with miss cascade expected.
- EDF order via kernel priority queue with the deadline as vtime and no lag compensation.
- Docs plus validation track the new shape. No `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.7.1

- Dispatch batch at `32` with the `nr_slots` clamp at entry and the remaining budget as the per tier bound. Flood at `8` past `128` queued with the step cap at `32`.
- Priority tiers skip within four probes through the shared move with mask wins on drain. Overflow keeps the `32` step cap in the same style.
- Preempt margin plus tail at `100us` with the floor at `100us` and one kick per park. The three kick points stay with no extra sender.
- First deviation floor at the max of error and average quarter with shifts plus clamp kept. Later samples keep quarter steps toward error.
- Docs plus validation track the new bounds. No `dhq.h` header is used and the queue order stays in kernel priority queues.
