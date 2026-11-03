# Memory snapshot performance experiments

**Primary strategy:** [MEMSNAPSHOT_PRESSURE_PLAN.md](MEMSNAPSHOT_PRESSURE_PLAN.md)
measures controlled resident KV objects under fixed business cgroup pressure.
[REAL_BUSINESS_PLAN.md](REAL_BUSINESS_PLAN.md) is an optional native second tier;
its matrices are stopped. Fixture measurements below remain historical
framework validation and cannot be relabeled as business acceptance.

This opt-in suite measures feature costs separately from memory-pressure costs.
It reuses the fault-isolation framework's real services, discovery, ownership,
plain Agent build and event storage. It does not change production features.

## Experiments and interpretation

| Experiment | Groups | Identical conditions | Comparison |
|---|---|---|---|
| idle | A: no Agent; B: feature disabled; C: enabled | no induced pressure; same requested HTTP/Redis rate | C−B feature residency; C−A total residency |
| pulse | A: no Agent; B: disabled; D: enabled | same pressure MiB, timing, container limits and offered rate | D−B feature increment under pressure; D−A total impact |

Do not label D−C from different pressure trajectories as capture overhead.
Group order is randomized with a recorded seed. Each group gets fresh fixtures
and a fresh Agent. Repeat five times by default; failed trials remain visible
and cannot contribute valid pairs. Partial captures retain status and entry
counts; Go requires complete, Java/Python allow nonempty complete/partial.
No capture retry or fault-overlay executable is used in measured groups.

Default HTTP load and high-frequency process sampling cover the first container
of each runtime, all pressure targets and the neighbor. Additional watched
containers stay idle, keeping listener scale separate from offered business
load. `--load-all` explicitly loads and samples every container. All containers
still receive before/after identity, state and memory-failure checks.

The load fixture allocates memory and hashes payloads on every `/work` request.
A smaller unpressured Go neighbor is checked separately; if memburst selects it,
the trial is invalid for the uncollected-neighbor claim. Transaction checksum,
process lifetime, background progress, request bodies and memory-limit failure
counters are checked. This fixture is an example workload, not every production
application's allocation/GC behavior.

## Implemented scenario controls

| Question | Controls / evidence |
|---|---|
| memburst residency and process scale | `--experiment idle --extra-processes N --poll-interval S`; actual process count and per-process readiness |
| memburst trigger and up to three targets | `--experiment pulse --pressure-languages go,java,python --pressure-targets 3 --burst-max-targets 3`; actual selected PIDs, raw cardinality and records |
| threshold listener scale | `--copies N`: N registered containers **per selected runtime**; additional neighbor is not registered |
| simultaneous container edges | `--pressure-targets N` among selected `--pressure-languages`; threshold arbitrates one eligible container per admitted batch; require a nonempty successful eligible subset, retain every selected PID and do not assert all edges are captured |
| runtime differences | Go required as pressure driver; choose pressure runtime with `--pressure-languages`; all loaded businesses retain separate results |
| memory headroom | `--memory-limit-mib`, `--pressure-mib`, `--threshold-percent`; observed cgroup usage must confirm pressure |
| output/deadline sensitivity | threshold `--top-k`, `--capture-timeout`; retain entries/truncation/status/output bytes; memburst keeps its shipping fixed limits |
| business load and capacity sweep | `--qps`, explicit JSON matrix and optional p99 SLO; target and neighbor latency/throughput per window |
| Redis neighbor and fork | `--redis`; each logical request pipelines SET, GET with payload verification, and INCR; `--redis-fork-interval 10 --redis-keys 512` adds scheduled BGSAVE on a 32 MiB dataset |
| independent load | `--load-controller-url` and `--load-token-file`; separate load VM, bounded fixed-arrival jobs, clock/source/artifact verification, lease cancellation and client CPU/RSS/PSI |
| repeated captures | repeats create independent groups; use separate stability suite for repeated same-Agent captures |

Pressure allocation uses the existing fixtures: Go private anonymous mappings,
Java file-backed mappings and Python shared anonymous mappings;
it is not a claim about Java heap exhaustion. Pressure is limited to 600 MiB by
the current fixture, with at least 64 MiB configured container headroom. This
suite does not deliberately induce OOM. Object-shape generators, forced slow
syscalls, cold-cache manipulation and runtime GC logs remain extensions. Redis is
a separate uncollected neighbor, not an additional supported snapshot runtime.
The fork witness requires a BGSAVE acknowledgment, a newly completed RDB file,
successful INFO state and nonzero fork duration. Redis versions exposing
`total_forks` also require an increased counter. Observed child PIDs, COW bytes
when supported, INFO, Redis binary hash, logs and RDB files are retained. Every
acknowledged request must match the server work counter. Dataset size is bounded
to 32 MiB; Redis uses its own 256 MiB cgroup and no global daemon is changed.

## Commands

Requires an isolated root Linux VM, Python >=3.8, Docker with cgroup v1, Java
compiler/runtime, Python and a hash-verified build from this framework. BPF
objects must match the Agent. Run only one memory campaign at a time.

```sh
python3 integration/fault_isolation_framework/performance.py \
  --module memburst --experiment idle \
  --build /root/build --bpf-dir /root/project/bpf \
  --extra-processes 100 --repeats 5 --output /root/perf-burst-idle

python3 integration/fault_isolation_framework/performance.py \
  --module memory_threshold_snapshot --experiment pulse \
  --build /root/build --bpf-dir /root/project/bpf \
  --pressure-languages go,java,python --pressure-targets 3 \
  --repeats 5 --output /root/perf-threshold-pulse
```

`--plan` validates arguments and prints the deterministic schedule without
creating output. Short validation may use `--repeats 1 --warmup 3 --baseline 4
--hold 12 --recovery 4 --qps 5`; these are **not** performance acceptance runs.
Default warmup is 60 seconds, followed by 30 seconds baseline, 30 seconds hold
and 30 seconds recovery. Runtime-specific warmup still needs calibration.

The built-in fixed-arrival HTTP/Redis driver is bounded per target. Latency is
measured from intended arrival, with send delay and service time retained.
Queue overflow, dispatch lag, timeouts, incorrect responses and missing rows
invalidate a trial. Request identity and ordinal coverage are checked, including
warmup; no missing/duplicate/extra arrivals are accepted. Each logical request
uses a fresh TCP connection consistently across all groups. Redis requests use
one connection for the SET/GET/INCR pipeline. Calibrate the network path and
hypervisor FD limits before a formal run.

### Separate load VM

Use a private test network. On the load VM, install the exact same framework
revision and provision a random token file with mode 0600 on both VMs. The token
is never written to reports. Start the typed job service on the load VM:

```sh
python3 integration/fault_isolation_framework/load_controller.py \
  --token-file /root/load-token --output /data/load-jobs \
  --target-host DUT_PRIVATE_IP --port-start 30000 --port-count 64
```

Run the DUT campaign with the endpoint reachable from the DUT:

```sh
python3 integration/fault_isolation_framework/performance.py \
  --module memburst --experiment pulse --burst-max-targets 1 \
  --build /data/build --bpf-dir /data/bpf --redis \
  --redis-server /usr/bin/redis-server --redis-fork-interval 10 \
  --redis-keys 512 --load-controller-url http://LOAD_PRIVATE_IP:19890 \
  --load-token-file /root/load-token --load-target-host DUT_PRIVATE_IP \
  --service-port-base 30000 --load-target-base-port 30000 \
  --output /data/perf-burst-redis
```

Only the configured host/port range and fixed HTTP/Redis jobs are accepted; no
arbitrary shell commands are exposed. Each job requires authentication,
heartbeat lease renewal, bounded queues and duration, cancellation and draining.
The client verifies the three load-driver source hashes, clock uncertainty and
drift (default 20 ms bound), and raw artifact byte counts/SHA-256 before
acknowledging transfer. Acknowledgment deletes transferred raw files only on the
load VM. The DUT retains remote raw monotonic timestamps and converted copies,
clock samples, source hashes, remote CPU/RSS/PSI and job metadata. Clock offset
is subtracted, not silently included in measured service latency.

External mode binds owned business ports to 0.0.0.0; defaults remain ephemeral
loopback ports for existing suites. Keep these ports and the bearer-token HTTP
service confined to the private lab network. The host and port seen by the load
VM may differ from the DUT bind ports when using explicit NAT forwarding.
The 140 deployment uses host-loopback QEMU forwards, without a DUT SSH tunnel.
Separate VMs remove load CPU from the DUT, but share a physical host and its
network emulator; this is a disclosed limitation of published VM results.

## Explicit matrices and rate sweeps

Example `matrix.json`:

```json
[
  {"name":"burst-idle-100","options":{"module":"memburst","experiment":"idle","extra-processes":100}},
  {"name":"threshold-q20","options":{"module":"memory_threshold_snapshot","experiment":"pulse","qps":20}},
  {"name":"threshold-q40","options":{"module":"memory_threshold_snapshot","experiment":"pulse","qps":40}}
]
```

```sh
python3 integration/fault_isolation_framework/performance_matrix.py \
  --matrix matrix.json --build /root/build --bpf-dir /root/project/bpf \
  --common-options /root/remote-options.json \
  --slo-p99-ms 20 --output /root/perf-matrix
```

`--common-options` is a JSON object of CLI option names and values (without
leading `--`). It supplies runtime paths and remote-load settings to every cell;
a cell can override a common value. Common options are retained in the matrix
output. All cells are validated before execution, run sequentially and keep independent
reports. The optional capacity report groups only identical configurations
apart from QPS, and reports the **highest tested rate** satisfying the supplied
SLO in every repeat. It does not interpolate or prove maximum capacity. At least
1000 requests per target/window are needed for p99; p95 needs 200. Null tails
are unavailable, never zero. Tail percentiles are not averaged across runs.

## Measurements and artifacts

- `REPORT.md`, `analysis.json`: trial validity and paired absolute/percentage
  deltas by baseline, trigger, recovery and combined measured window. Percent
  change is unavailable for a zero baseline; repeat medians never average tails.
- `results.json`, `command.json`, `supervisor.json`: configuration, order, results,
  campaign termination and ownership cleanup outcome.
- Per-trial `requests.jsonl`: every intended arrival, dispatch lag, send/end
  timestamps, response validity and failure reason.
- `resources.jsonl`: Agent, observed descendants and businesses; CPU counters,
  RSS, FD/thread counts, faults, switches, I/O; cgroup usage/lifetime peak/failcnt;
  host meminfo/vmstat/CPU counters and available PSI.
- `remote-load.json`, raw remote requests/resources and `redis.json`: placement,
  source/clock/hash proof, load resources, actual writes and completed forks.
- `pressure.json`: atomic pressure commands, release and first-observed event
  times; events include target PIDs, provider duration, status and output limits.
- `environment.json`, configs/logs/events, `executed-framework.tar.gz`, and
  `integrity.json`: binary/BPF/source evidence and raw artifact hashes.

Resource sampling defaults to 100 ms. `cpu_seconds` is Agent self CPU plus
waited-child CPU from `/proc/PID/stat` (cutime+cstime). This includes workers
that exit between samples. Child CPU is attributed when reaped, so work crossing
window boundaries is not prorated and live/unreaped children are excluded.
`sampled_tree_cpu_seconds` remains a separate lower-bound diagnostic; never add
it to the waited-child total, which would double-count observed workers.
RSS sums shared pages and is not unique memory.
Cgroup peak counters cover the container lifetime, not only the trigger window.
The trial summary `selected_pids` is the requested-target intersection; complete
ranked selection, including Agent/self captures, remains in the raw events.
Provider duration is not full queue-to-persistence latency. First observed event
time includes observer polling lag. Unsupported PSI is null, not zero.

Offline verification and derived report regeneration:

```sh
python3 integration/fault_isolation_framework/performance.py \
  --report --output /root/perf-threshold-pulse
```

`VALIDATION_PASS` means a complete, valid measurement workflow. Performance
acceptance is separately `NOT_EVALUATED`; no arbitrary universal overhead budget
is installed. A short VM run cannot establish production throughput or p99 SLOs.

## Execution stages and reference coverage

1. Run short validation of idle, burst-one, burst-three, threshold-three and
   both Redis-fork cells, one randomized repeat with 3/4/12/4 s windows.
   These validate orchestration and capture coverage, not performance acceptance.
   For memburst require every requested target and at most the configured
   one/three selection slots in every raw event. For threshold require actual
   successful eligible selections, consistent with one-container batch arbitration.
2. Calibrate no-Agent A and disabled-feature B controls, runtime warmup,
   observer cost, client CPU and dispatch lag. Infrastructure errors invalidate
   controls as well as enabled trials. Preserve failures; repeat in a new output
   directory only after recording the cause and environment change.
3. Run `performance_reference_matrix.json`: 18 cells, five independent repeats,
   randomized group order, 60 s warmup and 30 s baseline/trigger/recovery.
   At 40 requests/s each 30 s window has 1200 intended arrivals per loaded target;
   p99 remains unavailable when fewer than 1000 valid requests are present.
   The matrix covers process scale/poll interval, listeners, one/three targets,
   Go/Java/Python, headroom, top-k, timeout, Redis writes/fork and 40/80 rate cells.
   Each case includes both an HTTP neighbor and a real Redis write neighbor;
   fork cells additionally schedule BGSAVE every 10 s after warmup.
4. Compare C-B/C-A for residency and D-B/D-A under matched pressure. Report CPU
   seconds including reaped child CPU, sampled RSS peak, actual target count,
   status/entries, target/neighbor throughput and window tails. Failed cells
   remain visible and are excluded from valid paired cost conclusions.
5. Keep calibration and formally repeated evidence separate. Preserve commands,
   kernels, CPU/memory sizes, QEMU/network configuration and limits, runtime
   versions, source and six-binary hashes. Rebuild and rerun all control groups
   after an environment or kernel change; never combine incompatible baselines.

Top-k/timeout cells report actual status and truncation; they do not guarantee
this fixture hits a limit. Failed captures are retained. Agree workload-specific
throughput/tail/resource budgets before declaring acceptance. The 40/80 cells
are a small tested rate sweep, not maximum-capacity or production SLO proof.
Long-duration reliability, injected failures, allocation/memory-bandwidth
microbenchmarks, other runtime/kernel versions and real Kubernetes discovery
are outside this performance matrix and must be reported separately.

See [independent-load short validation](PERFORMANCE_COMPLETION_VALIDATION.md)
for retained failures, calibration and actual Redis fork witnesses.
