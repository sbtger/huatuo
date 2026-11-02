# Memory snapshot performance experiments

This opt-in suite measures feature costs separately from memory-pressure costs.
It reuses the fault-isolation framework's real services, discovery, ownership,
plain Agent build and event storage. It does not change production features.

## Experiments and interpretation

| Experiment | Groups | Identical conditions | Comparison |
|---|---|---|---|
| idle | A: no Agent; B: feature disabled; C: enabled | no induced pressure; same requested HTTP rate | C−B feature residency; C−A total residency |
| pulse | A: no Agent; B: disabled; D: enabled | same pressure MiB, timing, container limits and HTTP rate | D−B feature increment under pressure; D−A total impact |

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
| memburst trigger and up to three targets | `--experiment pulse --pressure-languages go,java,python --pressure-targets 3`; actual selected PIDs and records |
| threshold listener scale | `--copies N`: N registered containers **per selected runtime**; additional neighbor is not registered |
| simultaneous container edges | `--pressure-targets N` among selected `--pressure-languages`; report actual captures, not assumed parallel execution |
| runtime differences | Go required as pressure driver; choose pressure runtime with `--pressure-languages`; all loaded businesses retain separate results |
| memory headroom | `--memory-limit-mib`, `--pressure-mib`, `--threshold-percent`; observed cgroup usage must confirm pressure |
| output/deadline sensitivity | threshold `--top-k`, `--capture-timeout`; retain entries/truncation/status/output bytes; memburst keeps its shipping fixed limits |
| business load and capacity sweep | `--qps`, explicit JSON matrix and optional p99 SLO; target and neighbor latency/throughput per window |
| repeated captures | repeats create independent groups; use separate stability suite for repeated same-Agent captures |

Pressure allocation uses the existing fixtures (including Java direct memory);
it is not a claim about Java heap exhaustion. Pressure is limited to 600 MiB by
the current fixture, with at least 64 MiB configured container headroom. This
suite does not deliberately induce OOM. Object-shape generators, forced slow
syscalls, cold-cache manipulation, runtime GC logs and a fully managed remote
load-controller remain extensions; they are not silently simulated here.

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

The built-in fixed-arrival HTTP driver is bounded per target. Latency is measured
from intended arrival, with send delay and service time retained. Queue overflow,
dispatch lag, timeouts, incorrect responses and missing rows cannot disappear.
Co-located client/observer CPU can distort measurements. Calibrate it and repeat
important results with a separate host/load tool before publishing overhead.
The standalone `workloads/performance_load.py` accepts a JSON list of reachable
`{id,url}` targets, rate, duration and optional epoch start time for external
experiments. The campaign currently orchestrates its co-located driver only.

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
  --slo-p99-ms 20 --output /root/perf-matrix
```

All cells are validated before execution, run sequentially and keep independent
reports. The optional capacity report groups only identical configurations
apart from QPS, and reports the **highest tested rate** satisfying the supplied
SLO in every repeat. It does not interpolate or prove maximum capacity. At least
1000 requests per target/window are needed for p99; p95 needs 200. Null tails
are unavailable, never zero. Tail percentiles are not averaged across runs.

## Measurements and artifacts

- `REPORT.md`, `analysis.json`: trial validity and paired absolute deltas.
- `results.json`, `command.json`, `supervisor.json`: configuration, order, results,
  campaign termination and ownership cleanup outcome.
- Per-trial `requests.jsonl`: every intended arrival, dispatch lag, send/end
  timestamps, response validity and failure reason.
- `resources.jsonl`: Agent, observed descendants and businesses; CPU counters,
  RSS, FD/thread counts, faults, switches, I/O; cgroup usage/lifetime peak/failcnt;
  host meminfo/vmstat/CPU counters and available PSI.
- `pressure.json`: atomic pressure commands, release and first-observed event
  times; events include target PIDs, provider duration, status and output limits.
- `environment.json`, configs/logs/events, `executed-framework.tar.gz`, and
  `integrity.json`: binary/BPF/source evidence and raw artifact hashes.

Resource sampling defaults to 100 ms. CPU is a sampled counter delta; short-lived
children may escape observations. RSS sums shared pages and is not unique memory.
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
