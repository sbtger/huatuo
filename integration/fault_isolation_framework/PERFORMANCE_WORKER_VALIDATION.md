# Current-worker short performance validation

Date: 2026-11-03. Performance acceptance: **NOT_EVALUATED**.

This report supersedes no historical run. It uses a fresh build from production
revision `47ca12574f70f7fb8672482c7e2eb78830ce0a40`, including the independent
snapshot worker. Measured groups use the plain Agent and plain worker; the
build also contains separately hashed fault binaries that are not used here.

## Method

DUT: 140 guest on SSH port 2222, Linux 5.10, 16 vCPU/16 GiB, cgroup v1.
Go, Java 17 and Python fixtures plus an unregistered Go neighbor are loaded
at 20 requests/s each. One randomized repeat per cell (seed 923); fresh
fixtures per group; 3 s warmup, 4 s baseline, 12 s hold, 4 s recovery.
A has no Agent, B disables the feature, C enables it without pressure,
D enables it with the same pressure as A/B. Pressure is 500 MiB per selected
container with a 768 MiB memory limit. The CPU observer samples at 100 ms.
No fault injection, capture retry or relaxed validity threshold is used.

## Results

| Cell | Workflow | Valid trials | Captures in enabled group | Raw audit |
|---|---|---:|---:|---|
| burst-idle | VALIDATION_PASS | 3/3 | 0 | PASS |
| threshold-idle | VALIDATION_PASS | 3/3 | 0 | PASS |
| burst-three | INVALID_OR_FAILED | 2/3 | 6 | PASS |
| threshold-java | VALIDATION_PASS | 3/3 | 1 | PASS |
| threshold-python | VALIDATION_PASS | 3/3 | 1 | PASS |
| threshold-three | INVALID_OR_FAILED | 1/3 | 1 | PASS |

Measured-window request counts (warmup excluded): `{'campaigns': 6, 'trials': 18, 'valid_trials': 15, 'measured_scheduled': 28800, 'measured_success': 28767, 'measured_errors': 33}`.

## Invalid observations retained

- `burst-three/D`: invalid load or business errors: target-000-go; invalid load or business errors: target-000-java; invalid load or business errors: target-000-python; invalid load or business errors: neighbor-go.
  `target-000-go`: 400/400 successful; max send delay 213.6 ms; reasons dispatch-lag guard.
  `target-000-java`: 400/400 successful; max send delay 170.8 ms; reasons dispatch-lag guard.
  `target-000-python`: 367/400 successful; max send delay 3095.3 ms; reasons URLError(TimeoutError('timed out')), load queue full.
  `neighbor-go`: 400/400 successful; max send delay 171.9 ms; reasons dispatch-lag guard.
- `threshold-three/D`: Failure('missing or failed requested-target capture; never score incomplete collection as cheap success').
- `threshold-three/B`: invalid load or business errors: target-000-go; invalid load or business errors: target-000-java; invalid load or business errors: target-000-python; invalid load or business errors: neighbor-go.
  `target-000-go`: 400/400 successful; max send delay 169.3 ms; reasons dispatch-lag guard.
  `target-000-java`: 400/400 successful; max send delay 170.1 ms; reasons dispatch-lag guard.
  `target-000-python`: 400/400 successful; max send delay 170.5 ms; reasons dispatch-lag guard.
  `neighbor-go`: 400/400 successful; max send delay 170.8 ms; reasons dispatch-lag guard.

These observations are failures of measurement validity or business request
checks, not evidence of acceptable overhead. In particular, a request timeout
must not be dismissed as client jitter solely because dispatch lag also rose.
Successful captures do not override failed business or load assertions.

The burst-three matched A/B controls had no request errors and passed the
dispatch guard; D therefore needs reproduction rather than an assumption that
all failures were driver-only. The DUT had abundant available memory and no
observed rise in memory PSI during this D trial. This does not identify the
root cause. In threshold-three, D persisted only one target; the action runner
has a global cooldown, but the exact missed-edge/batch timeline has not been
proven. B also exceeded the dispatch guard, so the concurrent cost comparison
is unavailable. Neither issue is marked fixed.

## CPU diagnostic (not an overhead acceptance result)

| Cell | Group | Agent self CPU s | Reaped-child CPU s | Total CPU s | Sampled tree CPU s |
|---|---|---:|---:|---:|---:|
| burst-idle | C | 0.080 | 0.000 | 0.080 | 0.080 |
| burst-idle | A | 0.000 | 0.000 | 0.000 | 0.000 |
| burst-idle | B | 0.060 | 0.000 | 0.060 | 0.060 |
| threshold-idle | C | 0.040 | 0.000 | 0.040 | 0.040 |
| threshold-idle | A | 0.000 | 0.000 | 0.000 | 0.000 |
| threshold-idle | B | 0.060 | 0.000 | 0.060 | 0.060 |
| burst-three | D | 0.650 | 1.190 | 1.840 | 1.520 |
| burst-three | A | 0.000 | 0.000 | 0.000 | 0.000 |
| burst-three | B | 0.050 | 0.000 | 0.050 | 0.050 |
| threshold-java | D | 0.070 | 0.080 | 0.150 | 0.070 |
| threshold-java | A | 0.000 | 0.000 | 0.000 | 0.000 |
| threshold-java | B | 0.070 | 0.000 | 0.070 | 0.070 |
| threshold-python | D | 0.060 | 0.040 | 0.100 | 0.060 |
| threshold-python | A | 0.000 | 0.000 | 0.000 | 0.000 |
| threshold-python | B | 0.070 | 0.000 | 0.070 | 0.070 |
| threshold-three | D | 0.090 | 0.000 | 0.090 | 0.090 |
| threshold-three | A | 0.000 | 0.000 | 0.000 | 0.000 |
| threshold-three | B | 0.050 | 0.000 | 0.050 | 0.050 |

The total adds Agent self CPU and waited-child counters; sampled descendant
CPU is shown separately and is never added again. This retains workers that
start and exit between samples. CPU is attributed at reap; live/unreaped
children and cross-window attribution remain limitations. The first/last
in-window observations omit up to roughly two sampling intervals. RSS is
a sampled simultaneous sum, not an exact peak or unique physical memory.

## What remains before published overhead conclusions

- Calibrate and run an independently reachable load controller. Current
  QEMU guests use isolated NAT with identical guest IPs; load is co-located.
- Investigate and reproduce invalid triggered trials against matched A/B
  controls. Retain failures; do not raise latency/error guards to pass.
- Run the 14-cell reference matrix with at least five repeats, calibrated
  runtime warmup and enough samples per window; this short run has no p99.
- Agree workload-specific throughput, latency and resource budgets.
  Long stability and system resource exhaustion are separate campaigns.

## Reproduction and evidence

Use `performance_matrix.py --matrix performance_smoke_matrix.json` with the
build/BPF/output arguments described in `PERFORMANCE_PLAN.md`. Full settings,
all trial summaries and binary hashes accompany this report in
`PERFORMANCE_WORKER_RESULTS.json`. Per-cell `integrity.json` and `audit.json`
cover raw requests, resources, events, configs and executed framework source.
Durable raw evidence is retained on 140 under
`/data1/zp/performance-worker-evidence-20261103/`; this is a local evidence
location, not a publicly hosted download. Open-source readers can reproduce
the suite; this summary does not claim public availability of all raw logs.
