# Independent-load performance framework validation

Date: 2026-11-03. Performance acceptance: **NOT_EVALUATED**.

This records short workflow validation of the new independent-load and Redis
extensions. It preserves the negative results and supersedes no historical run.
The production Agent and memory-snapshot feature code are unchanged by this
extension. Formal repeated measurements are separate from this short report.

## Setup

DUT: 8 vCPU/8 GiB, Linux `6.6.8-cache-ext-g2770699acde8`, Docker cgroup v1.
Load VM: 4 vCPU/6 GiB, Linux 7.2-rc2; separate guest CPU/memory, shared physical
host and QEMU network emulator. Dedicated 64 GiB DUT data disk. Load crosses
host-loopback-only NAT forwards without a DUT SSH tunnel. Go, HotSpot 17,
CPython 3.12.3, and real Redis 5.0.7; Redis is an unregistered neighbor.

Each cell has one randomized A/B/D repeat, fresh owned containers and a plain
Agent/worker. A: no Agent; B: feature disabled; D: enabled under identical
pressure. Windows: 3 s warmup, 4 s baseline, 12 s trigger, 4 s recovery. Each
loaded target receives 40 logical requests/s; HTTP checksum and Redis pipelined
SET/GET/INCR responses and server counters must match. Resource sampling is
100 ms. Fork cells use a 32 MiB Redis dataset and BGSAVE every 5 s after warmup.
The short windows are insufficient for per-window p99 acceptance.

## Results

| Cell | Workflow | Valid trials | Enabled captures | Completed Redis forks | Raw audit |
|---|---|---:|---|---:|---|
| burst-one | VALIDATION_PASS | 3/3 | go:complete | 0 | PASS |
| burst-three | INVALID_OR_FAILED | 2/3 | java:partial, go:complete, python:complete | 0 | PASS |
| threshold-three | INVALID_OR_FAILED | 2/3 | python:complete | 0 | PASS |
| burst-redis-fork | VALIDATION_PASS | 3/3 | go:complete, go:complete | 12 | PASS |
| threshold-redis-fork | VALIDATION_PASS | 3/3 | go:complete | 12 | PASS |

13/15 trials passed all workflow checks. The separate idle calibration passed
all A/B/C groups. All five cell raw-artifact audits passed. Both fork cells
observed four completed BGSAVE operations per group: 24 completed forks in total.
Redis5 lacks `total_forks`; evidence includes BGSAVE acknowledgment, newly written
RDB, successful completion state, nonzero `latest_fork_usec`, and child PIDs
when observed. No counter was invented for an unsupported INFO field.

## Negative findings retained

- `burst-three/D`: invalid load or business errors: target-000-python. Failed request counts by target: `{'target-000-python': 114}`.
- `threshold-three/D`: invalid load or business errors: target-000-python. Failed request counts by target: `{'target-000-python': 3}`.

Matched A/B groups passed for both multi-target cells. D persisted successful
eligible snapshots, while Python experienced timeouts/queue overflow during the
pressure ramp. In burst-three, Python CPU and the time to establish pressure
also increased relative to A/B. This is an investigation lead, not
a proven attribution to a specific production function. Keep the failed trials
excluded from valid cost pairs; do not relax guards or describe the finding as
harmless client jitter. Formal repeats must preserve any recurrence.

Threshold selects one eligible container per admitted batch; it does not
promise a snapshot for every simultaneous container edge. The test requires a
nonempty successful eligible selection and retains actual selected PIDs.
Memburst requires all requested targets and enforces the configured one/three
raw event cardinality limit. No business was stopped to force selection.

## Calibration and framework checks

Initial no-Agent load failed because the host QEMU soft FD limit was 1024. A
separate 2400-request probe succeeded 1524 times before the change and 2400
times after raising only the hypervisor process soft limit to 65536. Agent
and business resource limits, response/dispatch guards and error assertions
were unchanged. Initial failed directories remain available. The prior DUT
boot image had been deleted; the recovered, pinned kernel differs from earlier
smoke runs. All controls were rerun; incompatible kernel baselines are not mixed.

The final independent code review found queued requests still being sent after
cancellation. A populated-queue regression failed with 101 transport calls
against one expected call. Workers now check cancellation before transport,
and cancelled queued arrivals remain explicit failed records. The regression
and full 159-test framework suite passed on Python 3.9 locally and on the Linux
builder. Repository `make check` passed before the final commit.

## Reproduction and retained evidence

Use [PERFORMANCE_PLAN.md](PERFORMANCE_PLAN.md) for the independent load service,
token files, routes, CLI and 18-cell five-repeat reference matrix. The smoke
cells shorten windows and fork interval as recorded above. Failed directories
are never overwritten. The final formal run must use a clean rebuilt commit,
matching frozen source on both guests and verified six-binary/source hashes.

Builder evidence is retained under `/data1/zp/huatuo-perf-vm2224-20261103/`:
`completion-smoke-summary.json`, `completion-smoke-raw.tar.gz`, FD calibration,
kernel/network configuration, test logs and the execution ledger. Raw evidence
is a local lab archive, not a publicly hosted download. Review identifiers
before sharing logs. Repeated measurements and workload-specific budgets are
still required before publishing overhead acceptance.
