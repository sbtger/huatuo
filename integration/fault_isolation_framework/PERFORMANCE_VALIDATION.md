# Performance framework short validation — 2026-11-02

This validates measurement and rejection paths, not production overhead or SLOs.
Use [the plan](PERFORMANCE_PLAN.md) for execution and interpretation, and
[structured results](PERFORMANCE_RESULTS.json) for trial-level observations.

## Environment and workload

- Dedicated x86-64 VM: 16 vCPUs, 16 GiB configured memory; Linux
  `5.10.0-cache-ext-vm-nokmem-8780cdccc1e2`; Docker cgroup v1.
- Go 1.24.3 fixture, HotSpot 17.0.19, CPython 3.12.3; real plain Agent.
- Agent SHA-256:
  `5b4fd01e1a72d8dcdeb268e11e68c7e0a94e662f608baa5f068f2b54823a2807`.
  This is the retained PID-enumeration-fix candidate, not a new official release.
- Three registered runtime containers and one unregistered, unpressured Go
  neighbor; 5 requests/second per loaded business. No fault overlay or retry.
- One repeat/cell; warmup 3 s, baseline 4 s, hold 12 s, recovery 4 s.
  Pulse pressure: 500 MiB per selected container; 768 MiB container limits.
- Same immutable producer source for all six campaigns; the executed source,
  binaries' hashes, BPF hashes, configurations and full raw evidence are retained.

## Results

| Case | Module | Experiment | Measurement verdict | Enabled-group max dispatch lag |
|---|---|---|---|---:|
| P01 | memory_threshold_snapshot | idle A/B/C | VALIDATION_PASS | 0.375 ms |
| P02 | memory_threshold_snapshot | three-target pulse A/B/D | INVALID_OR_FAILED | 147.936 ms |
| P03 | memburst | idle A/B/C | VALIDATION_PASS | 0.392 ms |
| P04 | memburst | three-target pulse A/B/D | INVALID_OR_FAILED | 193.125 ms |
| P05 | memory_threshold_snapshot | single-Go-target pulse A/B/D | VALIDATION_PASS | 0.349 ms |
| P06 | memburst | single-Go-target pulse A/B/D | VALIDATION_PASS | 0.400 ms |

The concurrent pressure cases exceeded the preconfigured **100 ms load-generator
scheduler-lag bound**. Their business requests completed successfully, and real
matching snapshots persisted (one requested target for threshold; three for
memburst), but the offered load was insufficiently precise for accepted paired
performance conclusions. Both D trials remain invalid; their A/B controls and
all raw failures remain visible. P05/P06 are separate lower-concurrency cells,
not replacement retries that erase P02/P04.

The one observed threshold capture does not prove that the other two targets
were captured in parallel. Actual selection and the existing node-wide cooldown
are preserved. Full ranked memburst records, including self/other selections,
remain in the raw events; requested-target capture counts are separate.

Across all cells: **18 independent trials, 8,280 HTTP requests, 4,000 resource
samples**, no HTTP checksum/error observations, and six requested-target capture
records. Six evidence/ownership audits passed. Four campaigns had valid complete
measurement groups (16 valid trials total); two campaigns had one invalid D
group each. Invalid D groups contribute **zero valid pairs**.

Short measured windows contain 100 requests/business, below the 200/1,000 sample
floors for p95/p99. Those tails are null; no p99 or production capacity conclusion
is claimed. An offline capacity-path check also confirmed that insufficient-tail
and invalid campaigns cannot yield an accepted highest-tested rate.

## Implementation verification

- 124 Python framework controls passed locally and on the Linux builder with
  Python 3.9. The builder's default Python 3.6 is unsupported; its initial run
  failed before rerunning with the supported interpreter.
- Repository `make check` passed.
- Fresh read-only review identified three Important issues: unregistered-neighbor
  readiness, stale capture attribution and aborted-campaign capacity inclusion.
  Each has a regression observed RED then GREEN. No Critical or deferred Minor
  review findings remained; the full 124-control suite passed after fixes.
- Independent raw checks verified request ordinal coverage, resource identities,
  recorded file hashes, exact executed source, and absence of owned live
  processes, Docker containers and images after completion.

The framework is ready for larger calibrated experiments. Formal concurrency
measurements should move the generator to a separate host and verify its offered
rate before evaluating feature cost. Higher process/container counts, five-repeat
experiments, object-shape stress and runtime-specific warmup remain unmeasured
by this short validation. Worker isolation is not implemented by this change.

## Raw evidence

Archive: `huatuo-performance-evidence-20261102-v2.tar.gz`
(96,697,974 bytes; 6 campaigns / 18 trials).

SHA-256:
`0c575ee978f914ec617757a44ea0949656584a3816ecca6d8ab3261d20a0dc3b`.

The archive retains all six datasets, including invalid concurrent cells, source
snapshots, build metadata, independent audit and capacity-path verification.
The structured public results omit machine-specific artifact paths.
