# Resident KV memory snapshot pressure experiments

This is the primary snapshot-cost experiment. Native etcd/Kafka/mitmproxy
adapters remain an optional second tier; their matrices are stopped. Historical
allocation fixtures remain validation evidence, not real-business acceptance.

## Lifecycle and comparisons

All groups start an identical real Agent with both snapshot triggers disabled
and identical remaining configuration. A has no explicit test helper. B starts
a persistent test helper and production WorkerManager but never invokes a
snapshot. C uses the same helper/manager and invokes unchanged production
collector.Snapshot/worker/providers, output limiting, bounded JSON serialization
and a test-owned disk write plus fsync. No production trigger API is added.

B-A includes test scaffold initialization and residency. It does not isolate an
unavailable production feature toggle: the shipping Agent unconditionally initializes
its own worker manager in every group (cmd/huatuo-bamai/tracing.go). C-B measures controlled snapshot work;
C-A includes that work plus scaffold. Daemon threshold/burst detection, ranking
and normal event persistence are excluded. The extra fsync is disclosed rather
than called the daemon's persistence behavior.

## Controlled resident business

One business container runs at a time. The intended full-size cap is 4 vCPU and
4 GiB when VM headroom permits; the 8 GiB DUT must not also run a 4 GiB neighbor.
Short validation may explicitly use a smaller limit and remains nonacceptance.

GET/SET/DELETE/FILL share a seeded deterministic contract. FILL retains real
runtime Record objects with nested maps/lists/arrays. Ninety percent of values
are 1 KiB, ten percent 64 KiB. GET reads immutable retained keys. SET replaces
one of 64 fixed churn slots; DELETE removes and recreates that slot within the
operation. This is bounded allocation/free churn, not an unbounded write log.
The external driver independently predicts each operation/key/payload SHA.
Counters must match every acknowledged seeded operation, including warmup.

Go uses ordinary heap objects at several size/callsite stacks, with the default
512 KiB MemProfileRate fixed at startup. Stats retain published profile-record
count and GC cycles, cumulative pause nanoseconds, lifetime GCCPUFraction
and heap metrics. Rate=1 is not used. GOMEMLIMIT is 90%
of the business limit to bound normal runtime GC headroom; GC remains enabled.
Java uses HotSpot17/G1 with Xms64m and bounded Xmx. Bounded GC logs retain
pause wall durations; MXBean collection wall milliseconds are not GC CPU.
Unavailable Java GC CPU stays null. Collector output may be
partial and is never called a full heap dump. Python uses tracked Record,
dictionary, list and nested-container objects; sampled gc.is_tracked results,
GC counts/thresholds/generation stats remain in evidence. Bounded
gc.callbacks counters retain cumulative pause wall nanoseconds and collecting
thread CPU nanoseconds, including callback overhead; they are not unbounded
per-GC logs. Bytes-only fillers,
external stress processes, target injection and disabled runtime GC are absent.

## Pressure and workload identity

The ladder is 60/80/90/95% of actual business cgroup usage/limit, not requested
payload bytes or host memory. A fresh calibration container grows a real store
and records actual usage until a stable retained-object plateau is observed.
The rough grow calibration is provisional: normal runtime heap occupancy and
charged physical residency can differ across fresh processes even when live
object count, GC count and committed heap match. Before freezing, run exactly
two fresh baseline replays for each of at most three candidate rounds. Each
uses a canonical grow-only recipe from1024 objects in bounded20000-object
steps,0.5second step settling and final1.25second settling. It then runs the
same seeded warmup+baseline offered-load prefix and records five0.25second
pressure probes at the intended capture boundary, without invoking snapshots.
All attempts, GC state, pressure traces and failures remain in the output.

Freeze only if both predetermined fresh replicas independently fit the band.
Refine retained Record count only from all baseline pressure observations,
never snapshot performance. Rebuild the canonical recipe from zero for every
new candidate. Excess residency variance, invalid baseline load/state or three
unsuccessful candidate rounds mark calibration invalid/unreachable; no retry
until a lucky process appears. The frozen record count, exact FILL recipe and
object shape then match every A/B/C group. An independent SHA-256 oracle
verifies the ordered key/size/payload digest in every group. No FILL adjustment occurs during measured load or capture. Warmup,
seeded request distribution, rate, duration, limit and runtime tuning match.
Each group must independently remain within the configured pressure band at the
capture boundary; drift and temporary growth remain visible in raw samples.

The 95% level is opt-in, requires successful paired 90% preflight trials and VM
headroom, and retains allocation/OOM failures. An optional future ramp-to-OOM
experiment must separately compare time and allocated bytes to OOM and identify
cgroup and victim. It is not implemented by these plateau trials. Five no-OOM
runs do not establish the absence of OOM risk.

## Concrete interfaces and implementation checklist

- [x] workloads/resident/main.go, ResidentKV.java, python_kv.py: HTTP /fill POST,
  /stats GET and seeded /op GET; real retained objects, fixed churn and GC stats.
- [x] workloads/resident_protocol.py: independent seed/operation/key/payload
  oracle, shared only by the client and controller; no arbitrary tool commands.
- [x] workloads/resident_kv.py: single-container launch, bounded grow-only FILL,
  plateau calibration, frozen plans, object/profile/operation verification.
- [x] workloads/performance_load.py and load_controller.py: typed resident jobs
  on the existing authenticated destination allowlist, bounded queues/leases,
  cancellation, intended-arrival timestamps and SHA-verified raw transfer.
- [x] workloads/snapshot_cost/main.go: persistent test driver of unchanged
  production collector/WorkerManager and bounded JSON write+fsync.
- [x] adapters/huatuo/resident_performance.py: A/B/C scheduling, frozen pressure,
  capture validation, independent comparisons, failed/partial/truncated output.
- [x] environments/performance.py: business, Agent/helper/worker scopes, VM
  samples and parent/reaped-child CPU. v1 memory usage/limit/lifetime peak,
  failcnt and oom_control differ from v2 current/max/peak/events. Unsupported
  counters and cgroup PSI remain null, not invented zero. Current orchestration
  requires cgroup v1; counter parsing also understands v2 for future adapters.
- [x] performance.py: resident CLI, deterministic plan, count/limit checks,
  pressure ladder and guarded 95% preflight; default five independent repeats.
- [x] Existing test files: RED/GREEN contract, resource/clock/lease/control checks,
  exact fill replay and canonical ordinal phase partition despite clock mapping.
- [ ] Short actual VM validation: each Go/Java/Python A/B/C first60%, then90%.
- [ ] make check, scoped signed-off commits and review before formal execution.

Example short command (repeat for each resident-language):

```sh
python3 integration/fault_isolation_framework/performance.py \
  --business resident --resident-language go \
  --module memory_threshold_snapshot --build /data/build --bpf-dir /data/bpf \
  --resident-go /data/resident-go --snapshot-helper /data/snapshot-cost \
  --memory-limit-mib 768 --business-cpus 4 --pressure-levels 60,90 \
  --load-controller-url http://LOAD:19890 --load-token-file /data/token \
  --repeats 1 --warmup 4 --baseline 5 --hold 10 --recovery 5 --qps 100 \
  --output /data/resident-go-smoke
```

Formal defaults retain >=5 randomized paired repetitions. A short run cannot
meet a tail sample budget merely by printing percentiles: P99 needs 1000 and
P999 needs 10000 successful samples per reported window. Errors, timeouts,
missing/duplicate arrivals and incorrect bodies invalidate a trial. Capture
failure/unavailability/empty output invalidates C; partial/truncated successful
output retains its exact status. Failed C never scores as cheap full capture.

Resource scope is explicit: business cgroup; separate Agent/helper and bounded
worker-slot memory cgroups; VM/observer parent scope; process CPU including
reaped children. Sampled window peaks differ from cgroup lifetime peaks. RSS
sums shared pages. v1 failcnt counts allocation-limit failures, not OOM kills.
Raw memory.stat/PSI/vmstat disclose reclaim and output page-cache effects.
Host builds can contend with the VMs: correctness smokes disclose that overlap,
and quantitative paired trials must wait for a quiet host.


Capture-boundary pressure currently uses three immediate cgroup reads. These
are a point-in-time band check, not a second timed plateau test. Calibration
uses timed settling; subsequent measured pressure min/max drift remains in the
report, including after C. A longer timed boundary check is deferred rather
than claimed implemented. Helper output is polled only at complete newline
records; shutdown parsing preserves valid rows and malformed raw tails, marks
protocol failure, and cannot bypass owned-resource cleanup or summary saving.
