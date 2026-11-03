# Native business snapshot-cost experiments

The selected workloads are etcd 3.6.5 (Go 1.24), Kafka 3.9.1 (HotSpot 17),
and mitmproxy 11.0.2 (CPython 3.12). Existing fixture results remain historical
framework validation. They are not real-business acceptance evidence.

The primary experiment measures memory snapshot collection itself. Both B and
D run the real Agent with snapshot triggers disabled, plus an identical idle
persistent test helper. Only D sends bounded capture requests to that helper.
The helper calls the unchanged production `collector.Snapshot` with the
production `WorkerManager` and plain shipping worker executable. This includes
worker startup, IPC, provider scanning, output limiting and reaping. It excludes
daemon trigger detection, RSS ranking and event persistence. It introduces no
production endpoint, target injection, heap dump or GC setting change.

Each fresh group has the same initial data size, real flow retention, container
limit, runtime settings and native offered load. Data is seeded before measured
load; no pressure change coincides with D's snapshots. Default seed size is
32 MiB per product. The seed is native etcd KV data, Kafka messages/log cache,
or completed mitmproxy HTTP flows retained by a bounded addon. Every observed
cgroup usage and target identity remains in the evidence. Resource sampling
includes helper and children; helper self plus waited-child CPU is reported
separately from Agent CPU. Simultaneous sampled tree RSS is not unique memory
or an exact peak. Fixed offered load is identical within each B/D pair.

Implementation sequence:

1. Add fixed recipes for official etcd benchmark PUT/GET, Kafka producer and
   consumer performance tools, and pinned wrk2 with per-response body checking.
   Keep native histograms separate from fixed-arrival HTTP request rows.
2. Extend the existing authenticated, destination-allowlisted controller with
   bounded typed native jobs, process-group cancellation and lease expiry.
   Preserve tool stdout/stderr, child CPU/RSS and SHA-verified artifact transfer.
3. Add independent native workload plugins, persistent collector helper, B/D
   orchestration and rate steps. Reuse Docker ownership, discovery, Agent
   configuration, resource sampling, raw sealing and paired reporting.
4. Extend existing test files, run controls and make check. Run short native
   business smokes and validate actual nonempty successful provider output.
   Preserve every failure in a fresh directory. Formal execution follows review
   and a clean frozen build, with workload-specific SLOs supplied explicitly.

Default rate steps are 100 and 200 operations/records/requests per second.
Warmup is 60 seconds; baseline, capture and recovery jobs are 30 seconds each.
Native jobs have >=20 second windows because wrk2 calibrates for ten seconds.
Snapshots begin 12 seconds into the capture job, default one snapshot. Multiple
snapshots are explicit and must fit the configured window and timeout. Native
jobs may contain consecutive tool stages; timestamps retain their real duration.
No aggregate is split into invented per-request rows or subwindow percentiles.

Metrics and correctness:

- etcd: official benchmark PUT/GET ops/s and RPC P95/P99/errors. PUT uses 256B
  crypto-random values. Its tool has no seed/payload flag; random input bytes
  differ between groups while keyspace, size, distribution, initial data and
  rate match. A separate deterministic CRUD prefix is read back exactly.
  Benchmark key cardinality and value lengths/revisions are checked separately;
  random benchmark values are not falsely claimed known-input verified.
- Kafka: official producer records/s, MB/s and ack P95/P99/errors; official
  consumer throughput; independent complete consumer readback verifies monotonic
  IDs, count, order and SHA. Producer retries are zero. Monotonic payloads are
  variable-length decimal IDs, not fixed 1 KiB records. Readback reaching the
  acknowledged end proves its lag zero at that boundary; consumer group lag
  needs its own committed-offset witness and must not be inferred from that.
- mitmproxy: wrk2 constant offered RPS, corrected latency P95/P99, socket errors,
  status errors and timeouts. Lua verifies every completed response body. The
  real reverse proxy retains completed /large flows; the separate origin is
  not selected for snapshots. The idle neighbor is independently read/identity
  checked and must remain uncollected.

Only complete matched B/D pairs with correct business state and actual D
captures contribute paired deltas. Failed, unavailable, empty or wrong-provider
snapshots invalidate the cell. No retry hides the first capture failure.
Capacity is the highest TESTED rate meeting the explicitly configured P99 SLO
in every repeat, with zero business errors and valid captures. It is not an
interpolated maximum. No universal overhead or acceptance budget is installed.

Official references: [etcd source](https://github.com/etcd-io/etcd/tree/v3.6.5/tools/benchmark),
[Kafka tools](https://github.com/apache/kafka/tree/3.9.1/tools/src/main/java/org/apache/kafka/tools),
[mitmproxy options](https://docs.mitmproxy.org/stable/concepts/options/),
[wrk2](https://github.com/giltene/wrk2/tree/44a94c17d8e6a0bac8559b53da76848e430cb7a7).
