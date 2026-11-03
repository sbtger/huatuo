# Real-application snapshot B/C experiment

This is the active plan. The earlier stdlib resident-KV experiment and native
Kafka/mitmproxy matrices remain historical evidence. They are not primary app
acceptance. Run only one 4 CPU / 4 GiB business container on the 8 GiB DUT.

## Applications and shared HTTP cache contract

Go: official etcd3.6.5. Retain unmodified official benchmark PUT/GET as a native
capacity/reference witness. Timed mixed load uses a small fixed-arrival Go
client built with pinned official clientv3 SDK3.6.5. Its per-request timings are
real SDK-driver observations, not reconstructed official-tool histograms.
Keep RSS anonymous/file/cache, Go heap and published-profile evidence separate;
actual cgroup pressure from real KV/cache is a valid service profile. Report
anonymous/cache/Go-live-heap separately and never call cgroup90% Go-heap90%.
Mark unreachable only when real KV cannot safely stabilize the requested
cgroup band. No external filler or relabeling mmap cache as Go heap.

Java: Spring Boot3.4.5 / embedded Tomcat / Java17, in-memory ConcurrentHashMap
with striped/per-key synchronization. Python: FastAPI0.115.12 / Uvicorn0.34.2 /
CPython3.12, one serving worker owns the tracked Record/nested-container graph.
Spring uses32Tomcat threads. FastAPI uses async request concurrency in one
Uvicorn event loop; normal CPython GIL constraints remain, not CPU parallelism. No global lock
covers cache operations. Normal GC and explicit matching JVM heap profile stay
identical in B/C; no forced GC, pre-touch, injection or heap dump.

Protocol version cache-v1, shared by those two HTTP cache applications:

- POST /fill?records=N&seed=S: bounded grow-only1024..1000000 retained records;
  only premeasurement. POST /freeze rejects subsequent FILL changes.
- GET /stats: cheap counts/runtime/live count/value bytes/inflight/GC/heap and
  tracked-object samples. GET /stats?verify=1 computes ordered live payload SHA
  outside timed serving; never do a full digest on cheap telemetry polls.
- GET/PUT/DELETE /cache/{key}?ordinal=N&seed=S return full actual value bytes,
  never just an echoed hash. PUT receives the exact payload body. DELETE means
  DELETE_REPLACE (eviction/rebuild): remove and repopulate the same key under a
  per-key/striped lock, returning the actual removed value. It is not ordinary
  permanently-deleting traffic. Live object count and payload sizes stay bounded.
- Response headers: X-Bench-Ordinal, X-Bench-Operation (GET/SET/DELETE),
  X-Bench-Key. Record/read/verify bodies independently on every response.
- Payload byte97+key%26 repeated65536 bytes when key%10==0, otherwise1024 bytes.
- Seeded operation/key recipe: m=((ordinal+seed)*1103515245+12345)&0x7fffffff;
  m%100<70 is GET, <90 SET, otherwise DELETE. selector=(m//100)%100;
  r=(m*48271)%2147483647; hotN=max(1,min(records-1,ceil(records*.2)));
  key=r%hotN for selector<80, otherwise hotN+r%(records-hotN). This offers80%
  traffic to20% of keys while exercising the entire working set, not first1024.
- Only APP_DIAGNOSTIC=1 permits delay_ms20: apply20ms on ordinal%20==0 (5%).
  Primary B/C reject any nonzero diagnostic delay. The diagnostic is separately
  labeled, never an artificial positive snapshot cost.

## Load, capacity and measurement scope

Use pinned wrk2 with a small documented instrumentation patch: unchanged native
pacing/HDR logic, expose its own expected/sent/response timestamps to the fixed
Lua body oracle, add bounded per-phase/per-endpoint HDR and five-second windows.
Retain every full response check, exact histogram counts and full raw rows around
planned capture±timeout margin plus every error. Do not synthesize request rows
from aggregate histograms. Disclose HDR precision, coverage, transport failures
and any trace-budget overflow. Native wrk2 uses wall time: retain wall/monotonic
anchors and reject jumps beyond the clock bound.

Use a finite B-only rate ladder, >=60s measured phase windows, same mixed recipe
as C, one owned fixed store per pressure for the finite ladder (GC/JIT/MVCC state
and maintenance retained); chosen normal/high rates get independent fresh B
validation. Actual paired B/C use fresh identical frozen layout recipes. A tested stable rate needs actual/offered
throughput agreement, zero errors/timeouts/body mismatches, stable tail/backlog,
load-host headroom, business CPU quota/throttling and GC observations. If the
pacer/client is the bound, report CLIENT_LIMITED, not application capacity.
After the first stable/unstable bracket, run at most six actual B binary
refinements until unstable/stable<=1.06. Freeze the highest actually tested
stable point, never an interpolated maximum. A stable ladder ceiling or
CLIENT_LIMITED result is CAPACITY_NOT_BRACKETED. Use128fixed connections and
min(4,connections) native HTTP threads; client CPU headroom uses effective
generator parallelism. These are capacity estimates at that fixed client
geometry, not a universal application maximum. Freeze55% of the stable point
for normal load and80% for high load. The estimated fraction interval assumes
single-round monotonic stability; the first unstable point may be transient.
Retain this uncertainty and high-band NOT_COVERED if the interval misses75–85%. No C result selects
pressure, records, rate or runtime profile.

First one-round B/C scenarios only:60% memory/normal load;90% memory/normal load;
90% memory/high load.95% requires separate bounded preflight and stays deferred.
Both groups run the same real Agent with all automatic snapshot triggers
excluded and a persistent production WorkerManager helper. B keeps it idle;
C requests ONE unchanged production worker/provider snapshot and explicitly
bounded result JSON serialization plus test-owned disk write/fsync. A is an
optional diagnostic, not the primary comparison. Failed/partial/truncated and
unavailable captures remain visible; never score an empty failed capture cheap.

Actual snapshots can last25ms. Report their real timestamp overlap, request
count/max and clock resolution; P99/P999 remain null when too sparse. Phase
windows >=60s are distinct from actual collector intervals. Per-endpoint report
QPS/P95/P99/max/error/timeout/correctness, scheduled-arrival latency, throughput
vs goal, backlog, GC/CPU/throttle, business and disjoint collector memory peaks.
Every complete single pair is DESCRIPTIVE_ONE_PAIR, with raw B/C, signed delta
and percent (null when B is zero/missing). A positive or negative delta alone
proves neither attribution nor improvement. NO_DETECTABLE_DIFFERENCE requires
a defined resolution/noise criterion; no such significance test is claimed here.

Run separate diagnostic controls only at normal60% memory (diagnostic-only
never enters90% or the primary B/C queue): known20ms delay on5% of
requests, and a known bounded memory increment in a separately labeled harness
scope. Prove the observer detects them. HTTP waits occur in app diagnostic serving; SDK controls use a real client
worker wait, explicitly not server latency. They do not run in actual C and do
not force snapshot deltas positive. Keep all invalid attempts and baseline choices.

## Files and implementation checklist

- workloads/applications/{spring-cache,fastapi_cache.py}: real framework apps.
- workloads/application_protocol.py: independent payload, operation/key oracle.
- workloads/applications/etcd_load: pinned native clientv3 fixed-arrival driver.
- workloads/applications/{instrument_wrk2.py,bench_metrics.h,cache.lua}: source
  pinned wrk2 measurement hooks, bounded HDR and real request capture windows.
- workloads/application_tools.py + load_controller.py: typed allowlisted native
  jobs, lease cancellation, process groups, bounded output and verified ACK.
- workloads/application_workloads.py: genuine apps, frozen pressure/heap proof.
- adapters/huatuo/application_performance.py + application_performance.py:
  finite B-only capacity bracket, frozen B/C scenarios, diagnostics and reports.
- Existing test_business/test_resources/test_cli files: RED/GREEN controls;
  make check before each signed-off commit. No new unit test files.

No five-round queue or formal acceptance launch is authorized by this plan.
Short actual validation first checks60% per app, then90% only after B calibration
is valid. Shared physical-host reliability soaks and VM clock/client limits are
recorded. Runtime/tool versions, source archives, patches, dependency hashes,
commands, invalid outputs and all raw data remain separate and immutable.

Primary references: [etcd maintenance](https://etcd.io/docs/v3.6/op-guide/maintenance/), [etcd v3 API](https://etcd.io/docs/v3.6/dev-guide/interacting_v3/), [pinned wrk2 source](https://github.com/giltene/wrk2/tree/44a94c17d8e6a0bac8559b53da76848e430cb7a7).


## Bounded state and evidence lifecycle

etcd uses one new UUID-owned runtime DB on the data disk, separate from the
source/evidence directory. Require9GiB free before creation for the8GiB backend
quota plus reserve. Verify ownership marker, final logical readback and container
stop before successful-state teardown. Failed states remain with their marker;
failed calibration/campaign stops rather than deleting failures to regain space.
Expected rate-limit probes remain source evidence while a healthy shared store
is bracketed; protocol/pressure/ownership failures stop it. No deletion follows
campaign sealing. Record SDK maintenance every5s with revision retention1000,
DB/in-use bytes, revision, duration/error; maintenance CPU belongs to the whole
client CPU scope and has no invented per-maintenance CPU measurement. No
concurrent server auto-compactor or forced defragmentation is enabled.

Large histograms are verified artifacts, not the bounded HTTP status JSON.
ACK follows verified DUT copies even when later parse/state validation fails.
Only64 recent ACK metadata entries remain; active and unacknowledged jobs remain.
The512MiB output budget and1GiB free-space admission guard bound load-host state;
overflow is a failed measurement, never a reason to quietly reduce offered rate.
All request counts enter histograms. Full rows cover the configured capture
margin plus every error; missing interval coverage makes actual-window tails null.

## Current implementation and verification checkpoint

Implemented: real app plugins; native SDK GET/PUT; official benchmark reference
hook; instrumented wrk2 exact-integer request oracle; typed bounded jobs and
verified transfer/retention; B-only pressure/capacity controls; one-round B/C and
separate diagnostic route; per-endpoint tails, errors, runtime GC/throttling,
phase/actual-interval memory/CPU and readable tables. Java bounded GC logs expose
pause wall durations; MXBean collection walltime and unsupported GC CPU remain
separate. Python callbacks aggregate bounded GC wall/collecting-thread CPU.

Verified before quantitative runs: real Spring and FastAPI external HTTP
contracts (initial failures retained); pinned LuaJIT oracle including ordinal
30million; native tool20s correctness; private1024-record real Agent/helper/
production-worker captures for all3apps. Private source05ad66665333 returned Go
complete7entries, FastAPI complete7entries, Java partial7entries with explicit
32MiB bounded HotSpot coverage. Those tests used the disclosed previous frozen
Agent/helper build and prove integration only, not performance acceptance.

Pending actual validation: known-delay/known-memory sensitivity under the frozen
native controller; independent B capacity/pressure calibration; one real B/C
pair per scenario, first FastAPI normal60 then sequential apps/90 only after
valid preflight. Fresh source/build identity and full checks precede the final
logical commit. No5round/95% run or universal SLO acceptance is implemented or
claimed. Optional OOM ramps and statistical significance remain future scope.

## Public rebuild and one-round entry points

From the repository root on Linux with Go1.24, JDK17, Maven3.9.9, CPython3.12,
GCC/make/zlib development headers (wrk2 builds its bundled dependencies):

```sh
F=integration/fault_isolation_framework
TOOLS="$PWD/application-tools"
mkdir -p "$TOOLS"
git clone https://github.com/giltene/wrk2.git "$TOOLS/wrk2-upstream"
git -C "$TOOLS/wrk2-upstream" checkout 44a94c17d8e6a0bac8559b53da76848e430cb7a7
python3 "$F/workloads/applications/instrument_wrk2.py" \
  --source "$TOOLS/wrk2-upstream" --output "$TOOLS/wrk2-measured"
make -C "$TOOLS/wrk2-measured" -j4
(cd "$F/workloads/applications/etcd_load" && go mod verify && \
  go vet ./... && go build -o "$TOOLS/etcd-load-tool" .)
(cd "$F/workloads/applications/spring-cache" && mvn -B -DskipTests package)
python3.12 -m venv "$TOOLS/fastapi"
"$TOOLS/fastapi/bin/pip" install --require-hashes \
  -r "$F/workloads/applications/fastapi-requirements.txt"
```

Obtain etcd3.6.5 binaries and official benchmark from the pinned etcd release/
source and retain release archive SHA plus `etcd --version`, `benchmark --help`
and Go build-info. Copy the resulting artifacts and app JAR into the explicit
application-tools layout (`etcd/etcd`, `etcd-load-tool`,
`spring-cache/target/spring-cache-1.0.0.jar`, `fastapi/bin/python`). Record every
source/patch/binary/dependency hash; `measurement-build-proof.json` identifies
the instrumented wrk2 build. This is not claimed to be a stock wrk2 binary.

The external controller accepts only fixed typed recipes, not shell commands.
Example local operator-owned tool configuration on the load host:

```json
{
  "benchmark": "/opt/application-tools/benchmark",
  "wrk2_measured": "/opt/application-tools/wrk2-measured/wrk",
  "cache_lua": "/opt/source/integration/fault_isolation_framework/workloads/applications/cache.lua",
  "cache_recipe": "/opt/source/integration/fault_isolation_framework/workloads/applications/cache_recipe.lua",
  "etcd_sdk": "/opt/application-tools/etcd-load-tool",
  "wrk2_build_proof": "/opt/application-tools/wrk2-measured/measurement-build-proof.json"
}
```

Start the external controller with a random mode0600 token file (never put the
secret into argv/output), restricted target host and forwarded port range:

```sh
python3 "$F/load_controller.py" --token-file /secure/load-token \
  --output /data/load-owned --target-host 10.0.2.2 \
  --port-start 40000 --port-count 64 --native-tools /opt/tools.json
```

On the isolated DUT, use a verified plain Agent build manifest, unchanged worker
and a test helper built from the same production collector/WorkerManager source:

```sh
go build -mod=vendor -o "$TOOLS/snapshot-cost" "./$F/workloads/snapshot_cost"
python3 "$F/application_performance.py" --application fastapi \
  --output /data/results/diagnostic-unique --diagnostic-only \
  --build /opt/verified-agent-build --bpf-dir /opt/verified-bpf \
  --snapshot-helper "$TOOLS/snapshot-cost" --application-tools "$TOOLS" \
  --load-controller-url http://10.0.2.2:39990 \
  --load-token-file /secure/load-token
python3 "$F/application_performance.py" --application fastapi \
  --scenario normal60 --output /data/results/one-round-unique \
  --build /opt/verified-agent-build --bpf-dir /opt/verified-bpf \
  --snapshot-helper "$TOOLS/snapshot-cost" --application-tools "$TOOLS" \
  --load-controller-url http://10.0.2.2:39990 \
  --load-token-file /secure/load-token
```

Use `--plan` to inspect geometry without creating outputs. `--application spring`
or `etcd` selects the other real product; default `--scenario all` schedules only
one B/C pair for normal60, normal90 and high90, sequentially. Diagnostic-only is
restricted to60 and never invokes C. Frozen B plans are reusable only when the
exact application/runtime/source/seed/client/profile identity matches. No retry
turns an invalid trial into success. Inspect `analysis.json`, `REPORT.md`, raw
trial summaries, tool artifacts and integrity audit together.


Review corrections: HTTP five-second windows use intended scheduled arrival,
matching the SDK and phase membership even when completion crosses a boundary.
The pinned SDK uses `MaxUnaryRetries=1` (one invoker loop in3.6.5) and
`grpc.WithDisableRetry()` to disable configured service-policy retries.
Transparent transport retries remain possible per [gRPC1.71.1 API](https://pkg.go.dev/google.golang.org/grpc@v1.71.1#WithDisableRetry).
Latency/count/error scope is one logical SDK invocation; wire attempts are not
measured and are null, never claimed to be one wire RPC. The effective policy is
available through `etcd-load-tool --mode=config --endpoint=http://127.0.0.1:1`.
