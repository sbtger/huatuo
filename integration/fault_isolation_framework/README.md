# Fault isolation test framework

This suite asks a bounded question: **do Go, HotSpot and CPython applications
continue producing correct results and retaining committed state while HuaTuo's
memory snapshot collection fails?** It exercises the real `huatuo-bamai` daemon:
container discovery, native cgroup threshold notification, process selection,
runtime provider, snapshot normalization and local event storage. It extends the
existing provider/lifecycle integration tests and the earlier business stability
fixtures. It is an opt-in acceptance suite for a disposable VM, not a benchmark.

The **framework core is feature-neutral**: it executes declared scenarios,
observes independent businesses and audits complete raw evidence. Linux/Docker
environment helpers and the example HTTP business probe are separate modules.
The first maintained real adapter is `huatuo.memsnapshot`; its configuration,
discovery, trigger, overlay, snapshot assertions and retry/log policies live
under `adapters/huatuo/`. See [Architecture](ARCHITECTURE.md)
and the [recorded validation](VALIDATION.md).

A PASS establishes the assertions below for the recorded runtime, kernel, build,
traffic and fault window. It does not prove every exception path, every runtime
version, production availability, or an absence of performance overhead.

## Running

Requirements: Python 3.8+ for the test controller; dedicated root Linux/amd64 VM,
Docker with cgroup v1 and no running
HuaTuo daemon, CPython 3.12 supported by the provider, HotSpot JDK 17 with `javac`,
Go toolchain compatible with `go.mod`, C compiler, and the repository's normal
build prerequisites. The runner currently rejects cgroup v2 rather than reporting
it as covered. Existing cgroup-v2 functional tests remain separate coverage.

Build the repository's generated dependencies and BPF objects using its standard
build process first. Run from a prepared checkout:

```sh
python3 integration/fault_isolation_framework/build.py \
  --repo . --output /tmp/memsnapshot-isolation-build
python3 -m unittest discover -s integration/fault_isolation_framework -p 'test_*.py'
```

Run as root **inside the dedicated VM**. The output directory must be new:

```sh
python3 integration/fault_isolation_framework/run.py \
  --adapter huatuo.memsnapshot \
  --build /tmp/memsnapshot-isolation-build \
  --bpf-dir "$PWD/_output/bpf" \
  --output /tmp/memsnapshot-isolation-results \
  --java-home /usr/lib/jvm/java-17-openjdk-amd64 \
  --python /usr/bin/python3
python3 integration/fault_isolation_framework/audit.py \
  /tmp/memsnapshot-isolation-results
```

An amd64 Linux builder may build the Agent and Go fixture separately and transfer
`agent`, `agent-fault`, `business-go`, `deny-readv` and `build.json`, the BPF objects,
and this directory to the VM. The audit can be repeated on copied evidence.
New schema-v2 runs record a full
phase plan, artifact registration journal, manifest and file hashes. Missing or
truncated files, changed content, omitted phases and raw/summary accounting
mismatches fail. Feature log policy is mandatory for memsnapshot evidence.
Historical schema-v1 runs remain supported by the adapter's compatibility audit.
The builder creates a plain Agent and a separately hashed test Agent using Go's
`-overlay`. It does **not** edit production or vendor sources. Never distribute
`agent-fault` as a release binary. The overlay uses checked anchors and fails if
the production source has changed; review it before supporting a new version.
The C seccomp launcher must be compiled for the execution VM's architecture/libc.

Default fixed arrival rate is 10 `/work` requests/second per application, plus
one serialized transaction and independent state read every 200ms. This modest
load supplies continuous observations; it is not a capacity or performance test.
`--languages go,java,python` and `--faults` can select a diagnostic subset. The
public reliability report must explicitly list any omitted cases.

## Business assertions

All three applications remain active throughout every target's faults, so two
applications also serve as canaries while the third is being collected.

| Assertion | Independent evidence / failure gate |
| --- | --- |
| Application survives | Host PID + `/proc` start-time ticks stay unchanged; zombie/exit/restart fails |
| Responses remain correct | Every `/work` response must be HTTP 200 with the literal expected SHA-256 body |
| Committed state remains correct | POST sequence `n` adds `13*n`; acknowledgment and a separate GET must both match the controller's sequence and total |
| No hidden state rollback | Transactions continue across normal capture, failed capture, Agent replacement and recovery; the service state is never reset by the runner |
| Background work continues | Independent service tick counter advances, and no observed tick stall exceeds 2s |
| Service makes progress | No HTTP timeout (1s) or gap between successful `/work` responses exceeding 2s, including phase boundaries |
| No load silently disappears | Fixed arrival schedule; scheduler lag above 500ms fails; phase and final scheduled/completed counts must match |
| No late failures omitted | Observers and in-flight requests stop/drain before final all-row checks and log audit; inter-phase errors fail too |
| No accidental OOM | Business cgroup `memory.failcnt` remains unchanged; identities are checked after the final phase |

The 1s/2s bounds are hang-detection limits for this fixture. They are not a
production SLO or evidence of an acceptable latency regression. No CPU, RSS,
throughput regression or percentile comparison is part of acceptance.

Pressure is generated **inside each application's cgroup**, below its 768MiB
limit, with the feature threshold set to 60%. Go/Python use touched mappings;
Java uses touched temporary file mappings that are explicitly unmapped/deleted
on release. This keeps repeated pressure edges reproducible without relying on
malloc retention or changing the application's heap sampling configuration.
The Java test-only pressure helper uses `Unsafe.invokeCleaner`; the Agent remains
read-only with respect to application memory. It does not inject code into the
application or call a heap-dump endpoint.

## Fault matrix

Every row below runs independently against Go, Java and Python. Each fault is
followed by another real threshold capture with nonempty normal runtime entries,
valid selected PID and process RSS fallback. Go normal snapshots must be complete;
Java/Python may report their documented concurrent-runtime partial result.
For the exact CPython failure `CPython interpreter GC generations are invalid`,
normal/recovery phases permit at most three real threshold captures with the
same Agent and unchanged business. Every failed event is preserved in
`normal_attempts`; another failure kind or three failures fails the phase. This
checks eventual recovery after the observed invalid-GC-metadata result, not
universal success of every census. Its root cause has not been conclusively
established; concurrent GC is a hypothesis, and the failed events remain evidence.
Business assertions remain active throughout all attempts.

| Phase / fault | Injection and required witness | Recovery |
| --- | --- | --- |
| Agent off | Business assertions without Agent | Plain Agent normal capture |
| Feature blacklisted | Actual pressure; tracing status absent; no persisted event | Feature enabled normal capture |
| Plain Agent | Uninstrumented daemon emits nonempty normal snapshot | Control |
| Instrumented control | Overlay daemon with no fault armed emits normal snapshot | Faults begin |
| Permission denied | Real seccomp denies `process_vm_readv`; actual syscall returns EPERM; persisted reason identifies permission denial | Restart required (seccomp is irreversible) |
| EFAULT | Target-specific syscall-boundary override; marker + persisted `bad address` reason | Same Agent |
| Short read | Real syscall runs, returned byte count reduced by one; marker + persisted short-read reason | Same Agent |
| Provider panic | Panic inside production collector's recovery boundary; matching PID marker, expected recovery log and failed snapshot reason | Same Agent |
| Cancellation | Provider context canceled after production recovery is installed; marker + failed canceled snapshot | Same Agent |
| Timeout | Remote read delayed 4s beyond 3s snapshot deadline; marker + failed deadline reason | Same Agent |
| Blocked reader | Reader deliberately never returns; entry marker, no event, Agent alive and metrics responsive while business assertions run; Agent then SIGKILLed | New Agent |
| Kill after remote read | Completed real read marker, no event; SIGKILL identity/exit signal verified while business stays running | New Agent |
| Normal restart | Agent SIGTERM exits zero, fresh Agent captures same unchanged business process | Same business; new Agent |
| Storage full | Event filename points to `/dev/full` in a test-owned directory; real ENOSPC from event writer | Fresh Agent and normal storage |
| Invalid config | Threshold 101 is explicitly rejected; business continues | Fresh Agent with valid config |

For short read/EFAULT, a preexisting Java/Python `partial` result cannot count as
a fault witness: the persisted reason must identify the exact injected read
failure. An injection marker alone is insufficient. Unreached faults, empty
observation windows and recovery with empty/unavailable normal entries fail.

`block` is a containment test with supervisor recovery. It does **not** establish
that the production collector can interrupt a blocked syscall or gracefully shut
down in that state. The delay test checks deadline classification after the read
returns; it does not claim the syscall was interrupted at exactly 3 seconds.

## Logs and evidence

Unexpected Agent warn/error/fatal/panic logs fail the audit. Allowances are narrow:
a recovered test panic must match the injected target PID; a storage ENOSPC must
belong to the snapshot writer and a witnessed storage-full phase; invalid threshold
messages must match the deliberate value 101. A generic warning cannot hide behind
a fault marker. Normal recovery is separately proven by its persisted event.

The runner preserves `environment.json`, build hashes, BPF and test source hashes,
exact command line, per-run configs/Agent logs/metrics, per-request JSONL, normal
and failed snapshot events, `summary.json`, `registrations.jsonl`, `manifest.json`, `audit.json` and failure
tracebacks. Artifact names are relative within the output directory.
`summary.json` PASS plus `audit.json` PASS and a zero process exit are required.
Do not overwrite failing trial directories. Publish the full matrix and limits,
not only selected successful phases. Raw evidence may contain host/container
identifiers and stack paths; review those before posting publicly.

Cleanup stops only the suite's process groups, removes its containers and unique
image, and removes a kubelet discovery config only if the suite created it.
The local pod API fixture supplies discovery metadata; this does not test a real
Kubernetes control plane. No global ptrace restriction or disk-full condition is
introduced. Only test-owned event files use `/dev/full`.

## Repository integration

Keep this suite under `integration/fault_isolation_framework`. Its root/Docker/runtime
requirements make it an opt-in VM acceptance job. Adding these files does not
schedule it in CI or replace existing provider and threshold E2Es. Do not execute
it against production workloads. Test outputs and Python caches are ignored in
this directory; choose an output/build directory outside the source tree.

## Relationship to other tests

Existing `test_basic_memsnapshot_provider_live.sh` covers live provider correctness
and failure/lifecycle behavior; the threshold snapshot E2Es cover triggering,
suppression, event schema and lifecycle recovery. This suite adds ongoing business
correctness through actual Agent faults. It is opt-in and is not automatically
added to the existing lightweight CI gates.

Reference patterns include [Memray's attach integration tests](https://github.com/bloomberg/memray/blob/main/tests/integration/test_attach.py),
[py-spy's integration tests](https://github.com/benfred/py-spy/blob/master/tests/integration_test.rs),
and [async-profiler's process test helper](https://github.com/async-profiler/async-profiler/blob/master/test/one/profiler/test/TestProcess.java).
Their examples informed lifecycle and live-target checks; these links do not imply
that those projects prove HuaTuo's business fault isolation. The next, separate
stage may use calibrated open-loop load and baseline comparisons for overhead.
