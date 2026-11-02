# Memory snapshot worker isolation

The Agent executes runtime memory snapshots in the separately packaged
`huatuo-memsnapshot-worker`. Both `memburst` and `memory_threshold_snapshot`
use this collector. Runtime detection, provider reads, symbol parsing and
process-memory fallback run in the helper, which exits after one request.
Discovery, trigger policy, RSS ranking and persistence remain in the Agent.
The business process is read externally; collection does not attach a runtime
agent, stop it or inject code.

## Installation and compatibility

The normal Makefile command discovery builds the helper in `_output/bin/`.
Docker and RPM packaging copy that directory. Install the matching helper next
to the other binaries in the Agent's existing `--tools-bin-dir` directory.
The helper is an internal executable, not an interactive tracing CLI.

The Agent requires a writable memory-controller cgroup subtree visible in its
mount namespace. It uses `huatuo-memsnapshot-worker` under the memory mount for
v1, or under the unified mount for v2. The root has two leaf groups, `0` and `1`.
Agents sharing that subtree share a cgroup-inode flock, including across mount
namespaces that refer to the same inode. Deployments must expose the same owned
host subtree to instances that are intended to share a node-wide budget.
The Agent does not enable controllers in a foreign parent or move businesses.

Missing/unexecutable helpers, incompatible protocol, unavailable containment,
foreign tasks or unexpected descendant cgroups fail capture explicitly. They
do not silently fall back to in-process provider execution. Startup logs the
setup failure while the rest of the Agent can continue. Correct the installation
or cgroup delegation and restart the Agent after a setup failure.

Do not put other processes or child cgroups inside the reserved worker subtree.
Ownership checks reject foreign executables even when their argument list
contains the helper's path. Exact configured scripts and the constrained
pre-exec launcher are recognized; arbitrary argv matches are insufficient.

## Budgets and lifecycle

| Resource | Bound |
|---|---|
| Slots in one shared owned subtree | 2, including unreaped workers |
| Hard memory | 256 MiB/slot, 512 MiB/subtree |
| Go soft memory target | 192 MiB/helper |
| Open files | 128/helper |
| Encoded request | 4 KiB |
| Encoded reply | 1 MiB; snapshot retains its existing 512 KiB limit |
| Forwarded helper stderr | 64 KiB/helper; excess is drained and discarded |

On v2, swap is disabled for the subtree and slots. On v1, combined memory
and swap is capped at the same value when memsw accounting is available.
A v1 kernel without memsw accounting does not establish a separate swap bound.

A minimal shell joins the slot cgroup and sets the descriptor limit before
executing the Go helper. The end-to-end capture deadline includes admission,
startup, request transfer, provider work, response parsing and child completion.
Each memburst target gets its own budget, subject to the trigger's parent context.
The existing ranking, maximum three records, event format and cooldown remain.

On timeout/cancellation, the caller stops waiting, closes its response pipe and
signals its worker. A slot is reusable only after `Wait` and IO cleanup finish.
A timed-out manager close retains the shared lease until cleanup completes;
a new manager cannot multiply pending parent goroutines or descriptors merely
because a child has already disappeared from its cgroup.

Stable cgroups remain across Agent restarts. Startup validates the existing
subtree, refuses foreign contents and reconciles known residual helpers. A
populated slot does not become replacement capacity. Two stuck slots produce
explicit busy/unavailable results rather than unbounded replacement children.

A timeout result may have language `unknown` and omit `process_memory` when the
helper could not return validated data. Missing data is not reported as zero.
The parent does not perform a new synchronous procfs fallback after its deadline.
Existing process/container identity checks remain before persistence. Start-time
identity detects PID reuse, not exec inside the same process lifetime.

## What the boundary establishes

A worker panic, abnormal exit or blocking reader can fail collection while the
Agent remains available to serve other targets. The validation suite checks
business responses, committed state, Agent lifetime and later healthy captures.
Container retirement can cancel the worker before a paused syscall resumes;
that path must not claim an ESRCH read. Direct read-after-exit is tested separately.

SIGKILL does not guarantee immediate termination of a real uninterruptible
kernel task. Such a helper remains charged to its slot and hard memory budget.
The current injected block is a simulated non-returning reader, not a reproduced
kernel D-state hang. Shared CPU/IO contention and system-wide exhaustion remain
separate performance/reliability experiments.

## Validation entry points

In an isolated root Linux VM with the relevant memory controller:

```sh
HUATUO_MEMSNAP_WORKER_CGROUP_PARENT=/sys/fs/cgroup/memory \
HUATUO_MEMSNAP_WORKER_BINARY="$PWD/_output/bin/huatuo-memsnapshot-worker" \
go test -tags integration ./internal/memsnapshot/collector -run TestWorker
```

For v2, point the cgroup parent at the delegated unified hierarchy. The tests
create and remove uniquely named owned subtrees. The direct ESRCH test additionally
accepts `HUATUO_MEMSNAP_FAULT_WORKER_BINARY` and
`HUATUO_MEMSNAP_BUSINESS_BINARY` from the fault-isolation build.

The real-Agent suite builds independently hashed plain and fault helpers and
publishes them atomically between Agent lifetimes. Fault binaries are test-only.
Its worker evidence binds PID/start time, request ID, raw start/reap logs,
pressure request, actual failed event and later same-Agent healthy capture.
Resource gates count sampled Agent-plus-worker RSS, FDs, threads and watches;
parent values remain available separately. An exiting/execing child may have no
sampleable memory view; its PID and reason are retained as unavailable, without
replacing it with zero or discarding the parent sample. Missing Agent metrics
remain a failure. Reaped-worker debug records retain
completed child CPU time. Sampling is not an exact instantaneous memory peak.

See `integration/fault_isolation_framework/` for the reproducible campaigns and
recorded validation. These reliability checks do not establish zero production
overhead or a 72-hour soak result.
