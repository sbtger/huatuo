# Independent memsnapshot worker design

Status: concrete proposal; not implemented or validated. This is separate from
the PID-enumeration repair. The user selected process isolation as the preferred
direction; the lifecycle and rollout choices below are implementation proposals.

## Problem and guarantee

The existing collector synchronously executes providers behind one global slot.
Context cancellation cannot interrupt a non-returning read. Trigger workers are
also serial, and memburst publishes after collecting the entire ranked batch.
Go symbol parsing additionally allocates large temporary tables in the Agent.

Move runtime detection/provider execution/symbol parsing into a disposable
worker. Bound how long the Agent caller waits and how much worker capacity and
memory the node can retain. A timeout must produce an explicit failed result
without holding the Agent scheduler until the worker exits.

Do not claim that SIGKILL immediately terminates an uninterruptible kernel task.
An unreaped worker continues to consume its resource slot and hard memory budget.
When all slots are occupied, return an explicit busy/unavailable result rather
than starting additional workers. Business availability under host-wide resource
exhaustion remains outside the established guarantee.

## Approaches

1. Bounded goroutines retain in-process allocation/panic/syscall coupling; they
   cannot forcibly terminate a read. Insufficient for the requested boundary.
2. Self-exec the Agent avoids another release artifact but also imports all its
   registration/init dependencies. A special startup path must never initialize
   BPF, storage, the pod manager or a second HTTP server.
3. Dedicated `huatuo-memsnapshot-worker` imports the provider stack only, has a
   small single-request protocol, and exits after each capture. Recommend this
   approach, accepting the additional build/package artifact and version check.

## Interfaces and ownership

Keep `collector.Snapshot(ctx, identity, Options)` and `collector.Result` as the
trigger-facing interface. Factor the existing inline provider path into a
worker-side implementation; the worker must never recursively spawn a worker.
The Agent-side collector owns worker admission, IPC, deadlines, termination and
reaping. Providers continue to consume `memsnapshot.Request` and context.

Resolve the helper from the configured tools directory using an absolute path;
do not search PATH or accept an executable path from an event. Package it with
the Agent in Makefile/container/release installation paths. Missing or mismatched
helpers fail capture explicitly; no silent fallback to the inline path when
process-isolation mode is selected.

Protocol v1 uses inherited private pipes, one request and one response per
process. Request: protocol version, request ID, TGID/start-time identity, top-K,
sampling seed and remaining deadline. Maximum encoded request: 4 KiB. Response:
same version/request ID/process identity, detected language, timestamps,
snapshot and process-memory sample. Maximum envelope: 1 MiB; embedded snapshot
still obeys the existing `MaxSnapshotBytes=512 KiB` and top-K limits. Decode one
JSON value with strict fields, reject extra/truncated/oversized replies, validate
status and identity, and run output normalization again in the Agent.

The worker validates identity before detection, before collection and before
replying. The Agent repeats identity/container validation before persistence.
Revalidate all language-independent memory fallback data too: a reused PID must
not receive the old target's failed capture result. Process start time does not
detect exec; this existing limitation must remain documented.

## Bounded lifecycle

Initial proposed limits: two node-wide slots, at most 128 FDs per worker, at most
256 MiB hard memory per slot, 1 MiB response, 64 KiB diagnostic stderr ring.
These are provisional worker limits that require runtime compatibility testing;
they do not replace or relax current acceptance budgets. A goroutine reading
stdout must stop at the envelope limit and request worker termination.

Queue admission, exec, request transfer, provider execution and response parsing
share one end-to-end deadline derived from the current `SnapshotTimeout` and
parent context. Do not reset the budget at each stage. Retain `WaitForCapture`
semantics only within that remaining budget. Deadline expiry sends termination,
closes caller-owned pipe endpoints and returns a bounded failed snapshot with
valid process-memory fallback when possible. Reuse an already validated sample
or omit fallback if no caller budget remains; a post-timeout synchronous procfs
read must not extend the caller deadline. Parent cancellation returns the
context error, preserving existing event suppression rules.

Exactly one bounded reaper owns each started `exec.Cmd.Wait`. Release a slot only
after confirmed exit/reap, not after sending a signal. Do not append unlimited
wait goroutines, retries or replacement children. An exited worker with a reply
failure still has to be reaped. An unreaped worker is quarantined and consumes
its slot; another healthy target can use the remaining slot. If both are stuck,
captures degrade explicitly while Agent HTTP and event processing continue.

Use dedicated worker cgroups and worker-owned process groups, never a target's
business cgroup or process group. Hard memory containment must be in place
before helper runtime startup: use atomic placement at process creation where
supported, or a minimal launcher that joins the slot cgroup before exec of the
Go helper. A Go-level handshake alone cannot contain allocations made before
`main`. Retain that handshake before target reads; on failure terminate without
collection. Until the launcher/atomic placement is verified on a platform, do
not claim the 256 MiB cap covers startup there. Do not use
`RLIMIT_AS` as a substitute: Go reserves substantial virtual address space.
Inherit only the read privileges required by the Agent; do not add ptrace,
signals, runtime attach or code injection into the business process.

Stable node-owned slot cgroups must also bound residual workers across Agent
restart. Startup reconciles those cgroups under the Agent singleton lock,
verifies ownership, terminates residual helpers and counts occupied slots.
Never recycle a populated slot or delete it as if cleanup succeeded. Parent
death signaling can supplement this, but cannot alone guarantee cleanup for a
D-state task or bound repeated Agent restarts.

If cgroup containment or the helper is unavailable in process mode, fail the
capture and preserve base telemetry. Compatibility is required for supported
cgroup v1/v2 deployments before making this the default shipping mode.

## Trigger behavior

Threshold snapshots retain existing node-wide cooldown in the first iteration.
A failed worker does not bypass rate limits. Log/count cooldown suppression with
bounded reason labels. Healthy-target acceptance must wait from the *actual*
attempt completion plus the configured interval, then generate a new pressure
edge. The existing test's read-active interval contract must be split: a reaped
blocked worker is successful containment, not evidence that its read is still
active. Pending-event retention beyond cooldown is a separate policy change.

Memburst retains ranking and at most three process records. Each record obtains
its own worker deadline, rather than inheriting an already-expired previous
target's batch budget. With the current 2-second budget, the serial implementation
can publish within the sum of those three bounded attempts (plus fixed cleanup
allowance), even if one helper remains unreaped. Preserve already collected
records and encode failures for unsuccessful targets; do not discard a healthy
result merely because a later worker failed. Keep the existing bounded event
format rather than introducing partial event updates in this first iteration.

## Acceptance and rollout

Add protocol/lifecycle cases to existing collector tests and real subprocess
integration tests: success for Go/Java/Python, malformed/oversized reply, no reply,
early exit, provider panic, cancellation, timeout, target exit, wrong start time,
permission denial, missing helper, incompatible protocol and cleanup failure.
Assert the same Agent remains responsive and actual worker identities exit or
remain correctly charged to bounded capacity. A simulated unreaped reaper proves
manager accounting only; do not call it a real kernel D-state test.

The real-Agent fault matrix must assert business responses throughout; for a
blocked Go read, require a failed/terminated worker and a healthy Java/Python
capture on the same Agent after allowed cooldown. Also verify one occupied slot
does not prevent the other slot serving work, both occupied slots reject excess
requests, and restart does not multiply residual workers. Preserve event names,
fields, units, identity checks and fault evidence.

Repeat the same-Agent 20-round/30-minute test under original FD/RSS/watch/thread
budgets. Report parent and child resources separately and their aggregate; low
parent RSS alone is not evidence of lower total footprint. No 72-hour soak or
performance claim follows from these short runs. Ship process mode only after
packaging, permissions, cgroup compatibility and runtime coverage pass; document
the remaining limitations of inline mode during rollout.

## Files expected to change during implementation

- `internal/memsnapshot/collector`: manager/IPC and factored inline worker path.
- `cmd/huatuo-memsnapshot-worker`: dedicated minimal entry point.
- Agent setup: configure the worker path and lifecycle explicitly.
- `core/autotracing/memburst_snapshot.go`: independent target budgets.
- Makefile, container/release packaging: distribute a matching helper.
- Existing collector/trigger tests and subprocess integration tests.
- Fault-isolation adapter: account for worker IDs, exit and bounded residue.

No production execution-boundary code has been changed by this proposal.
