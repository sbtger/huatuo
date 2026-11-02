# Memsnapshot worker isolation implementation plan

> **For agentic workers:** Use superpowers:executing-plans task by task.

**Goal:** Bound failed collection without stopping business or other targets.
**Architecture:** Dedicated disposable provider helper, two stable cgroup slots,
strict bounded IPC and one end-to-end deadline. Keep trigger/event interfaces.
**Tech Stack:** Go, Linux processes, cgroup v1/v2, existing Python E2E framework.
**Spec:** ../specs/2026-11-02-memsnapshot-worker-isolation-design.md

## Global Constraints

- Request 4 KiB; response 1 MiB; snapshot 512 KiB; stderr 64 KiB.
- Two slots, 256 MiB and 128 FDs per helper; retain unreaped capacity.
- No post-timeout synchronous procfs fallback; no silent inline fallback.
- Preserve identity checks, event format, cooldown and original test budgets.
- Existing unit test files only; external process integration tests allowed.
- make check before commits; Signed-off-by and messages <=75 columns.

## Review Focus

- Late, partial or malformed child reply must never be accepted.
- Agent restart must not multiply residual worker capacity.
- Cancellation during startup must release descriptors and reap children.
- Worker OOM must not select a business process as victim.
- Healthy target captures must survive another target timeout.

### Task 1: Bounded subprocess protocol and lifecycle

Files: internal/memsnapshot/collector/worker*.go; collector.go;
cmd/huatuo-memsnapshot-worker/main.go; existing collector_test.go;
external worker integration test.
Produces: WorkerManager.Snapshot, ServeWorker, UseWorker.
- [x] Write/run RED subprocess tests: no reply times out; later capture works;
  malformed/oversized/wrong identity replies fail; canceled child is reaped.
- [x] Factor inline provider path; implement strict protocol, bounded admission,
  kill/reap accounting and absolute helper path. Test production implementation.
- [x] Run collector unit and real subprocess integration tests: PASS.
  Actual provider panic RED exposed stdout log contamination; helper stderr
  logging preserves a valid failed response and process metadata (GREEN).

### Task 2: Resource containment and shipping integration

Files: collector/worker_cgroup_linux.go; cmd/huatuo-bamai setup;
Makefile/build packaging/docs and existing tests.
Consumes Task 1 manager; produces contained shipping helper execution.
- [x] Write/run RED real-cgroup tests: startup containment, caps, occupied slot
  reconciliation, refusal without containment. Unsupported environments SKIP.
- [x] Implement stable owned slots under exclusive lock; minimal shell launcher
  joins cgroup before exec of Go runtime and sets FD cap. Fail capture explicitly
  if setup fails, preserving Agent telemetry. Wire helper into automatic cmd build.
- [x] Verify v1/v2 and package paths; tests PASS or explicit platform limitation.

### Task 3: Trigger deadlines and real-Agent acceptance

Files: core/autotracing/memburst_snapshot.go; existing trigger tests;
fault_isolation_framework adapters/tests/reports.
Consumes contained worker collector; preserves public event schema.
- [x] Verify real helper timeouts and same-Agent Java/Python recovery.
  Use real-Agent acceptance rather than an injected target-deadline unit seam.
- [x] Give each target its own bounded deadline; retain healthy batch records.
- [x] Adapt fault injection to helper; assert worker exits and same Agent survives;
  verify Java/Python after failed Go, honoring actual completion plus cooldown.
- [x] Run Go/Java/Python fault matrix and 20 rounds/30 minutes threshold steady
  on VM2222. Retain business/resource evidence and aggregate child measurements.
- [x] Run project checks, report baseline failures, whole-branch review, commit
  focused changes and push existing authorized feature branch.

## Recorded outcome

Final six-mode matrices: memburst 102 cases, threshold 108 cases, both PASS.
Threshold 20 rounds on one shipping Agent lasted 1800.005 seconds; its full
campaign passed. Final cross-target/exit checks with churn=5 passed for both
modules. All five final campaigns: 263 cases, 137775 work requests, all business
and artifact audits PASS. Native v1/v2: 15 top-level tests each with race, no skip.

One earlier limit-change timeout remains unexplained despite later passes.
The public result is PARTIAL rather than an all-exception-path claim. See
integration/fault_isolation_framework/WORKER_VALIDATION.md for exact provenance,
retained failures, offline replay compatibility repair and unverified scope.
