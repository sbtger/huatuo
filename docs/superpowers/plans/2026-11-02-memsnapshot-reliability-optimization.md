# Memsnapshot Reliability Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove demonstrated FD accumulation, diagnose RSS growth, and define
the independent collector execution boundary.

**Architecture:** Avoid the leaking process constructor at the memburst caller.
Keep immutable original campaigns and deploy repairs as new builds. Separate
the larger execution-boundary change from resource ownership repair.

**Tech Stack:** Go 1.24.3, real Linux procfs, existing Python fault-isolation harness.

**Spec:** docs/superpowers/specs/2026-11-02-memsnapshot-reliability-optimization-design.md

## Global Constraints

- No changed acceptance budgets, forced GC in acceptance, or overwritten runs.
- Preserve PID/start-time validation and ranking for RSS/shared memory.
- No new unit test files; external procfs behavior belongs in an integration test.
- Generated files read-only; `make check` before commit; signed-off messages <=75 columns.

## Review Focus

- Process exit during enumeration must remain a skipped candidate.
- Unsupported pidfd kernels must not be mistaken for proof of the resource fix.
- RSS/shared metrics must retain descending order and valid process identity.
- Existing resource failures must remain separate from optimized-run outcomes.
- A worker stuck in a syscall must not cause unbounded replacement creation.

### Task 1: PID enumeration repair

**Files:** core/autotracing/memburst_process.go;
core/autotracing/memburst_process_integration_test.go.

**Interfaces:** `topMemoryProcesses(int, memoryType) ([]*processMemInfo, error)`
remains unchanged.

- [x] Add real-procfs regression: GC disabled, enumerate both memory metrics
  repeatedly, assert no new pidfds; verify ranked identities and descending values.
- [x] Run against original code and retain the expected pidfd-growth failure.
- [x] Use `process.Pids()` and construct metric readers directly, preserving
  both existing identity checks. Do not patch vendor.
- [x] Run targeted integration tests and existing autotracing tests; build a
  separately named Agent. Run the unmodified memburst campaign after original queue.
- [x] Run required project checks; review and commit one logical repair.

### Task 2: RSS evidence and diagnosis

**Files:** diagnostic scripts/artifacts outside shipping code; update
integration/fault_isolation_framework/RELIABILITY_DIAGNOSIS.md.

**Interfaces:** read-only `/proc/PID`, existing metrics and pprof endpoints.

- [x] Record same-Agent heap/profile and RSS snapshots without forced GC.
- [x] Compare live heap, reserved/released memory and repeated-capture growth.
- [x] Report confirmed allocations or explicitly retain an unresolved finding;
  use an isolated diagnostic run if GC/reclamation must be tested.

### Task 2a: Repair pressure-control publication

**Files:** core/util.py, pressure-control writers in the example adapter/workloads,
and existing test_core.py.

- [x] Confirm the threshold steady timeout has Python pressure-thread ValueError
  on an empty control file and unchanged low memory use, rather than infer an
  Agent read failure from the timeout alone.
- [x] RED: existing readers must retain the old complete control value; failed
  replacement must preserve the value and remove temporary files.
- [x] GREEN: publish control values by same-directory atomic rename, use it at
  every target_mb writer; 105 framework controls pass locally.
- [x] Use a new isolated producer snapshot for reruns, preserving original100.

### Task 3: Independent capture execution design

**Files:** docs/superpowers/specs/2026-11-02-memsnapshot-worker-isolation-design.md.

**Interfaces:** current collector request/result and both trigger lifecycles.

- [x] Ground a concrete worker protocol and bounded lifecycle in existing code.
- [x] Specify timeout, resource ownership, target identity, failure publication,
  cooldown and stuck-worker capacity behavior, plus executable acceptance cases.
- [x] Review design before changing production execution architecture.

## Execution outcome

Both repairs pass their controls and VM follow-ups. Original22 runs:13 PASS,
9 FAIL; the original same-Agent memburst check passed20 rounds/1800.002seconds.
The original threshold steady attempt failed from a confirmed pressure-writer
race and has only a short repaired smoke rerun, not a replacement30-minute PASS.
Five producer105 follow-ups pass; the matched original-Agent panic control also
passes this repetition, so the FD peak failure is correctly treated as intermittent.
Fullmakeunit retains two independently reproduced baseline failures; no acceptance
budget was relaxed. Worker process isolation remains a reviewed proposal, not an
implemented repair; the original cross-target delay/block failures remain open.
