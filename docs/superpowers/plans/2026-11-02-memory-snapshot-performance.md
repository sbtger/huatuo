# Memory snapshot performance implementation plan

> **For agentic workers:** Use superpowers:executing-plans.

**Goal:** Reproducible idle and pressured feature-cost comparisons.
**Architecture:** Generic load/measurement/reporting core plus HuaTuo adapter.
**Tech Stack:** Python standard library, Linux procfs/cgroup v1, existing Agent.
**Spec:** ../specs/2026-11-02-memory-snapshot-performance-design.md

## Global Constraints

No feature retries or fault overlay in measured captures. Preserve raw failures.
Bound request queues. Record intended arrivals. Require real matching events.
No performance acceptance claim from short/co-located VM smoke. Existing tests
only; make check before each commit; SOB and <=75 character commit messages.

## Review Focus

- Queue overload and HTTP timeouts must remain visible.
- Snapshot failure must never pass as a low-cost success.
- PID reuse/short-lived children must not corrupt CPU attribution.
- Aborted/partial trials must not enter paired valid comparisons.
- Reordered groups must use identical pressure and requested load.

### Task 1: Generic performance observations
Files: core/performance.py, workloads/performance_load.py,
environments/performance.py; existing test_resources.py.
Produces: fixed arrival request stream, process resource samples, analysis.
- [x] Add tests for intended-arrival latency, bounded overload, missing/failed
  samples, percentile sample floor, CPU counter deltas and invalid-pair exclusion.
- [x] Run tests RED, implement, run full Python suite GREEN.

### Task 2: Real Agent experiment adapter and CLI
Files: adapters/huatuo/performance.py, performance.py; existing test_cli.py.
Consumes generic Task 1 measurements; produces randomized idle/pulse trials.
- [x] Add RED tests for idle/pulse schedules and invalid CLI combinations.
- [x] Implement fresh owned target/neighbor fixtures, plain Agent A/B/C/D,
  pressure trace, event validation, resource sampling and deterministic cleanup.
- [x] Implement offline report generation and integrity manifest.
- [x] Run full controls and help/plan validation GREEN.

### Task 3: VM verification and public documentation
Files: PERFORMANCE_PLAN.md, PERFORMANCE_VALIDATION.md, README.md.
- [x] Run isolated VM short idle and pulse for both modules; preserve all trials.
- [x] Audit artifacts, resource cleanup and load denominators; report limitations.
- [x] Whole-branch review; fix material findings; make check and focused commit.

Execution outcome: 124 controls PASS; make check PASS; six VM campaigns / 18 trials, four valid campaigns and two correctly rejected concurrent-load campaigns. See PERFORMANCE_VALIDATION.md.
