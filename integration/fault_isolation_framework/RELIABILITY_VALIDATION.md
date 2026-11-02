# Memory snapshot reliability validation — 2026-11-02

This is a historical pre-worker record. Its builds and measurements do not
validate the later dedicated-helper implementation. See
[worker validation](WORKER_VALIDATION.md) for the new scope and open issues.

Original campaign completion: **22/22 runs**, 13 PASS and 9 FAIL. This report retains failed runs; it is not an all-green reliability claim.

The independent auditor checked 166,959 recorded work requests across Go, Java and Python in 382 executed case entries. Business auditing is PASS for 22/22 completed runs, for the observed periods only. A stopped feature plan does not prove unexecuted recovery or future scenarios.

## Environment and provenance

VM kernel 5.10.0-cache-ext-vm-nokmem-8780cdccc1e2, cgroup v1, Docker API 1.52, Go 1.24.3, HotSpot 17.0.19 and CPython 3.12.3. One campaign ran at a time. There is no cgroup-v2, real Kubernetes, PID-reuse, Agent OOM/FD-exhaustion or host-wide contention acceptance in this report.

The matching shipping Agent and separately identified fault Agent were built from the recorded pre-commit worktree. Test-only overlays inject read/provider faults; production Go sources contain no injected block or panic. Original producer100 and auditor103 are separate snapshots with recorded file hashes. Follow-up producer105 repairs atomic pressure-control publication. Agent binary hashes and the exact production repair patch are retained with raw build evidence. See `RELIABILITY_RESULTS.json` for per-run hashes and verdicts.

## Original primary results

| Run | Overall | Business audit | Executed cases |
| --- | --- | --- | ---: |
| threshold-target-exit-20261102-trial2 | PASS | PASS | 16 |
| threshold-isolation-efault-20261102-trial2 | PASS | PASS | 16 |
| threshold-isolation-delay-20261102-trial2 | FAIL | PASS | 7 |
| threshold-isolation-block-20261102-trial2 | FAIL | PASS | 7 |
| threshold-fault-panic-20261102-trial1 | PASS | PASS | 23 |
| threshold-fault-cancel-20261102-trial1 | PASS | PASS | 23 |
| threshold-fault-delay-20261102-trial1 | PASS | PASS | 23 |
| threshold-fault-block-20261102-trial1 | PASS | PASS | 23 |
| threshold-fault-kill_after_read-20261102-trial1 | PASS | PASS | 23 |
| threshold-fault-permission-20261102-trial1 | PASS | PASS | 23 |
| memburst-target-exit-20261102-trial1 | PASS | PASS | 15 |
| memburst-isolation-efault-20261102-trial1 | PASS | PASS | 15 |
| memburst-isolation-delay-20261102-trial1 | FAIL | PASS | 7 |
| memburst-isolation-block-20261102-trial1 | FAIL | PASS | 7 |
| memburst-fault-panic-20261102-trial1 | FAIL | PASS | 22 |
| memburst-fault-cancel-20261102-trial1 | PASS | PASS | 22 |
| memburst-fault-delay-20261102-trial1 | FAIL | PASS | 22 |
| memburst-fault-block-20261102-trial1 | FAIL | PASS | 22 |
| memburst-fault-kill_after_read-20261102-trial1 | PASS | PASS | 22 |
| memburst-fault-permission-20261102-trial1 | FAIL | PASS | 22 |
| threshold-steady-observed-20261102-trial1 | FAIL | PASS | 7 |
| memburst-steady-observed-20261102-trial1 | PASS | PASS | 15 |

## What the checks establish

- The original memburst steady campaign passed: 20 rounds, 1800.002 seconds on one shipping Agent; warmed RSS growth -10.676 MiB, FD growth 0, thread growth 1, inotify-watch growth 0. The newer threshold steady attempt stopped early on the diagnosed pressure-thread race and did not complete 30 minutes.
- Threshold panic, cancel, delay, block, kill-after-read and permission matrices exercise Go/Java/Python with real Agent capture/recovery, business assertions, storage failure/recovery and restart. A block-matrix PASS permits killing and replacing the Agent; it is not proof of interrupting the blocked read.
- Cross-target EFAULT checks exercise same-Agent healthy Java and Python captures after a Go read error. Delay/block checks fail on the first healthy Java assertion in both triggers; Python was not reached in those failed checks.
- Disposable-target exit uses an auxiliary Go process, confirms a real post-exit read failure and same-Agent recovery. It does not establish Java/Python exit races.
- Cooldown checks observe the entire remaining window negatively and require a new positive capture after expiry. Per-module raw timestamps distinguish enqueue from upload.
- Steady checks request 20 rounds and at least 1800 seconds on one shipping Agent, with raw FD/RSS/thread/inotify-watch observations. A failed or incomplete attempt is not counted as meeting that acceptance.

## Diagnosed failures

1. **Cross-target capture isolation:** synchronous providers, one global collector slot and serial trigger workers allow a non-returning read to block other captures. Threshold completion/cooldown clears pending work; memburst shares batch expiry and publishes only after the batch returns. Actual 30-second read intervals and healthy pressure were witnessed. These are test-injected read-boundary failures, not observed real kernel D-state hangs.
2. **FD peaks:** memburst process enumeration calls an old gopsutil constructor that opens pidfds without explicit Release. FDs reached 650 against the unchanged 512 test budget before panic injection. Same-VM reproduction and a one-line Release diagnostic control confirm GC-delayed cleanup. The production repair instead avoids that constructor, because re-vendoring would discard a dependency patch.
3. **RSS growth:** an original delay campaign grew settled RSS by 88.84 MiB against 64 MiB. Read-only profiles identify substantial Go symbol-table parsing and reserved idle heap; subsequent RSS falls without forced GC. This is evidence for allocation/reclamation effects, not proof that all growth is harmless or that a permanent leak is absent.
4. **Threshold steady harness failure:** Python pressure input read an empty target_mb file during truncate/write, raised ValueError and terminated its pressure thread. Actual usage remained about 47 MiB despite the 500 MiB request. This specific trial is a harness/input failure, not proof of a collector read failure. Atomic file replacement repairs the demonstrated writer race.

Detailed source paths, timelines, reproduction and limitations are in `RELIABILITY_DIAGNOSIS.md`.

## Optimization follow-ups

| Build / scenario | Overall | Business | FD peak |
| --- | --- | --- | ---: |
| baseline/panic | PASS | PASS | 243 |
| optimized/panic | PASS | PASS | 57 |
| optimized/block | PASS | PASS | 57 |
| optimized/permission | PASS | PASS | 57 |
| optimized/threshold-control | PASS | PASS | 41 |

All five follow-ups pass overall and independent business auditing. The matched original-Agent panic control also passes in this repetition; the earlier 650-FD failure is intermittent, not deterministically reproduced by every campaign. Fixed-Agent panic/block/permission framework FD peaks are 57, against the unchanged 512 budget. The independent observer recorded 208 pidfds in the original control and 0 across 356 fixed-Agent observations; observed FD peaks differ with sampling windows (242 vs 60) and are not a performance ratio.

The threshold target-exit/normal-cycle follow-up validates the atomic input repair as a short smoke test. It does not replace the failed original threshold 20-round/30-minute attempt or establish a new 30-minute threshold acceptance. All recorded owned resources across 34 runs passed read-only cleanup checks: 200 PID/start-time instances, 136 containers, 34 images and136 container memory-cgroup paths.

The PID repair has a real-procfs regression: original code fails with GC disabled, repaired code passes three independent runs for RSS/shared ranking. Existing open-reader and failed-replacement tests cover atomic control publication; 105 framework controls pass.

Relevant Go packages pass. Full `make unit` fails `TestIOCostObject` (NULL undefined in BPF fixture) and `TestInitAndShutdown` (operation not permitted) on the140 host; both failures also reproduce with the original memburst implementation. They remain reported failures, not waived successes.

The worker-process architecture is a separately reviewed proposal in `docs/superpowers/specs/2026-11-02-memsnapshot-worker-isolation-design.md`; it is not a shipping implementation or a fix for the currently failing capture-isolation checks.

## Audit boundaries and evidence

Request-stream hashes and accounting are independently checked even when a feature plan stops early. `adapter_audit_completed=false` means feature log policy was not fully audited; an empty unexpected-log object must not be interpreted as verified absence of warnings/errors. Present registered artifacts were hash-checked; missing future-plan artifacts are retained as incompleteness, and changed artifacts invalidate evidence.

Historical trials and the diagnostic-only overlay run are listed separately in the JSON. They are not replacements for primary failures. Raw run directories, executed framework archives, build hashes, diagnostic outputs and full exports remain on the140 test environment; raw data is not embedded in this repository.

No 72-hour stability or performance/overhead claim follows from these results.
