# Reliability failure diagnosis — 2026-11-02

These findings concern the current short VM campaign, not a 72-hour soak or a
performance evaluation. No shipping source was changed during this investigation.
Original failures remain failures. The original 22-run campaign has completed; optimization follow-ups are
recorded separately in RELIABILITY_VALIDATION.md.

## Cross-target capture isolation

Both triggers failed their delay and block cross-target checks. In each case the
Go read fault was reached before the healthy Java capture request. The healthy
target had real memory pressure; this was not a missing input edge. Execution
stopped at the Java assertion, so these failures do not establish a separate
Python capture failure.

### Shared collector limitation

`internal/memsnapshot/collector/collector.go:31` declares one process-wide
`captureSlot`. `Snapshot` acquires it and releases it only on function return.
The provider executes synchronously. `context.WithTimeout` requests cooperative
cancellation; it does not forcibly return from a blocked read. A separate
goroutine timer would not, by itself, terminate that read or release its resources.

The test-only syscall wrapper uses `time.Sleep(30s)` or `select {}` at the read
boundary. This confirms behavior when reads do not return cooperatively; it is
not evidence that a real kernel syscall hung during this run.

### Threshold trigger

`core/autotracing/memory_threshold_snapshot_action.go` allows one active batch
(`Submit`, `runActionBatches`). The scheduler cannot dispatch another batch until
`actions.Done()` becomes ready. After completion, `Finish` starts node cooldown
and `mainAction` clears pending pressure events while cooldown is active.

Observed in `threshold-isolation-delay`, trial 2:

- Configured snapshot budget: 3 seconds; node cooldown: 8 seconds.
- Go capture started at 13:37:45 and finished at 13:38:15, with `elapsed_ms=30005`.
- Java was requested approximately 8.65 seconds after the blocked read began.
- No Java capture started before the 45-second request timeout.

The serial worker prevents Java execution during the blocked Go capture. On
delayed completion, the scheduler's pending-work/cooldown policy also prevents
the queued pressure edge from becoming a new capture. With permanent blocking,
completion never arrives. The normal shutdown path also joins the worker, so a
cooperative stop cannot be assumed to finish in this state.

Evidence directory:
`/root/reliability-threshold-isolation-delay-20261102-trial2/evidence`.
The corresponding block trial has `read_end_ns=0` before forced cleanup.

### Memburst trigger

`core/autotracing/memburst_snapshot.go` has one snapshot worker. Within a job,
`collectBurstSnapshots` visits ranked processes serially, sharing a batch timeout
of `process count * 2s`. `saveBurst` runs after the collection loop finishes.

Observed in `memburst-isolation-delay`, trial 1:

- Read active interval: monotonic 244552562665460–244582563593243 ns (30 seconds).
- Healthy request began at 244561125221578 ns, inside that interval.
- The first event started at 14:05:13 and was uploaded at 14:05:43.
- Its ranked Go, Java and dockerd snapshots all reported
  `context deadline exceeded`. Java had not been collected before batch expiry.
- A later job ranked Java first, but the healthy request still produced no
  acceptable completed event before timeout. Its cancellation event was saved
  during cleanup. The existing evidence does not individually time every read
  in that later job, so it cannot prove its exact per-read sequence.

This is serialization and batch publication coupling: one target can delay or
invalidate other targets' snapshots. It does not show business execution being
blocked. The permanent-block check additionally shows the worker does not
complete while the injected read remains blocked.

Evidence directory:
`/root/reliability-memburst-isolation-delay-20261102-trial1/evidence`.

## FD budget failure: process-enumeration pidfds await GC

The panic campaign failed its **test resource budget**, not an observed OS
`EMFILE` limit. Its peak was 650 FDs against a test budget of 512. RSS peaked at
182.62 MiB, below the 512 MiB absolute memory budget. Two seconds after the FD
peak, the same Agent had 34 FDs. The peak occurred during cooldown, before panic
injection, so attributing it to panic would be incorrect.

The production call path is:

```text
topMemoryProcesses
  -> gopsutil/process.Processes
  -> NewProcessWithContext
  -> PidExistsWithContext
  -> os.FindProcess
  -> Linux pidfd open
```

`vendor/github.com/shirou/gopsutil/process/process_posix.go:102` calls
`os.FindProcess` but does not `Release` the returned `*os.Process`, including on
the mounted-procfs early-return path. Go 1.24.3 attaches a finalizer that releases
the pidfd, so unreachable handles can accumulate until GC runs.

A read-only observer caught the shipping `agent` binary in a subsequent memburst
run with 450 FDs, of which 416 were `anon_inode:[pidfd]`. It did not capture the
descriptor types at the original 650-FD peak; the attribution combines this
observation with the shared code path and controlled reproduction.

### Controlled reproduction and one-variable check

A standalone program was built with the repository's vendored gopsutil and Go
1.24.3, then run in the same VM. Automatic GC was disabled **in this standalone
probe only**, to make deferred cleanup deterministic. This setting was not
applied to any Agent or acceptance campaign.

| Step | Original vendored dependency: pidfds | `defer proc.Release()` diagnostic overlay: pidfds |
| --- | ---: | ---: |
| Baseline | 0 | 0 |
| Enumerate 209 processes once | 209 | 0 |
| Enumerate twice | 418 | 0 |
| Enumerate three times | 627 | 0 |
| Explicit GC | 0 | 0 |

Only the diagnostic binary used the one-line release overlay. Neither Agent
binary nor the tracked vendored dependency was modified. This confirms deferred
pidfd cleanup, rather than an unreclaimable FD leak. It still causes real peak FD
usage and can matter when the Agent has a low descriptor limit or the host has
many processes. Production impact at an actual FD limit was not tested here.

Evidence directories:

- `/root/reliability-memburst-fault-panic-20261102-trial1/evidence`
- `/root/reliability-memburst-fault-delay-20261102-trial1/evidence`
- `/root/reliability-fd-observation-20261102.jsonl`

Standalone reproduction source and outputs are retained with the local
`diagnosis-20261102` artifacts. The release overlay is an investigation control,
not a completed production fix or a passing Agent regression test.

## Additional RSS finding remains open

While investigating, the memburst delay matrix finished with a different gate
failure: the same shipping Agent's settled RSS increased from 94,388,224 to
187,539,456 bytes, an 88.84 MiB increase against a 64 MiB growth budget. It did
not exceed the absolute 512 MiB budget. These endpoints precede replacement by
the fault Agent, so the increase cannot be attributed to the injected delay.

The retained samples do not distinguish retained heap, reclaimable runtime
memory or persistent growth. This requires heap/runtime evidence and a controlled
follow-up; it is not yet diagnosed as a memory leak and must not be explained
away by the pidfd finding or marked PASS.

Read-only metrics and heap profiles were subsequently sampled during a separate
same-Agent memburst steady run, without requesting GC. That run completed 20
rounds in 1800.002 seconds and passed all campaign gates; the warmed Agent RSS
endpoint decreased 10.676 MiB, FD growth was 0, thread growth 1 and watch growth 0. Through round 8, measured
heap allocation was approximately 74–86 MiB and RSS fell as well as rose
(approximately 152–194 MiB at sampled checkpoints). Profiles identify large Go
symbol-table allocations (`ReadGoTable -> readPCLN -> elf.Section.Data`), alongside
startup BTF metadata. Ranked records confirm that memburst also captured the
Agent itself. Reserved idle heap and varying released pages account for a
substantial part of the RSS difference at those observations. These samples do
not yet establish a permanent leak or explain every failed RSS endpoint.

The original failed delay campaign provides a more specific ranking transition:
its first three warmup events captured the business runtimes/dockerd, without
Agent PID 208037. Starting at event index 3, that Agent itself entered the top three
and was repeatedly captured. Its recorded post-capture RSS rose from 148,754,432
to187,355, 136 bytes, later fell to158,171, 136 and subsequently rose again. The
warmed baseline 94,388,224 bytes preceded this self-capture path. Thus the growth
check compared a baseline without large self-symbolization to an endpoint after
it; the observed Go-table allocations explain a concrete additional memory path.
This is not permission to exclude the Agent, change ranking or relax the budget.
The PID-enumeration repair also reduces per-ranking allocation, but whether it
prevents this campaign's RSS failure requires the separate Agent rerun.

## Confirmed pressure-control writer race

The original producer100 threshold steady trial failed during a later Python
pressure request. Its retained Python log contains `ValueError: invalid literal
for int() with base 10: ''` in the pressure background thread. Failure diagnostics
showed a requested 500 MiB control value but only about 47 MiB cgroup usage.
The business HTTP thread continued running. The input had not been applied;
this trial cannot establish a collector failure or complete the 30-minute check.

Writers used `Path.write_text`, which truncates the same inode before writing.
The independently running service can open/read it in that interval. Producer105
uses a complete same-directory temporary file followed by `os.replace` at every
`target_mb` writer. Directory bind mounts preserve visibility of replacement
inodes. An existing open reader retains the old complete value, while subsequent
opens see the new complete value. Two red/green controls verify that behavior
and preservation/temporary cleanup on replacement failure. All 105 framework
controls pass. This repairs the demonstrated harness race without changing the
Python workload parser or relaxing a product gate.

Historical Python timeouts without this retained traceback are not automatically
assigned the same root cause. Original runs keep their original outcomes and
source archives; follow-ups execute from a separate producer105 directory.

## Conclusion and repair boundaries

- Cross-target failures concern collector availability and shared publication,
  separate from business continuity. Existing observed business checks have not
  reported request errors; the original 22 runs also passed independent observed-period business auditing.
- FD accumulation has a concrete ownership defect and a successful isolated
  release control. An Agent-level fix and regression remain to be implemented.
- A hard read deadline needs an execution boundary that can actually terminate
  the work, together with bounded concurrency and cleanup. Merely returning from
  a timer while leaving the worker behind would not establish isolation.
- RSS growth remains an open investigation. No thresholds were relaxed and no
  failed evidence was replaced with a successful diagnostic result.
