# Memory snapshot performance design

Approved direction: user requested implementation of the preceding performance
proposal on 2026-11-02. This suite is separate from unfinished worker isolation.

Reuse the existing Linux/Docker ownership, fixtures, Agent configuration and
artifact storage. Add generic fixed-arrival HTTP load and proc/cgroup sampling,
with HuaTuo-specific scheduling, pressure and event validation in an adapter.
Alternative: wrap only wrk2 (strong load generator, insufficient event/resource
attribution); alternative: extend reliability phases (mixes functional retries
with performance observations). Select reusable performance core plus adapter.

Two experiments avoid confusing memory-pressure cost with collection cost:
idle compares A/no Agent, B/feature disabled, C/enabled without pressure;
pulse compares A/no Agent, B/disabled, D/enabled with identical pressure steps.
Do not subtract an idle C result from a pressured D and call it capture cost.
Randomize group order reproducibly; fresh fixtures and Agent per group. No
capture retries. Repeated trials retain failures and valid-run denominators.

Bound fixed-arrival dispatch queues. Measure latency from intended arrival,
send delay and service time; include errors, missed arrivals and timeouts.
A built-in stdlib load driver is for validation/low-rate experiments only;
external machines can run the standalone load driver against reachable URLs.
Label co-located generator results and do not claim production SLO acceptance.

Measure process CPU time/RSS/FDs/threads/faults/context switches/I/O, cgroup
usage/peak/failures, host memory/vmstat/PSI where available. Track children by
PID/start ticks; child aggregate is explicitly sampled, not exact lifetime CPU.
Pressure controls use atomic writes. Record observed usage and command times,
not merely requested MiB. Target and unpressured neighbor identities and HTTP
checksums must remain valid. Retain matching real events, selected PIDs,
snapshot statuses, output bytes and persisted time. An unsuccessful capture
cannot be interpreted as cheap successful collection.

CLI supports idle/pulse, runtime set, repeat/seed, pressure MiB, durations,
extra ranking processes, watched container count, Top-K, capture timeout,
cooldown and module-specific real sampling interval. Keep current schema,
limits and supported cgroup v1 fixture boundary explicit. Multi-container
pressure records observed selected/suppressed targets, not assumed parallelism.

Machine-readable results, raw requests/resources/events, checksums, environment,
pairwise deltas and Markdown report. Performance budgets optional and explicit;
no universal 5% limit. Low-sample tail percentiles unavailable. Short VM smoke
proves the implementation path only, not full performance characterization.
