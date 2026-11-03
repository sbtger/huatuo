# First real-application snapshot B/C pair

On 2026-11-03, FastAPI normal60 completed one descriptive B/C pair:
both trials were valid, business quality passed, and the evidence audit
passed (386 files, no errors). No SLO or statistical significance is claimed.
Spring Boot, etcd and the 90% scenarios have not run in this campaign;
their waiting queue was stopped before any further case started.

The business had 4 CPU / 4 GiB, CPython 3.12.3, one async Uvicorn worker,
288,739 real tracked Records and 2,158,388,224 payload bytes. Seed 923,
80/20 hotspot and GET/SET/DELETE_REPLACE 70/20/10 were fixed for B/C.
The verified pre/post dataset SHA-256 was identical in both groups:
`5a5bdbb1bc6ee8bbbf01217e9a0f9ba58cab62ee1ee0f86ed0febbec438d05f8`.

B-only calibration found 1,312 RPS stable and 1,375 unstable (4.80% bracket).
The frozen normal rate was 721 RPS, with a fresh stable B validation.
This is a measured bracket estimate under a single-round monotonicity
assumption; a transient unstable point does not establish maximum capacity.
Both groups ran 60s warmup, baseline, capture phase and recovery.
Both contained the same real Agent with automatic triggers disabled plus
an idle test helper. C issued one production WorkerManager/provider capture
with bounded result serialization, owned disk write and fsync. The Agent
initializes its own manager in both groups; this is not a feature-toggle
initialization comparison.

| Capture phase: 60 seconds | B idle | C snapshot | C−B | Change % |
|---|---:|---:|---:|---:|
| Success cohort RPS | 721.017 | 720.983 | -0.033 | -0.005 |
| P99 ms | 22.415 | 6.651 | -15.764 | -70.33 |
| P999 ms | 35.167 | 10.727 | -24.440 | -69.50 |
| Business target CPU s | 32.350 | 34.770 | +2.420 | +7.48 |
| Agent + helper + reaped worker CPU s | 1.180 | 4.140 | +2.960 | +250.85 |
| Collector simultaneous scoped peak MiB | 80.867 | 87.992 | +7.125 | +8.81 |
| Collector peak above phase baseline MiB | 0.695 | 7.375 | +6.680 | +960.67 |
| Worker lifetime HWM increase MiB | 0 | 8.000 | +8.000 | null |
| Business peak above phase baseline MiB | 0.148 | 0.172 | +0.023 | +15.79 |
| Pre-capture cgroup usage / limit % | 58.6151 | 58.6073 | -0.0078 pp | — |
| Errors / timeouts / OOM / charge failures | 0 | 0 | 0 | null |

Business CPU selects only `application-python`, excluding the helper.
Collector total peak and its baseline-adjusted increase are different
metrics; worker HWM is a lifetime counter and is not added to simultaneous
peaks. In the capture phase, both groups had zero additional GC collections,
GC wall/thread CPU time and CPU quota throttling. Matching pressure and
these counters does not establish that all background conditions matched.

**The lower C latency is not evidence of improvement or zero impact.**
Before any C capture, baseline P99 was already 23.919 ms in B versus
6.355 ms in C. Recovery P99 was 22.863 versus 6.435 ms. The cause of this
between-trial difference is unresolved; this pair cannot isolate a causal
request-latency effect. The physical host also ran the VM2222 and VM2230
reliability soaks. One Python worker does not represent a replicated cache.

The actual C interval was 11:25:16.249–11:25:19.234 UTC: full wall
2,984.737 ms, provider 2,965 ms. It returned **partial**, seven nonempty
type entries, `output_truncated=true`, with reason
`deadline reached during external object census`. This was a bounded
GC-tracked census, not a full heap dump; no retry replaced it.
The complete retained trace contained 2,137 definite scheduled arrivals
inside this interval: P99 6.162 ms, P999 null (fewer than 10,000 samples),
max 9.409 ms, zero errors, clock uncertainty 7.905 ms.

RPS counts successful responses in the scheduled-arrival cohort divided
by phase seconds. It is not completion-wall instantaneous throughput;
a pause followed by draining may preserve cohort RPS. Percentiles use
scheduled arrival through completion. Raw timelines and backlog remain
necessary when interpreting a short capture.

The separate DIAGNOSTIC control detected a real 20 ms delay on 5% of
requests (P99 +33.392 ms; 550 traced delays, minimum 21.122 ms) and a
32 MiB owned memory allocation (observed +36,417,536 bytes). This validates
observer sensitivity; neither artificial cost was injected into C.

Measurement source was commit
`cd5705696f889c24ba3d14c73c6b05d3d9601430`, framework identity
`4a318ec45bc289ebee0710e349567d20f341702c54bb2fa61ef61f6cca284ad0`.
Production binaries and instrumented tools were the verified unchanged
`7cbdd866570bddc4b32c0b0c303da30f89045362` build. Rebuild and launch
instructions are in [the active plan](APPLICATION_PERFORMANCE_PLAN.md).
This instance's authoritative DUT output is
`/data/huatuo-performance/application-4a318ec45bc2/run-fastapi-normal60-02`;
the host snapshot is
`/data1/zp/huatuo-application-tools-20261103/first-pair-chain-4a318ec45bc2/final-read-summary.json`.
Raw trial summaries, histograms, traces, resource samples, capture output,
source archive and manifests remain retained. The earlier failed 5s probe
attempt remains separate; its fix changed only the probe throughput gate.
Final supervisor exit was 0 with no cleanup errors, Docker was empty,
and the campaign unit was inactive. No subsequent experiment was launched.
