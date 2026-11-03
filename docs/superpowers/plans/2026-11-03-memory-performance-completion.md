# Memory snapshot performance completion implementation plan

> Execute inline with executing-plans and TDD; one final independent review.

Goal: implement the approved table's real Redis load, independent load VM,
shipping selection semantics, and start a calibrated repeated campaign.
Architecture: VM2224 is DUT, VM2223 is load controller. Loopback-only QEMU
forwarding exposes dedicated service ports across their isolated NATs. The
load controller owns bounded jobs with auth, lease expiry, cancellation and
hash-verified artifact transfer. VM2222's frozen 72h soak is not modified.
Tech stack: Python>=3.8 stdlib, real Redis RESP/BGSAVE, existing Go/Java/Python
fixtures, Docker cgroup v1 DUT; existing six-binary build and BPF.
Spec: integration/fault_isolation_framework/PERFORMANCE_PLAN.md plus the
approved Cooper performance-table text (Redis write/fork, A/B/C or A/B/D).

Global constraints: no production feature changes; no relaxation of dispatch,
response, memory-failure, checksum or resource validity guards; no retries that
replace failed results. Formal groups random seed and >=5 repeats, warmup60s,
30s baseline/trigger/recovery, >=1000 requests/window before reporting p99.
Shared physical host remains a disclosed limitation, not production acceptance.

- [ ] Preserve earlier unfinished cohort prototype patch, then remove it from
  the worktree; shipping threshold selects one eligible container per batch.
- [ ] Add selection-policy tests RED, implement separate threshold/memburst
  capture expectations, configure burst target limit1..3 and driver pressure.
- [ ] Add typed RESP parser/load tests RED. Implement real Redis neighbor with
  seeded bounded data, SET/GET/counter checks and scheduled actual BGSAVE;
  retain INFO/logs/fork counts and check completed forks and business state.
- [ ] Add opt-in fixed service bind/ports preserving default loopback/ephemeral
  behavior for all existing stability uses. Test Python listen behavior.
- [ ] Add remote job server/client and existing-file tests RED for auth, URL
  allowlist, checksum, timeline conversion, lease cancellation, raw integrity.
  run_load accepts per-target HTTP/Redis and cancellation with bounded queues.
- [ ] Add external-load CLI validation and matrix options. Implement capture,
  Redis and remote resource artifacts; report actual selection policy and load
  placement. Clock uncertainty/drift invalidates a trial, never hides latency.
- [ ] Provision DUT Redis and dedicated64GiB test disk; restart only idle DUT
  once to add QMP and loopback service forwarding. Existing DUT has no QMP.
  Add load-controller forward via its existing QMP; no SSH keys distributed.
- [ ] Run full framework controls, make check, final independent review; fix
  important findings with RED/GREEN and keep one/few scoped75-column SOB commits.
- [ ] Deploy frozen identical framework to DUT/loadVM; hash six binaries and
  source. Calibrate external load, run Redis write/fork and multi-target smoke
  trials. Retain failed original/corrected validation directories separately.
- [ ] Start supervised >=5-repeat table matrix sequentially, with source,
  command, readiness, progress, raw request/resource/event artifacts and reports.
  Assert first formal trial/campaign runs correctly before final status.

Files: existing performance.py, performance_matrix.py, adapter/performance.py,
fixtures.py, performance_load.py, services/main.go/SnapshotBusiness.java/
python_service.py; new workloads/redis_protocol.py, performance_redis.py,
services/redis_service.py, environments/remote_load.py and load_controller.py.
Tests extend existing test_resources.py/test_business.py/test_cli.py only.
Ops deployment scripts/data stay in task evidence directory, never contain
secrets in Git. Tokens are mode0600 and API never accepts arbitrary commands.
