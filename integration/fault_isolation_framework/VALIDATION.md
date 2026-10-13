# Recorded validation: 2026-10-13

The real-Agent suite passed **78 phases** (26 each for Go, Java and Python), and
the final raw-evidence audit passed. The three services completed **8,521 work
requests and 4,173 in-memory state updates with independent reads**, with no
business response/state/identity/progress assertion failures.

This is evidence of business isolation in the recorded setup and windows, not
a universal reliability guarantee or a performance evaluation. State fixtures
exercise application memory; they do not test database transactions.

The portable, sanitized [result record](results/2026-10-13-cgroup-v1.json) contains
all phase results, runtime/build/object hashes, counters and recovery attempts.
It omits machine paths, host/container identifiers, process IDs and raw stacks.
The raw evidence remains archived separately under its SHA-256 in the record;
raw logs are not committed to the repository. This historical validation ran
against production revision `f7ae016d1178ed7e7759d92c33bb2d1bb3d88a62` with the
pre-commit suite. It is not presented as a newly executed run of a later commit.

## Environment and coverage

- Linux/amd64; kernel `5.10.0-cache-ext-vm-nokmem-8780cdccc1e2`, Docker cgroup v1.
- Go 1.24.3; HotSpot/OpenJDK 17.0.19 with G1; CPython 3.12.3 with default GC.
- Each target has Agent-off, blacklist, plain-Agent and instrumented-control phases.
- Each target has permission, EFAULT, short-read, panic, cancellation, deadline,
  blocked-read, kill-after-read, normal restart, ENOSPC and invalid-config phases,
  each followed by normal recovery. Other services remain active as canaries.
- 22 assertion/log negative-control and real Python fixture tests passed.

## Observed Python failures

`python/delay-recovery` and `python/invalid_config-recovery` each first produced
`CPython interpreter GC generations are invalid`, then succeeded with complete,
seven-entry snapshots on the next real threshold capture in the same Agent and
business process. Both failed events are retained in the archived raw evidence
and both attempts appear in the result record.

The suite permits at most three normal capture attempts only for this exact
CPython error. This is a controller test policy, not an automatic production
Agent retry guarantee. The root cause remains unconfirmed; concurrent GC is a
hypothesis. An earlier trial also failed strict first-attempt recovery and remains
in the raw-evidence archive. No attempt or failed trial was overwritten.

## Material limits

The Agent and business binaries were rebuilt. A full BPF rebuild encountered the
builder's existing kernel-header failure, so generated ABI/BPF objects were
reused and their hashes recorded. This report does not claim a clean full BPF
rebuild. Focused memsnapshot/memorywatch/autotracing Go tests passed. The full
repository Go test command on the unprivileged builder failed solely at
`internal/bpf/TestInitAndShutdown` with EPERM; the same compiled test passed when
run as root in the isolated VM.

Blocked-reader recovery required SIGKILL and Agent replacement while businesses
continued correctly. Deadline classification was checked after a delayed read
returned; forced syscall interruption was not established. Cgroup v2, other
kernels/runtimes, long soak, Agent OOM/FD exhaustion, system-wide contention,
real Kubernetes control-plane behavior and performance overhead were not
validated by this run. The suite is opt-in and has not been added to CI gates.

## Branch packaging regression

After adding the suite to its dedicated branch, `make check` and focused Go
memsnapshot, memorywatch and autotracing tests passed. All **30 Python tests**
passed, including eight evidence-completeness positive/negative controls. The
stricter audit also passed against the complete historical 78-phase evidence.
The full builder Go test command again failed only the BPF initialization test
with EPERM; no privileged whole-repository pass is claimed for this rerun.

Freshly rebuilt plain/fault Agents and the lint-adjusted Go fixture passed a new
**26-phase Go regression** in the same isolated VM: **930 work requests and 460
state updates with independent reads**, with no business errors, unexpected Agent
logs or evidence-accounting errors. See the sanitized
[Go regression record](results/2026-10-13-go-regression.json). Java/Python were
not rerun during this packaging step; their unchanged fixture coverage is the
historical full-matrix run above. Both runs used the pre-commit suite; production
code was unchanged. No performance or additional environment coverage is implied.

## Modular framework validation

The extracted core, environment helpers, business probe and memsnapshot adapter
passed **58 tests**: the original 30 plus 28 framework/CLI/resource/raw-attribution
controls. A non-HuaTuo test feature exercises the real runner with a `payments`
target; core imports are also checked without adapter, workload or environment
packages. This establishes the extension boundary, not reliability of a second
production agent.

After independent review and fixes, a new **78-phase Go/Java/Python matrix**
passed with **8,505 work requests and 4,167 state updates plus independent reads**.
Its schema-v2 audit passed with no business errors, unexpected Agent logs or
evidence errors. The [sanitized modular result](results/2026-10-13-modular-framework.json)
records all phases, build/source/BPF hashes, runtime details and the separate
raw archive SHA-256. The executed parent revision was `b5355c923`; test code was
the pre-commit modular suite, while production code was unchanged.

The first capture in `python/cancel-recovery` and `python/block-recovery` returned
`CPython interpreter GC generations are invalid`. Both succeeded on the second
capture with the same recovery Agent and unchanged business. Both attempts are
retained. For block recovery, the recovery Agent is the replacement after
SIGKILL. This is the same bounded controller policy described above, not a
production retry guarantee. Its root cause remains unconfirmed.

Review negative controls reproduced and fixed empty-message exceptions becoming
PASS, ignored Docker removal failures, final record-read exceptions bypassing
cleanup, and offline acceptance of claimed faults without matching raw markers
and snapshots. Adapter-policy exceptions and unknown evidence schemas fail too.
The final unsupported-schema CLI guard was checked separately by the 58-test
run and a repeated full-evidence audit; matrix core/adapter sources were unchanged.
An earlier modular 78-phase run is preserved separately and also passed the
stricter raw-attribution audit.

`make check` and focused Go packages passed. Full Go tests on the builder again
failed solely at `internal/bpf/TestInitAndShutdown` with EPERM; the freshly
compiled same test passed as root in the VM. This does not claim a privileged
whole-repository run. Agent/fixture binaries were rebuilt; BPF objects were
reused with recorded hashes. Raw archive export records intentional `/dev/full`
symlinks in a manifest instead of following or packaging them as device files.

The kernel/cgroup/runtime, discovery-fixture, blocked-syscall, performance and
long-term/resource-exhaustion limits remain those listed above. No CI scheduling
was added.
