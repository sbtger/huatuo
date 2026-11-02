# Memsnapshot reliability optimization

The user authorized starting the recommended optimizations on 2026-11-02.
Preserve the original campaign results and budgets; do not overwrite executing
frameworks or Agent binaries.

## Immediate repair: memburst PID enumeration

`topMemoryProcesses` already validates process start time before reading metrics
and before returning ranked targets. Enumerate with `process.Pids()` and create
the metric reader with `&process.Process{Pid: pid}`. This avoids gopsutil's
`NewProcess -> PidExists -> os.FindProcess` ownership bug without changing ranking,
memory metrics or the identity validation contract.

Approaches considered: modifying vendor is fragile because `make check`
re-vendors; upgrading the old gopsutil API adds unrelated migration risk; avoid
the affected constructor in the existing caller. Choose the third approach.

Acceptance: real Linux procfs integration test detects pidfd accumulation with
GC disabled, supports RSS/shared ranking, returns existing validated process
identities in descending order, and passes with the caller repair. A separately
identified shipping Agent must pass the original memburst FD budget unchanged.

## RSS investigation

Observe the same Agent's `/proc` memory and existing metrics/profile endpoints
at baseline and repeated-capture checkpoints. Ordinary acceptance runs must not
force GC or change budgets. Record observer provenance; profiles used to test
GC/reclamation hypotheses are diagnostic evidence, not substitute acceptance.
Do not implement a memory repair until retained allocations or ownership is
identified.

## Capture execution boundary

The user selected the recommended independent-process direction. A complete
design must define the worker protocol, process identity checks, timeout and
cancellation behavior, bounded outstanding workers, resource limits, cleanup,
per-target publication and trigger cooldown compatibility. In-flight kernel
D-state work cannot be assumed immediately killable. Do not replace the global
slot with unbounded goroutines or claim hard syscall cancellation.

Deliver the concrete architecture separately from the small PID repair, so it
can be reviewed without obscuring the proven ownership defect.
