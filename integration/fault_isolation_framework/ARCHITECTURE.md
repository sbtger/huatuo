# Framework architecture and adapter boundaries

The reusable unit is the Python execution/evidence core. The maintained real
adapter is HuaTuo memsnapshot. A second in-memory test adapter uses a `payments`
business target to exercise the core independently; it is an API conformance
control, not validation of another production observation agent.

```text
CLI registry
    |
    +-- core Runner + EvidenceStore + audit
    |       |
    |       +-- BusinessProbe protocol
    |       |       +-- example HTTP/state/progress probe
    |       |
    |       +-- FeatureAdapter protocol
    |               +-- HuaTuo memsnapshot
    |                       +-- HuaTuo Agent/discovery helpers
    |                       +-- trigger/fault/result/log policies
    |
    +-- Linux/Docker environment and example service fixtures
```

| Module | Responsibility | Dependencies |
| --- | --- | --- |
| `core/models.py` | Scenario, OperationResult, BusinessProbe/FeatureAdapter protocols | Python standard library |
| `core/runner.py` | Declared phase order, independent observations, fault gates, drain and final result | Core and supplied implementations |
| `core/evidence.py` | Register expected artifacts, record registration history, hash final files | Python standard library |
| `core/audit.py` | Plan/coverage, raw accounting, registered references, hashes/JSON integrity | Optional explicitly supplied adapter policy |
| `environments/` | Linux identity/process groups, owned Docker containers/image | Linux/Docker |
| `workloads/http_probe.py` | Example work checksum, state update/read, tick and process assertions | Example HTTP contract and Linux process view |
| `workloads/fixtures.py`, `workloads/services/` | Launch example Go/Java/Python businesses | Docker and selected runtimes |
| `adapters/huatuo/agent.py`, `discovery.py` | Daemon arguments and Pod discovery metadata | HuaTuo command/discovery contracts |
| `adapters/huatuo/memsnapshot/` | Threshold pressure, fault/recovery matrix, snapshot/log semantics, overlay build | Current HuaTuo collector and cgroup v1 |
| Root `run.py`, `build.py`, `audit.py` | Existing command compatibility and explicit adapter registry | Selected maintained adapter |

Core imports neither adapters nor workloads/environments. A runtime import guard
covers that boundary. HTTP paths, state formulas, tracing names, snapshot fields,
readv faults and CPython retries belong to the concrete implementations.

## Extension contracts

`BusinessProbe` exposes `target_id`, `begin`, `finish`, `close`, `totals` and
`records`. It must continuously observe its business, retain failed request
records, drain pending work on close, and return phase `samples`, `errors` and
`assertion_errors`. Workload-specific correctness assertions stay in that probe.
Raw work/transaction streams are registered as `requests` with the probe target ID.

`FeatureAdapter` exposes `adapter_id`, `probes`, `prepare`, `plan`, `scenarios`,
`quiesce`, `verify_final`, `audit_artifacts` and `cleanup`. It owns resource
preparation, the full ordered plan, trigger/injection semantics, recovery policy,
final resource checks and cleanup of only resources it created.

A `Scenario` supplies `name`, `target_id`, an operation, `expect_fault` and a
minimum observation duration. Its operation returns `OperationResult(detail,
fault_hits, evidence)`. Fault phases require a reached witness and registered raw
evidence. The adapter must validate that the witness identifies the exact fault;
a generic marker or unrelated partial result cannot establish that. Recovery is
an explicit following scenario whose operation must check the actual recovered
feature result. The core requires the full declared plan to run successfully.

All probes observe every phase, including other targets as canaries. Expected
feature failure cannot waive business assertions. Quiesce the feature, stop/drain
probes, check final resources and all request rows, collect business logs/cleanup,
then hash and audit final evidence. A cleanup or recovery exception fails the run.

To add another maintained feature, implement those two protocols and register
its CLI/policy explicitly in `cli.py`. Do not import arbitrary Python modules
named in an evidence file. Introduce configuration knobs only when its concrete
adapter needs them; generic core does not invent fault or runtime names.

## Evidence version 2

`summary.json` records schema/adapter identity, the complete planned phase list,
per-phase target, fault witness count and relative artifact references, business
observations, global request/update counts and errors. `registrations.jsonl`
records expected artifact registrations. `manifest.json` records the same set,
format, role, target ID, minimum document count and final SHA-256. Register files
before their producer uses them; add an expected document for each capture.

Audit rejects missing/empty/unhashed/changed files, truncated JSON, path escape,
manifest omissions, missing phases, empty business windows, unregistered fault
references and raw/summary count mismatches. It then invokes the adapter's log
policy. Memsnapshot sets `requires_audit_policy`; auditing its v2 evidence without
that policy fails rather than silently skipping feature log checks. The adapter
reconciles each claimed fault with raw markers for the exact phase/PID/action and
matching persisted snapshots, including normal/recovery attempts.

The streaming event reader tolerates a currently unfinished writer record while
waiting; the final evidence auditor parses the entire file strictly. These are
separate responsibilities. Neither hashing nor the registration journal is a
signature against deliberate forgery; preserve trusted originals and archive
hashes when publishing test reports.

Historical schema-v1 evidence remains supported by the compatibility audit CLI.
Its sequential Agent/config-name inference is isolated in
`adapters/huatuo/memsnapshot/legacy_audit.py`. Existing published records and raw
failed trials are preserved without rewriting them as new framework runs.

## Memsnapshot-specific limits

The adapter keeps cgroup-v1 threshold semantics, exact read fault attribution,
normal snapshot entry/PID/RSS checks, and at most three captures only for the
observed CPython invalid-GC-metadata failure. Failed attempts remain recorded.
Blocked reads still require supervisor SIGKILL/restart; forced syscall
cancellation is not established. Pod discovery is a local fixture, not a real
Kubernetes control-plane test. Performance remains a separate evaluation.

See [the design](docs/modular-design.md), [implementation plan](docs/modular-plan.md)
and [recorded validation](VALIDATION.md). The suite stays an opt-in isolated-VM job.
