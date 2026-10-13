# Modular fault isolation framework

Approved intent: extract a feature-neutral runner and evidence auditor, retain
HuaTuo memsnapshot as the first real adapter, and preserve every current business
and fault/recovery assertion. This is repository-local Python 3.8+ infrastructure
using only the standard library. Linux/amd64, root, Docker cgroup v1 and the
recorded runtime versions remain requirements of the memsnapshot adapter.

Core owns Scenario/OperationResult, independent probe observation, the declared
phase plan, drain/final accounting, failure propagation and artifact registration.
FeatureAdapter owns preparation, scenario generation, quiescence, final feature
checks, feature log/event policy and cleanup. BusinessProbe owns business request,
state and progress semantics. Docker/Linux utilities own runtime resources.

Scenario contains name, target_id, operation, expect_fault and minimum_seconds.
OperationResult contains detail, fault_hits and relative evidence paths. Probe
operations are begin, finish, close, totals and records. Adapter operations are
prepare, plan, scenarios, quiesce, verify_final, audit_artifacts and cleanup.

Core cannot import adapters or require snapshot fields, tracer names, language
names, HTTP endpoint shapes, state formulas or provider retry behavior. The
HTTP example probe retains the existing SHA body, 13*n updates, independent
reads, PID/start-time checks, scheduler and 1s/2s reliability bounds. These are
fixture contracts rather than performance claims.

Memsnapshot owns its threshold settings, pressure edge/cooldown, overlay/readv
faults, exact failed/partial reasons, recovery mode and the bounded CPython
invalid-GC-metadata retry. HuaTuo's generic command construction and discovery
fixture are shared only within the HuaTuo adapter package.

New schema-v2 evidence includes the complete declared plan, per-phase target and
witness references, registrations.jsonl, manifest.json, artifact hashes and raw
business streams. Registration happens before use; artifact-set equality against
the journal prevents accidentally dropping missing files from the final manifest.
Core checks raw counts, phase samples, complete coverage, reached fault witnesses,
registered references, JSON truncation and digest mismatches. The memsnapshot
policy checks expected/unexpected Agent logs. Its policy is mandatory when
recorded evidence identifies that adapter. Missing/unsupported evidence fails.

Historical schema-v1 audit behavior remains in the memsnapshot package and is
selected by the compatibility CLI. Existing historical reports are preserved.
Root run.py/build.py/audit.py commands remain supported. --adapter defaults to
huatuo.memsnapshot and rejects unknown names. There is no arbitrary plugin import
from an evidence file, pip release, performance work or CI scheduling change.

Acceptance: original 30 tests, generic second-feature negative controls, CLI and
build checks, historic full-matrix audit, make check, focused/full Go checks and a
new real three-language 78-phase run. A test adapter demonstrates API independence;
it does not establish another production agent's reliability.
