# Modular fault isolation framework implementation plan

> Execution: superpowers:executing-plans, inline in the authorized feature branch.

**Goal:** separate reusable execution/evidence code from memsnapshot semantics.
**Architecture:** core protocols and a runner consume independently implemented
business probes and feature adapters. Linux/Docker utilities serve the example
workloads and HuaTuo adapter without requiring feature-specific assertions.
**Tech stack:** Python 3.8+ standard library; existing Go/Java/Python fixtures.
**Spec:** [modular-design.md](modular-design.md).

## Constraints and review focus

Preserve old CLI and historical evidence. Keep production sources unchanged.
Retain continuous canaries, all-row final checks and failed recovery evidence.
Expected feature failure cannot waive business failures. Missing artifacts,
manifest omissions, unreached faults, exceptions during recovery/cleanup and
unsupported adapters must fail. Core must execute a non-HuaTuo test feature.

## Task 1: generic execution and evidence API

Files: core/{models,runner,evidence,audit,util}.py and test_core.py.
Interfaces: Scenario/OperationResult, BusinessProbe/FeatureAdapter and
EvidenceStore.register/expect_document/save; Runner.execute returns summary.
- [x] Write tests for a second feature and unreached/missing-evidence faults.
- [x] Observe RED: generic API unavailable.
- [x] Implement plan coverage, independent probes, drain, registration and audit.
- [x] Verify generic controls including late errors and omitted evidence are GREEN.

## Task 2: move concrete responsibilities and preserve CLI

Files: environments/{linux,docker}.py, workloads/{http_probe,fixtures,services/},
adapters/huatuo/{agent,discovery}.py, adapters/huatuo/memsnapshot/{adapter,trigger,
faults,assertions,log_policy,policy,legacy_audit,build,deny_readv.c}, cli.py and
compatibility entry points.
Interfaces: the adapter implements the core protocol; HTTP probe implements the
probe protocol. Root CLIs import the package without depending on working dir.
- [x] Extract original behavior with existing 30 tests as regression controls.
- [x] Move specific retry, log rules, trigger and fault witnesses into adapter.
- [x] Add mandatory policy and unsupported-adapter negative controls.
- [x] Verify unit suite, legacy 78-phase audit, CLI and builder.

## Task 3: real acceptance and publication-ready documentation

Files: README.md, ARCHITECTURE.md, VALIDATION.md and sanitized results.
- [x] Explain adapter/probe extension and evidence schema/compatibility.
- [x] Run a new three-language real-Agent matrix and audit its raw evidence.
- [x] Run make check, focused Go tests and full Go tests; report environment failures.
- [x] Independent whole-change review; fix important findings with RED/GREEN tests.
- [x] Commit one coherent refactor on the existing feature branch after checks.
