# Memory snapshot stability implementation plan

> Use superpowers:executing-plans. The approved specification is the stability design in this conversation.

Goal: extend the existing fault-isolation framework with real-Agent memburst and threshold stability suites, rebase onto upstream main, validate short profiles in the isolated VM, and document executable coverage and limits. No 72-hour execution or performance claim.

Architecture: retain Runner/BusinessProbe/EvidenceStore; add module adapters and bounded observation/supervision. Existing 58 controls remain the regression gate. Short/soak profiles share code and differ in duration/cycle quotas. No shipping Go code or generated files are hand edited.

## Task 1: rebase and compatibility
- [x] Preserve original refs and bundle; rebase the two framework commits onto top/main 8a627bdc0 in an isolated remote worktree.
- [x] Build fresh plain/fault Agents and fixtures; run all framework tests; repair changed anchors/contracts only with failing regression controls.

## Task 2: stability infrastructure
- [x] Add failing controls in existing test_core.py/test_resources.py for coverage quotas, elapsed duration, resource drift, missing samples, supervisor hard timeout, bounded request retention and audit attribution.
- [x] Implement cycle planning, disk-backed business records, resource sampling/checkpoints and independent supervision. Preserve ordinary fault-isolation CLI behavior.
- [x] Implement memburst real host-memory trigger and ranked snapshot validation; reuse threshold trigger and real business fixtures. Add faults/recovery, cooldown, limit changes, disposable cgroup replacement, Agent replacement and storage failure.
- [x] Run all controls and review fail-closed behavior; unknown/missing coverage must never become PASS.

## Task 3: VM validation and publication-ready plan
- [x] Run fresh short profiles for both adapters with Go/Java/Python in 140's VM, preserving failed trials and raw evidence.
- [x] Independently audit raw evidence and check cleanup. Record exact tested revisions, build/source hashes, scenario counts and all limits.
- [x] Write STABILITY_PLAN.md with commands, scenario definitions, quotas and assertion/report mapping, separating implemented, short-validated and unvalidated coverage.
- [x] Run make check and relevant Go regression; one whole-branch review and fix material findings; produce concise signed commits with messages wrapped to 75 columns.

## Review focus
Supervision while the controller hangs; no leaked process groups/containers; fault attribution cannot borrow unrelated errors; lifecycle fixture identity changes cannot waive canary identity checks; audit must detect dropped resource/request evidence. No guaranteed PID reuse, cgroup-v2, Agent OOM/FD or 72-hour claim without actual evidence.
