# Memory snapshot reliability gaps implementation plan

> Use superpowers:executing-plans. User approved the four P0 checks and existing optional fault matrix in this conversation ("搞下"). Continue in the existing isolated feature worktree.

Goal: add executable same-Agent continuity, cross-target fault isolation, target-exit read races and complete cooldown observation. Run bounded VM checks, retaining failures without changing production behavior or weakening gates. No 72h or performance assessment.

Architecture: keep Runner, probes and StabilityAdapter. Put optional operations and independent contracts in a Huatuo reliability module. Existing short CLI stays compatible; --checks selects additional pre-cycle phases. Steady defaults to >=20 rounds, >=1800s, same shipping Agent identity. Other checks run separately so a failing isolation check does not hide race/steady results.

## Tasks
- [x] Add RED controls in existing test_core.py for steady identity/round/duration, full cooldown observations/positive recovery, target isolation witness and target-exit ownership/read-result contracts.
- [x] Implement check planning, CLI budgets, streaming steady progress and policy validation. Same-Agent steady compares all-runtime captures; no restart allowed. Cooldown observes the remaining window and requires a post-expiry successful capture.
- [x] Extend test-only overlay with bounded pause-before-read controlled by fault file, actual read-result marker after release. Delete only disposable target, preserve main business identity and recover on same Agent.
- [x] Add target-specific EFAULT/delay/block isolation cases with healthy-target capture while fault remains active; no replacement until bounded result/timeout. Fail if healthy target cannot complete; preserve expected product limitation as FAIL.
- [x] Baseline77 controls then all controls, build plain/fault binaries, fresh VM short checks for both modules and all eight fault modes. Run same-Agent steady for20 rounds/30minutes per module sequentially.
- [x] One whole-change review, make check, exact coverage/result report including failures, one signed <=75-column commit and normal push to existing feature branch.

Review focus: no event reuse; healthy result must belong to different target and same Agent while fault file active; race must witness actual read after target exit; cooldown cannot pass without positive control; resource samples continue during paced steady waits. Tests may establish a limitation; production fixes are outside this change.

Execution record: the22 original campaigns all ran independently. Memburst
completed20 rounds and1800.002seconds on the same shipping Agent; the newer
threshold steady attempt stopped early on the now-diagnosed pressure-control
writer race. This is incomplete threshold steady acceptance, not a30-minute PASS.
The six optional fault modes were freshly executed for both modules; prior
EFAULT/short-read baselines remain in the earlier validation record. Original
failures and all source snapshots are retained. See RELIABILITY_VALIDATION.md
for exact coverage, diagnosis, separate business verdicts and follow-ups.
