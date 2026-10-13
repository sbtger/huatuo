# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""A second, non-HuaTuo feature exercises the real generic runner and auditor."""
import contextlib
import io
import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class FrameworkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "run"
        try:
            self.models = importlib.import_module(
                "fault_isolation_framework.core.models"
            )
            self.runner = importlib.import_module(
                "fault_isolation_framework.core.runner"
            )
            self.evidence = importlib.import_module(
                "fault_isolation_framework.core.evidence"
            )
            self.audit = importlib.import_module("fault_isolation_framework.core.audit")
        except ImportError:
            self.fail("generic runner/evidence API is not available")

    def tearDown(self):
        self.tmp.cleanup()

    def exercise(
        self,
        hits=1,
        witness=True,
        business_error=False,
        late_error=False,
        recovery_error=False,
        require_policy=False,
        records_error=False,
    ):
        store = self.evidence.EvidenceStore(self.root)
        models = self.models
        rows = []

        class Probe:
            target_id = "payments"
            seq = 0

            def begin(probe, name):
                return {}, 0

            def finish(probe, name, before, started, hits, expected):
                probe.seq += 1
                rows.extend(
                    [
                        dict(phase=name, kind="work", ok=True),
                        dict(phase=name, kind="transaction", ok=True),
                    ]
                )
                (store.output / "payments-requests.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows)
                )
                return dict(
                    samples=1,
                    scheduled=1,
                    completed=1,
                    errors=[],
                    assertion_errors=["bad checksum"] if business_error else [],
                )

            def close(probe):
                if late_error:
                    rows.append(
                        dict(
                            phase="between",
                            kind="work",
                            ok=False,
                            detail="late failure",
                        )
                    )
                    (store.output / "payments-requests.jsonl").write_text(
                        "".join(json.dumps(r) + "\n" for r in rows)
                    )

            def totals(probe):
                return dict(
                    requests=sum(r["kind"] == "work" for r in rows),
                    transactions=probe.seq,
                )

            def records(probe):
                if records_error:
                    raise OSError("cannot read business records")
                return rows

        probe = Probe()

        class Feature:
            adapter_id = "test.payments-reader"
            requires_audit_policy = require_policy
            probes = [probe]
            cleaned = False

            def prepare(feature):
                store.register(
                    "payments-requests.jsonl",
                    "requests",
                    target_id="payments",
                    format="jsonl",
                )

            def plan(feature):
                return ["payments/read-failure", "payments/recovery"]

            def scenarios(feature):
                def failure():
                    store.register("reader.log", "agent_log")
                    (store.output / "reader.log").write_text("reader denied access\n")
                    return models.OperationResult(
                        detail={"reason": "denied"},
                        fault_hits=hits,
                        evidence=["reader.log"] if witness else [],
                    )

                yield models.Scenario(
                    "payments/read-failure",
                    "payments",
                    failure,
                    expect_fault=True,
                    minimum_seconds=0,
                )

                def recovery():
                    if recovery_error == "empty":
                        raise RuntimeError()
                    if recovery_error:
                        raise RuntimeError("recovery unavailable")
                    return models.OperationResult(detail={"recovered": True})

                yield models.Scenario(
                    "payments/recovery", "payments", recovery, minimum_seconds=0
                )

            def quiesce(feature):
                pass

            def verify_final(feature):
                pass

            def audit_artifacts(feature, output, summary, manifest):
                return dict(
                    errors=[], unexpected_agent_logs={}, expected_fault_log_counts={}
                )

            def cleanup(feature):
                feature.cleaned = True

        feature = Feature()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
            io.StringIO()
        ):
            try:
                result = self.runner.Runner(store).execute(feature)
            except OSError:
                self.fail(
                    "record read failure must produce FAIL and still clean resources"
                )
        self.assertTrue(feature.cleaned)
        return result

    def test_second_feature_runs_without_snapshot_schema(self):
        result = self.exercise()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(result["total_business_requests"], {"payments": 2})
        self.assertEqual(self.audit.audit(self.root)["status"], "PASS")

    def test_unreached_fault_fails(self):
        self.assertEqual(self.exercise(hits=0)["status"], "FAIL")

    def test_fault_marker_without_evidence_fails(self):
        self.assertEqual(self.exercise(witness=False)["status"], "FAIL")

    def test_expected_collector_failure_cannot_hide_business_failure(self):
        self.assertEqual(self.exercise(business_error=True)["status"], "FAIL")

    def test_recovery_failure_fails_and_preserves_evidence(self):
        self.assertEqual(self.exercise(recovery_error=True)["status"], "FAIL")
        self.assertTrue((self.root / "reader.log").exists())

    def test_late_business_error_after_phase_fails(self):
        self.assertEqual(self.exercise(late_error=True)["status"], "FAIL")

    def test_missing_registered_evidence_fails_offline_audit(self):
        self.exercise()
        (self.root / "reader.log").unlink()
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_deleted_request_row_fails_offline_accounting(self):
        self.exercise()
        p = self.root / "payments-requests.jsonl"
        p.write_text("\n".join(p.read_text().splitlines()[1:]) + "\n")
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_truncated_request_stream_fails(self):
        self.exercise()
        with (self.root / "payments-requests.jsonl").open("a") as stream:
            stream.write('{"phase":')
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_incomplete_plan_cannot_claim_pass(self):
        self.exercise()
        p = self.root / "summary.json"
        summary = json.loads(p.read_text())
        summary["planned_cases"].append("payments/unexecuted")
        p.write_text(json.dumps(summary))
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_manifest_cannot_forget_a_registered_file(self):
        self.exercise()
        p = self.root / "manifest.json"
        manifest = json.loads(p.read_text())
        manifest["artifacts"] = [
            a for a in manifest["artifacts"] if a["path"] != "reader.log"
        ]
        p.write_text(json.dumps(manifest))
        (self.root / "reader.log").unlink()
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_adapter_policy_cannot_be_skipped_in_offline_audit(self):
        self.assertEqual(self.exercise(require_policy=True)["status"], "PASS")
        self.assertEqual(self.audit.audit(self.root)["status"], "FAIL")

    def test_empty_message_recovery_exception_fails(self):
        self.assertEqual(self.exercise(recovery_error="empty")["status"], "FAIL")

    def test_record_read_exception_fails_and_still_cleans_resources(self):
        self.assertEqual(self.exercise(records_error=True)["status"], "FAIL")

    def test_policy_exception_returns_failed_audit(self):
        self.exercise()

        def broken_policy(output, summary, manifest):
            raise RuntimeError("policy parser failed")

        try:
            result = self.audit.audit(self.root, broken_policy)
        except RuntimeError:
            self.fail("policy exception must return a structured FAIL")
        self.assertEqual(result["status"], "FAIL")

    def test_registration_rejects_outside_path(self):
        store = self.evidence.EvidenceStore(self.root)
        with self.assertRaises(ValueError):
            store.register("../foreign.log", "agent_log")


if __name__ == "__main__":
    unittest.main()
