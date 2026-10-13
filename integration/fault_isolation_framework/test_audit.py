# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Reject incomplete copied evidence even when the summary claims PASS."""
import json
import tempfile
import unittest
from pathlib import Path
from audit import audit


class EvidenceAuditTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def write(self, name, document):
        (self.root / name).write_text(json.dumps(document) + "\n")

    def fixture(self):
        self.write("environment.json", {"targets": [{"language": "go"}]})
        self.write(
            "summary.json",
            {
                "status": "PASS",
                "case_count": 1,
                "total_business_requests": {"go": 1},
                "total_business_transactions": {"go": 1},
                "evidence_files": {
                    "agent_logs": ["agent-1.log"],
                    "configs": ["bamai-1.conf"],
                    "request_streams": ["go-requests.jsonl"],
                },
                "cases": [
                    {
                        "name": "go/plain-agent",
                        "status": "PASS",
                        "detail": {},
                        "business": {"go": {"samples": 1, "assertion_errors": []}},
                    }
                ],
            },
        )
        (self.root / "agent-1.log").write_text('level="info" msg="ready"\n')
        (self.root / "bamai-1.conf").write_text("ThresholdPercent = 60\n")
        (self.root / "go-requests.jsonl").write_text(
            json.dumps({"phase": "go/plain-agent", "kind": "work", "ok": True})
            + "\n"
            + json.dumps({"phase": "go/plain-agent", "kind": "transaction", "ok": True})
            + "\n"
        )

    def test_complete_evidence_passes(self):
        self.fixture()
        self.assertEqual(audit(self.root)["status"], "PASS")

    def test_summary_without_raw_records_fails(self):
        self.write("summary.json", {"status": "PASS", "case_count": 78})
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_missing_request_stream_fails(self):
        self.fixture()
        (self.root / "go-requests.jsonl").unlink()
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_missing_agent_log_fails(self):
        self.fixture()
        (self.root / "agent-1.log").unlink()
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_deleted_work_row_fails_accounting(self):
        self.fixture()
        self.write(
            "go-requests.jsonl",
            {"phase": "go/plain-agent", "kind": "transaction", "ok": True},
        )
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_deleted_transaction_row_fails_accounting(self):
        self.fixture()
        self.write(
            "go-requests.jsonl", {"phase": "go/plain-agent", "kind": "work", "ok": True}
        )
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_truncated_jsonl_fails(self):
        self.fixture()
        with (self.root / "go-requests.jsonl").open("a") as stream:
            stream.write('{"kind":')
        self.assertEqual(audit(self.root)["status"], "FAIL")

    def test_missing_snapshot_event_file_fails(self):
        self.fixture()
        summary = json.loads((self.root / "summary.json").read_text())
        summary["cases"][0]["detail"][
            "event_file"
        ] = "/original/vm/events-1/memory_threshold_snapshot"
        self.write("summary.json", summary)
        self.assertEqual(audit(self.root)["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
