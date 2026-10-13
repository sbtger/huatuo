# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Offline claims must agree with the actual fault marker and snapshot."""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.adapters.huatuo.memsnapshot.policy import audit_artifacts


class AttributionTest(unittest.TestCase):
    def fixture(
        self, root, marker=True, pid=42, snapshot_status="failed", reason="bad address"
    ):
        (root / "environment.json").write_text(
            json.dumps(
                {"targets": [{"language": "go", "cid": "business-go", "pid": 42}]}
            )
        )
        (root / "agent-1.log").write_text(
            "MEMSNAP_FAULT id=go/efault action=efault pid=%d stage=read\n" % pid
            if marker
            else 'level="info" msg="ready"\n'
        )
        (root / "bamai-1.conf").write_text("ThresholdPercent = 60\n")
        (root / "events-1").mkdir()
        (root / "events-1/memory_threshold_snapshot").write_text(
            json.dumps(
                {
                    "container_id": "business-go",
                    "tracer_data": {
                        "victim_pid": 42,
                        "language": "go",
                        "process_memory": {"rss_bytes": 123},
                        "snapshot": {
                            "status": snapshot_status,
                            "status_reason": reason,
                            "entries": [],
                        },
                    },
                }
            )
        )
        summary = {
            "cases": [
                {
                    "name": "go/efault",
                    "target_id": "go",
                    "expect_fault": True,
                    "fault_hits": 1,
                    "evidence": [
                        "agent-1.log",
                        "bamai-1.conf",
                        "events-1/memory_threshold_snapshot",
                    ],
                    "detail": {
                        "status": "failed",
                        "reason": "bad address",
                        "entries": 0,
                        "event_file": "/original/events-1/memory_threshold_snapshot",
                    },
                }
            ]
        }
        manifest = {
            "artifacts": [
                {"path": "agent-1.log", "role": "agent_log"},
                {"path": "bamai-1.conf", "role": "agent_config"},
                {"path": "events-1/memory_threshold_snapshot", "role": "feature_event"},
            ]
        }
        return summary, manifest

    def exercise(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary, manifest = self.fixture(root, **kwargs)
            return audit_artifacts(root, summary, manifest)

    def test_matching_raw_fault_passes(self):
        self.assertEqual(self.exercise()["errors"], [])

    def test_claimed_fault_without_raw_marker_fails(self):
        self.assertTrue(self.exercise(marker=False)["errors"])

    def test_marker_for_another_pid_fails(self):
        self.assertTrue(self.exercise(pid=43)["errors"])

    def test_raw_complete_snapshot_cannot_prove_claimed_failure(self):
        self.assertTrue(self.exercise(snapshot_status="complete")["errors"])

    def test_raw_unrelated_failure_cannot_prove_efault(self):
        self.assertTrue(self.exercise(reason="unsupported runtime")["errors"])
