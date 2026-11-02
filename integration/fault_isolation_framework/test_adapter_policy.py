# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Offline claims must agree with the actual fault marker and snapshot."""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.adapters.huatuo.memsnapshot.policy import audit_artifacts


class AttributionTest(unittest.TestCase):
    def test_worker_failure_starts_recovery_cooldown_after_persistence(self):
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from fault_isolation_framework.adapters.huatuo.memsnapshot import worker

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            faultfile = root / "fault.json"
            faultfile.write_text(json.dumps({"requested_epoch": 100}))
            owner = SimpleNamespace(out=root, event_path=root / "events",
                faultfile=faultfile, last_capture=1, evidence=Mock())
            capture = {"status": "failed"}
            with patch.object(worker, "reaped_worker", return_value={}), \
                 patch.object(worker, "failed_capture", return_value=capture), \
                 patch.object(worker.time, "monotonic", return_value=123):
                result = worker.containment(owner, {})
            self.assertEqual(owner.last_capture, 123)
            self.assertEqual(result["failed_worker_capture"]["not_before_epoch"], 100)
            owner.evidence.expect_document.assert_called_once_with("events")

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

class WorkerBoundaryTest(unittest.TestCase):
    def test_missing_timeout_metadata_is_only_allowed_for_explicit_worker_failure(self):
        from fault_isolation_framework.adapters.huatuo.memsnapshot.worker import capture_metadata_errors
        record = dict(language="unknown", snapshot=dict(status="failed", status_reason="memory snapshot worker deadline: context deadline exceeded"))
        self.assertEqual(capture_metadata_errors(record, "go"), [])
        record["snapshot"]["status"] = "complete"
        self.assertTrue(capture_metadata_errors(record, "go"))
        record["snapshot"] = dict(status="failed", status_reason="unrelated failure")
        self.assertTrue(capture_metadata_errors(record, "go"))

    def test_helper_publication_preserves_running_readers_and_selects_fault_binary(self):
        from types import SimpleNamespace
        from fault_isolation_framework.core.evidence import EvidenceStore
        from fault_isolation_framework.adapters.huatuo.memsnapshot.worker import publish_worker
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build = root/"build"
            build.mkdir()
            (build/"huatuo-memsnapshot-worker").write_bytes(b"plain")
            (build/"huatuo-memsnapshot-worker-fault").write_bytes(b"fault")
            evidence = EvidenceStore(root/"out")
            owner = SimpleNamespace(build=build, out=evidence.output, evidence=evidence)
            publish_worker(owner, True)
            with (owner.out/"huatuo-memsnapshot-worker").open("rb") as old:
                publish_worker(owner, False)
                self.assertEqual(old.read(), b"plain")
            self.assertEqual((owner.out/"huatuo-memsnapshot-worker").read_bytes(), b"fault")

    def test_worker_isolation_requires_reap_before_healthy_capture(self):
        from fault_isolation_framework.adapters.huatuo.stability.reliability import contract_errors
        detail = dict(mode="block", fault_pid=3, healthy_pid=4, agent_before=[1,2], agent_after=[1,2],
            fault_active=True, marker="MEMSNAP_FAULT", healthy_capture=dict(target_pid=4,normal_attempts=[{}]),
            healthy_started_ns=30, healthy_finished_ns=40, read_active_ns=10, read_end_ns=20,
            worker_isolation=True,worker_identity=[7,9],worker_request_id=1,worker_reaped_ns=25,worker_gone=True,
            worker_started_log='msg="memory snapshot worker started" worker_pid="7" worker_start_ticks="9" request_id="1" target_pid="3"',
            worker_reaped_log='msg="memory snapshot worker reaped" worker_pid="7" worker_start_ticks="9" request_id="1" target_pid="3"',
            failed_worker_capture=dict(status="failed",reason="memory snapshot worker: context deadline exceeded"))
        self.assertEqual(contract_errors("isolation", detail), [])
        detail["worker_gone"] = False
        self.assertTrue(contract_errors("isolation", detail))
        detail["worker_gone"], detail["worker_reaped_ns"] = True, 35
        self.assertTrue(contract_errors("isolation", detail))

    def test_worker_audit_rejects_substituted_raw_failed_event(self):
        from fault_isolation_framework.adapters.huatuo.memsnapshot.worker import audit_worker_capture
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"events-1").mkdir()
            (root/"agent-1.json").write_text(json.dumps(dict(pid=1)))
            event = root/"events-1/memburst"
            document = dict(started_timestamp="1970-01-01T00:00:11Z",tracer_data=dict(process_snapshots=[dict(pid=3,language="unknown",snapshot=dict(status="failed",status_reason="memory snapshot worker deadline",entries=[]))]))
            event.write_text(json.dumps(document))
            capture = dict(event_file="/original/events-1/memburst",event_index=0,target_pid=3,agent_pid=1,status="failed",reason="memory snapshot worker deadline",entries=0,not_before_epoch=10)
            witness = dict(fault_config=dict(requested_epoch=10,pid=3),worker_identity=[7,9],request_id=1,gone=True,reaped_ns=25,agent=[1,2])
            (root/"worker.json").write_text(json.dumps(witness))
            detail = dict(fault_pid=3,agent_before=[1,2],failed_worker_capture=capture,worker_witness="worker.json",worker_identity=[7,9],worker_request_id=1,worker_reaped_ns=25)
            evidence = ["agent-1.log","events-1/memburst","worker.json"]
            self.assertEqual(audit_worker_capture(root, detail, evidence), [])
            witness["worker_identity"] = [8,9]
            (root/"worker.json").write_text(json.dumps(witness))
            self.assertTrue(audit_worker_capture(root, detail, evidence))
            witness["worker_identity"] = [7,9]
            (root/"worker.json").write_text(json.dumps(witness))
            document["tracer_data"]["process_snapshots"][0]["snapshot"]["status"] = "complete"
            event.write_text(json.dumps(document))
            self.assertTrue(audit_worker_capture(root, detail, evidence))
            document["tracer_data"]["process_snapshots"][0]["snapshot"]["status"] = "failed"
            document["started_timestamp"] = "1970-01-01T00:00:09Z"
            event.write_text(json.dumps(document))
            self.assertTrue(audit_worker_capture(root, detail, evidence))
            event.unlink()
            self.assertTrue(audit_worker_capture(root, detail, evidence))

    def test_target_exit_can_cancel_worker_before_resume_without_claiming_esrch(self):
        from fault_isolation_framework.adapters.huatuo.stability.reliability import contract_errors
        detail = dict(target_gone=True,target_pid=3,agent_before=[1,2],agent_after=[1,2],recovery=dict(normal_attempts=[{}]),
            target_exit_cancelled=True,worker_isolation=True,worker_identity=[7,9],worker_request_id=1,worker_gone=True,
            worker_started_log='msg="memory snapshot worker started" worker_pid="7" worker_start_ticks="9" request_id="1" target_pid="3"',
            worker_reaped_log='msg="memory snapshot worker reaped" worker_pid="7" worker_start_ticks="9" request_id="1" target_pid="3"',
            cancellation_log='capture process memory: context canceled')
        self.assertEqual(contract_errors("target-exit", detail), [])
        detail["worker_gone"] = False
        self.assertTrue(contract_errors("target-exit", detail))
