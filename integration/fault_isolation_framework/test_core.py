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


class StabilityControlsTest(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module("fault_isolation_framework.core.stability")
        except ImportError:
            self.fail("stability supervision and coverage API is missing")

    def test_campaign_missing_cycles_or_duration_cannot_pass(self):
        api = self.api()
        self.assertTrue(api.coverage_errors(2, 10, [dict(cycle=1, status="PASS")], 10))
        self.assertTrue(api.coverage_errors(1, 10, [dict(cycle=1, status="PASS")], 9))
        self.assertFalse(api.coverage_errors(1, 10, [dict(cycle=1, status="PASS")], 10))

    def test_campaign_duplicate_cycles_cannot_replace_missing_cycles(self):
        api = self.api()
        rows = [dict(cycle=1, status="PASS"), dict(cycle=1, status="PASS")]
        self.assertTrue(api.coverage_errors(2, 0, rows, 10))

    def test_resource_growth_is_compared_within_same_agent_identity(self):
        api = self.api()
        rows = [
            dict(agent=[10, 1], rss_bytes=10, fds=3),
            dict(agent=[10, 1], rss_bytes=30, fds=9),
            dict(agent=[10, 2], rss_bytes=100, fds=20),
        ]
        self.assertTrue(
            api.resource_errors(
                rows, rss_growth=10, fd_growth=3, rss_limit=200, fd_limit=100
            )
        )
        self.assertFalse(
            api.resource_errors(
                rows, rss_growth=100, fd_growth=10, rss_limit=200, fd_limit=100
            )
        )

    def test_resource_evidence_missing_or_observer_failure_fails(self):
        api = self.api()
        self.assertTrue(api.resource_errors([], 10, 3, 200, 100))
        self.assertTrue(
            api.resource_errors([dict(error="observer died")], 10, 3, 200, 100)
        )

    def test_supervisor_stops_hung_controller(self):
        import subprocess

        from fault_isolation_framework.environments.supervisor import supervise

        with tempfile.TemporaryDirectory() as output:
            result = supervise(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                Path(output),
                timeout=0.3,
                phase_timeout=0.2,
            )
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("timeout", result["reason"])
            self.assertNotEqual(result["returncode"], 0)


class StabilityEvidenceControlsTest(unittest.TestCase):
    def test_raw_resource_sampling_gap_fails_repeated_audit(self):
        from fault_isolation_framework.core.stability import resource_errors

        rows = [
            dict(time=0, agent=[1, 1], rss_bytes=10, fds=2),
            dict(time=40, agent=[1, 1], rss_bytes=10, fds=2),
        ]
        self.assertTrue(resource_errors(rows, 100, 100, 200, 200))

    def test_campaign_counts_come_from_raw_phase_operations(self):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.policy import (
                phase_counts,
            )
        except ImportError:
            self.fail("raw phase coverage accounting is missing")
        cases = [
            dict(
                name="cycle-0001/go/lifecycle",
                detail=dict(
                    replacements=[
                        {"capture": {"event_file": "e", "normal_attempts": [{}]}}
                    ]
                ),
            ),
            dict(
                name="cycle-0001/go/limit-change",
                detail=dict(captures=[{"event_file": "e", "normal_attempts": [{}]}]),
            ),
        ]
        actual = phase_counts(cases)
        self.assertEqual(actual["captures"], 2)
        self.assertEqual(actual["cgroup_replacements"], 1)
        self.assertEqual(actual["limit_changes"], 1)


class GrowthCoverageTest(unittest.TestCase):
    def test_warmed_agent_without_endpoint_cannot_claim_growth_checked(self):
        from fault_isolation_framework.core.stability import resource_errors

        rows = [dict(agent=[1, 2], rss_bytes=10, fds=3, settled=True, baseline=True)]
        self.assertTrue(resource_errors(rows, 100, 100, 200, 200))
        rows.append(dict(agent=[1, 2], rss_bytes=12, fds=3, settled=True))
        self.assertFalse(resource_errors(rows, 100, 100, 200, 200))


class SupervisorHeartbeatTest(unittest.TestCase):
    def test_stopped_resource_observer_aborts_even_with_large_phase_budget(self):
        from fault_isolation_framework.environments.supervisor import supervise

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            script = 'from pathlib import Path; import sys,time; Path(sys.argv[1]).write_text("{}\\n"); time.sleep(30)'
            try:
                result = supervise(
                    [
                        sys.executable,
                        "-c",
                        script,
                        str(root / "evidence/resources.jsonl"),
                    ],
                    root,
                    timeout=30,
                    phase_timeout=30,
                    observer_timeout=0.2,
                )
            except TypeError:
                self.fail("supervisor resource-heartbeat deadline is missing")
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("observer", result["reason"])


class RecoveryPolicyTest(unittest.TestCase):
    def test_normal_capture_requires_nonempty_supported_result_and_bounded_retry(self):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.policy import (
                normal_capture_errors,
            )
        except ImportError:
            self.fail("normal recovery audit gate is missing")
        bad = dict(
            normal_attempts=[dict(status="failed", entries=0, reason="bad address")]
        )
        self.assertTrue(normal_capture_errors(bad, "go"))
        good = dict(
            normal_attempts=[
                dict(
                    status="failed",
                    entries=0,
                    reason="CPython interpreter GC generations are invalid",
                ),
                dict(status="complete", entries=7, reason=""),
            ]
        )
        self.assertFalse(normal_capture_errors(good, "python"))
        self.assertTrue(normal_capture_errors(good, "go"))
        good["normal_attempts"] *= 2
        self.assertTrue(normal_capture_errors(good, "python"))


class BurstStimulusTest(unittest.TestCase):
    def test_anon_floor_waits_for_target_to_enter_rss_ranking(self):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.trigger import (
                burst_anon_floor,
            )
        except ImportError:
            self.fail("memburst target-ranking pressure floor is missing")
        total = 16 * 1024 * 1024
        baseline = 1024 * 1024
        percent = burst_anon_floor(total, baseline)
        self.assertGreaterEqual(total * percent / 100, baseline + 256 * 1024)
        self.assertLess(total * percent / 100, baseline + 500 * 1024)


class BurstConfigurationTest(unittest.TestCase):
    def test_memburst_config_renders_both_pressure_floor_and_cooldown(self):
        from types import SimpleNamespace
        from fault_isolation_framework.adapters.huatuo.stability.adapter import (
            StabilityAdapter,
        )

        adapter = StabilityAdapter.__new__(StabilityAdapter)
        adapter.tracer_name = "memburst"
        adapter.a = SimpleNamespace(cooldown=8, agent_port=19704)
        adapter.server = SimpleNamespace(server_port=10250)
        adapter.api = "1.52"
        from unittest.mock import patch

        with patch(
            "pathlib.Path.read_text",
            return_value="MemTotal: 16777216 kB\nActive(anon): 1024 kB\nInactive(anon): 1047552 kB\n",
        ):
            text = adapter.configuration(Path("/tmp/test-events"), [])
        self.assertIn("IntervalTracing = 8", text)
        import re

        floor = int(re.search(r"DeltaAnonThreshold = (\d+)", text).group(1))
        self.assertGreater(floor, 0)


class StreamingHashTest(unittest.TestCase):
    def test_final_manifest_hash_does_not_load_entire_request_file(self):
        from unittest.mock import patch
        from fault_isolation_framework.core.evidence import EvidenceStore

        with tempfile.TemporaryDirectory() as tmp:
            store = EvidenceStore(Path(tmp) / "evidence")
            store.register("stream.jsonl", "requests", format="jsonl")
            (store.output / "stream.jsonl").write_text('{"ok":true}\n' * 100)
            with patch(
                "pathlib.Path.read_bytes", side_effect=AssertionError("whole file read")
            ):
                store.save({"status": "PASS"})
            self.assertIn(
                "sha256",
                json.loads((store.output / "manifest.json").read_text())["artifacts"][
                    0
                ],
            )


class ComparableWarmupTest(unittest.TestCase):
    def test_mixed_runtime_agent_baseline_waits_for_all_runtime_warmups(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fault_isolation_framework.adapters.huatuo.stability.adapter import (
            StabilityAdapter,
        )

        adapter = StabilityAdapter.__new__(StabilityAdapter)
        adapter.agent = SimpleNamespace(pid=1)
        adapter.targets = [dict(language=lang) for lang in ("go", "java", "python")]
        adapter.warmed_agents = set()
        adapter.warmed_languages = {}
        adapter.counts = dict(captures=0)
        rows = []
        adapter.monitor = SimpleNamespace(record=lambda **row: rows.append(row))
        adapter.trigger = SimpleNamespace(
            capture=lambda *a, **kw: {}, release_all=lambda: None
        )
        with patch(
            "fault_isolation_framework.adapters.huatuo.stability.adapter.identity",
            return_value=[1, 2],
        ):
            adapter.capture(adapter.targets[0])
            self.assertEqual(
                rows, [], "Go-only cache state is not a mixed-runtime baseline"
            )
            adapter.capture(adapter.targets[1])
            self.assertEqual(rows, [])
            adapter.capture(adapter.targets[2])
            self.assertEqual(len(rows), 1)
            adapter.capture(adapter.targets[0])
            self.assertEqual(len(rows), 1)


class ShippingAgentControlTest(unittest.TestCase):
    def test_steady_campaign_starts_shipping_agent_even_when_faults_are_selected(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fault_isolation_framework.adapters.huatuo.stability.adapter import (
            StabilityAdapter,
        )

        adapter = StabilityAdapter.__new__(StabilityAdapter)
        adapter.agent = None
        adapter.a = SimpleNamespace(inject_faults=True)
        selected = []

        def start(**kwargs):
            selected.append(kwargs)
            adapter.agent = SimpleNamespace(pid=1)

        adapter.start_agent = start
        adapter.targets = [dict(language="go")]
        adapter.warmed_agents, adapter.warmed_languages = set(), {}
        adapter.counts = dict(captures=0)
        adapter.monitor = SimpleNamespace(record=lambda **kw: None)
        adapter.trigger = SimpleNamespace(
            capture=lambda *a, **kw: {}, release_all=lambda: None
        )
        with patch(
            "fault_isolation_framework.adapters.huatuo.stability.adapter.identity",
            return_value=[1, 2],
        ):
            adapter.capture(adapter.targets[0])
        self.assertEqual(selected, [dict(plain=True)])
