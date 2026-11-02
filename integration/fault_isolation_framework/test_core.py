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

    def test_partial_feature_failure_still_audits_observed_business_streams(self):
        self.exercise(hits=0)
        result = self.audit.audit(self.root)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result.get("business_audit_status"), "PASS")
        self.assertEqual(result["total_work_requests"], {"payments": 1})

    def test_partial_plan_cannot_hide_bad_between_phase_business_records(self):
        self.exercise(hits=0, late_error=True)
        result = self.audit.audit(self.root)
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result.get("business_audit_status"), "FAIL")
        self.assertTrue(result["business_errors"])

    def test_partial_business_is_unverified_when_request_evidence_is_missing(self):
        self.exercise(hits=0)
        (self.root / "payments-requests.jsonl").unlink()
        result = self.audit.audit(self.root)
        self.assertEqual(result.get("business_audit_status"), "UNVERIFIED")

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


class ReliabilityContractsTest(unittest.TestCase):
    def contract(self, name, detail):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.reliability import (
                contract_errors,
            )
        except ImportError:
            self.fail("reliability evidence contracts are unavailable")
        return contract_errors(name, detail)

    def test_steady_replacement_and_short_observation_fail(self):
        self.assertTrue(
            self.contract(
                "steady",
                dict(
                    rounds=20,
                    minimum_rounds=20,
                    elapsed_seconds=1800,
                    minimum_seconds=1800,
                    identities=[[1, 2], [2, 3]],
                    agent_binary="agent",
                    captures=[],
                ),
            )
        )

    def test_cooldown_requires_full_observation_and_positive_capture(self):
        self.assertTrue(
            self.contract(
                "cooldown",
                dict(
                    suppressed=True,
                    observed_seconds=0.5,
                    samples=[0],
                    post_expiry_capture={},
                ),
            )
        )

    def test_isolation_requires_different_live_target_and_same_agent(self):
        self.assertTrue(
            self.contract(
                "isolation",
                dict(
                    fault_pid=3,
                    healthy_pid=3,
                    agent_before=[1, 2],
                    agent_after=[1, 2],
                    fault_active=True,
                    marker="MEMSNAP_FAULT",
                    healthy_capture={},
                ),
            )
        )

    def test_target_exit_requires_read_after_exit_and_same_agent_recovery(self):
        self.assertTrue(
            self.contract(
                "target-exit",
                dict(
                    target_gone=True,
                    read_result="",
                    agent_before=[1, 2],
                    agent_after=[1, 2],
                    recovery={},
                ),
            )
        )

    def test_steady_cannot_claim_rounds_without_all_runtime_captures(self):
        detail = dict(
            rounds=20,
            minimum_rounds=20,
            elapsed_seconds=1800,
            minimum_seconds=1800,
            identities=[[1, 2]],
            agent_binary="agent",
            languages=["go", "java", "python"],
            round_results=[
                dict(round=i + 1, agent=[1, 2], captures=[]) for i in range(20)
            ],
        )
        self.assertTrue(self.contract("steady", detail))

    def test_cooldown_negative_window_must_precede_expiry(self):
        detail = dict(
            initial_event_count=1,
            observed_seconds=4,
            cooldown_deadline=8,
            observations=[dict(at=i, events=1) for i in [5, 7, 9]],
            post_expiry_capture=dict(normal_attempts=[{}]),
        )
        self.assertTrue(self.contract("cooldown", detail))

    def test_steady_accepts_complete_rounds_but_rejects_one_missing_language(self):
        captures = [
            dict(target_language=language, agent_pid=1)
            for language in ["go", "java", "python"]
        ]
        detail = dict(
            rounds=20,
            minimum_rounds=20,
            elapsed_seconds=1800,
            minimum_seconds=1800,
            identities=[[1, 2]],
            agent_binary="agent",
            languages=["go", "java", "python"],
            round_results=[
                dict(round=i + 1, agent=[1, 2], captures=list(captures))
                for i in range(20)
            ],
        )
        self.assertEqual(self.contract("steady", detail), [])
        detail["round_results"][10]["captures"].pop()
        self.assertTrue(self.contract("steady", detail))

    def test_cooldown_cannot_skip_middle_of_observation_window(self):
        detail = dict(
            initial_event_count=1,
            observed_seconds=7,
            observation_started=0,
            cooldown_deadline=7,
            observations=[dict(at=i, events=1) for i in [0, 1, 7]],
            post_expiry_capture=dict(normal_attempts=[{}]),
        )
        self.assertTrue(self.contract("cooldown", detail))

    def test_target_exit_audit_rejects_success_for_dead_target(self):
        from fault_isolation_framework.adapters.huatuo.stability.reliability import (
            audit_check,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent-1.log").write_text("MARK\nerr=no such process\n")
            (root / "events-1").mkdir()
            (root / "events-1/memburst").write_text(
                json.dumps(
                    dict(
                        tracer_data=dict(
                            process_snapshots=[
                                dict(pid=9, snapshot=dict(status="complete"))
                            ]
                        )
                    )
                )
            )
            detail = dict(
                check="target-exit",
                module="memburst",
                target_pid=9,
                target_gone=True,
                marker="MARK",
                read_result="err=no such process",
                agent_before=[1, 2],
                agent_after=[1, 2],
                recovery=dict(normal_attempts=[{}]),
            )
            case = dict(
                name="go/target-exit",
                detail=detail,
                evidence=["agent-1.log", "events-1/memburst"],
            )
            self.assertTrue(audit_check(root, case))

    def test_delay_isolation_cannot_pass_after_fault_has_already_finished(self):
        detail = dict(
            mode="delay",
            fault_pid=3,
            healthy_pid=4,
            agent_before=[1, 2],
            agent_after=[1, 2],
            fault_active=True,
            marker="MEMSNAP_FAULT",
            healthy_capture=dict(normal_attempts=[{}]),
            healthy_started_ns=30,
            healthy_finished_ns=40,
            read_active_ns=10,
            read_end_ns=20,
        )
        self.assertTrue(self.contract("isolation", detail))

    def test_memburst_cooldown_uses_trigger_time_before_snapshot_completion(self):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.reliability import (
                cooldown_boundary,
            )
        except ImportError:
            self.fail("cooldown has no module-specific raw timestamp boundary")
        doc = dict(
            started_timestamp="1970-01-01T00:00:00Z",
            uploaded_timestamp="1970-01-01T00:00:05Z",
        )
        self.assertAlmostEqual(cooldown_boundary("memburst", doc, 8, 6, 100), 101.8)
        self.assertAlmostEqual(
            cooldown_boundary("memory_threshold_snapshot", doc, 8, 6, 100), 106.8
        )

    def test_isolation_cannot_omit_another_selected_healthy_runtime(self):
        detail = dict(
            mode="efault",
            fault_pid=3,
            healthy_pid=4,
            agent_before=[1, 2],
            agent_after=[1, 2],
            fault_active=True,
            marker="MEMSNAP_FAULT",
            healthy_capture=dict(normal_attempts=[{}]),
            required_healthy_targets=2,
            additional_healthy_captures=[],
        )
        self.assertTrue(self.contract("isolation", detail))

    def test_isolation_cannot_count_one_healthy_target_twice(self):
        capture = dict(target_pid=4, normal_attempts=[{}])
        detail = dict(
            mode="efault",
            fault_pid=3,
            healthy_pid=4,
            agent_before=[1, 2],
            agent_after=[1, 2],
            fault_active=True,
            marker="MEMSNAP_FAULT",
            healthy_capture=capture,
            required_healthy_targets=2,
            expected_healthy_pids=[4, 5],
            additional_healthy_captures=[dict(capture)],
        )
        self.assertTrue(self.contract("isolation", detail))

    def test_isolation_audit_rejects_witness_for_another_fault_target(self):
        from fault_isolation_framework.adapters.huatuo.stability.reliability import (
            audit_check,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "environment.json").write_text(
                json.dumps(dict(targets=[dict(pid=p) for p in [3, 4, 5]]))
            )
            (root / "agent-1.log").write_text("MARK\n")
            (root / "attempt.json").write_text(json.dumps(dict(fault_pid=99)))
            detail = dict(
                check="isolation",
                mode="efault",
                fault_pid=3,
                healthy_pid=4,
                agent_before=[1, 2],
                agent_after=[1, 2],
                fault_active=True,
                marker="MARK",
                healthy_capture=dict(target_pid=4, normal_attempts=[{}]),
                additional_healthy_captures=[dict(target_pid=5, normal_attempts=[{}])],
                required_healthy_targets=2,
                expected_healthy_pids=[4, 5],
                witness="attempt.json",
            )
            self.assertTrue(
                audit_check(
                    root,
                    dict(
                        name="go/isolation",
                        detail=detail,
                        evidence=["agent-1.log", "attempt.json"],
                    ),
                )
            )

    def test_selected_steady_check_cannot_be_silently_skipped(self):
        try:
            from fault_isolation_framework.adapters.huatuo.stability.reliability import (
                selected_check_errors,
            )
        except ImportError:
            self.fail("audit does not reconcile selected checks with command line")
        self.assertTrue(
            selected_check_errors(
                ["stability.py", "--checks", "steady"],
                [dict(name="cycle-0001/go/capture", detail={})],
            )
        )
        self.assertTrue(
            selected_check_errors(
                ["stability.py", "--checks=steady", "--steady-seconds=3600"],
                [
                    dict(
                        name="cycle-0000/go/steady",
                        detail=dict(
                            check="steady", minimum_rounds=20, minimum_seconds=1800
                        ),
                    )
                ],
            )
        )

    def test_selected_isolation_cannot_substitute_a_weaker_fault_mode(self):
        from fault_isolation_framework.adapters.huatuo.stability.reliability import (
            selected_check_errors,
        )

        self.assertTrue(
            selected_check_errors(
                ["stability.py", "--checks", "isolation-block"],
                [
                    dict(
                        name="cycle-0000/go/isolation-block",
                        detail=dict(check="isolation", mode="efault"),
                    )
                ],
            )
        )

    def test_inotify_watch_leak_is_detected_even_when_fd_count_is_constant(self):
        from fault_isolation_framework.core.stability import resource_errors

        rows = [
            dict(
                time=t,
                agent=[1, 2],
                rss_bytes=10,
                fds=3,
                threads=22,
                inotify_watches=w,
                settled=True,
                baseline=(t == 0),
            )
            for t, w in [(0, 3), (2, 4)]
        ]
        try:
            errors = resource_errors(
                rows, 64, 16, 512, 512, watch_growth=0, thread_growth=16
            )
        except TypeError:
            self.fail("resource gates omit inotify watch and thread growth")
        self.assertTrue(errors)
        rows[1]["inotify_watches"] = 3
        rows[1]["threads"] = 39
        self.assertTrue(
            resource_errors(rows, 64, 16, 512, 512, watch_growth=0, thread_growth=16)
        )
        rows[1]["threads"] = 22
        self.assertEqual(
            resource_errors(rows, 64, 16, 512, 512, watch_growth=0, thread_growth=16),
            [],
        )

    def test_watch_budget_cannot_pass_without_raw_watch_samples(self):
        from fault_isolation_framework.core.stability import resource_errors

        rows = [dict(time=0, agent=[1, 2], rss_bytes=10, fds=3, threads=22)]
        try:
            self.assertTrue(
                resource_errors(
                    rows, 64, 16, 512, 512, watch_growth=0, thread_growth=16
                )
            )
        except TypeError:
            self.fail("resource gates cannot require raw watch observations")

    def test_late_persisted_pre_request_event_is_not_a_new_capture(self):
        try:
            from fault_isolation_framework.adapters.huatuo.memsnapshot.trigger import (
                event_after_request,
            )
        except ImportError:
            self.fail("capture does not reject asynchronous pre-request events")
        self.assertFalse(
            event_after_request(dict(started_timestamp="1970-01-01T00:00:05Z"), 8)
        )
        self.assertTrue(
            event_after_request(dict(started_timestamp="1970-01-01T00:00:09Z"), 8)
        )

    def test_fresh_agent_starts_below_pressure_to_avoid_untracked_startup_capture(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fault_isolation_framework.adapters.huatuo.stability.adapter import (
            StabilityAdapter,
        )

        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "target_mb"
            control.write_text("500")
            adapter = StabilityAdapter.__new__(StabilityAdapter)
            adapter.agent = None
            adapter.targets = [dict(language="go")]
            adapter.warmed_agents, adapter.warmed_languages = set(), {}
            adapter.counts = dict(captures=0)
            adapter.monitor = SimpleNamespace(record=lambda **kw: None)
            adapter.trigger = SimpleNamespace(
                capture=lambda *a, **kw: {}, release_all=lambda: control.write_text("0")
            )

            def start(**kwargs):
                self.assertEqual(
                    control.read_text(),
                    "0",
                    "Agent may capture high pressure before driver records its event baseline",
                )
                adapter.agent = SimpleNamespace(pid=1)

            adapter.start_agent = start
            with patch(
                "fault_isolation_framework.adapters.huatuo.stability.adapter.identity",
                return_value=[1, 2],
            ):
                adapter.capture(adapter.targets[0])

    def test_normal_capture_clears_other_pressure_sources_even_with_live_agent(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fault_isolation_framework.adapters.huatuo.stability.adapter import (
            StabilityAdapter,
        )

        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / "other-target-mb"
            other.write_text("500")
            adapter = StabilityAdapter.__new__(StabilityAdapter)
            adapter.agent = SimpleNamespace(pid=1)
            adapter.targets = [dict(language="go"), dict(language="java")]
            adapter.warmed_agents, adapter.warmed_languages = set(), {}
            adapter.counts = dict(captures=0)
            adapter.monitor = SimpleNamespace(record=lambda **kw: None)

            def capture(*args, **kwargs):
                self.assertEqual(
                    other.read_text(),
                    "0",
                    "single-target edge is confounded by a previous pressure source",
                )
                return {}

            adapter.trigger = SimpleNamespace(
                capture=capture, release_all=lambda: other.write_text("0")
            )
            with patch(
                "fault_isolation_framework.adapters.huatuo.stability.adapter.identity",
                return_value=[1, 2],
            ):
                adapter.capture(adapter.targets[0])


class ControlPublicationTest(unittest.TestCase):
    def test_existing_reader_never_sees_a_rewritten_pressure_value(self):
        util = importlib.import_module("fault_isolation_framework.core.util")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target_mb"
            path.write_text("500")
            with path.open() as reader:
                util.write_control(path, "0")
                self.assertEqual(reader.read(), "500")
            self.assertEqual(path.read_text(), "0")
            self.assertEqual(
                sorted(p.name for p in Path(directory).iterdir()), ["target_mb"]
            )

    def test_failed_publication_preserves_previous_value_and_removes_temporary(self):
        from unittest.mock import patch

        util = importlib.import_module("fault_isolation_framework.core.util")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target_mb"
            path.write_text("500")
            with patch.object(
                util.os, "replace", side_effect=OSError("injected publish failure")
            ):
                with self.assertRaises(OSError):
                    util.write_control(path, "0")
            self.assertEqual(path.read_text(), "500")
            self.assertEqual(
                sorted(p.name for p in Path(directory).iterdir()), ["target_mb"]
            )


if __name__ == "__main__":
    unittest.main()
