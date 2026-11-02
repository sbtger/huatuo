# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""A controlled Docker executable reproduces removal failures at the CLI boundary."""
import json, os, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.environments.docker import DockerEnvironment
from fault_isolation_framework.core.util import Failure


class CleanupTest(unittest.TestCase):
    def exercise(self, fail):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "docker"
            script.write_text(
                "#!"
                + sys.executable
                + "\n"
                + """import json,os,sys
with open(os.environ['ATTEMPTS'],'a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]==os.environ['FAIL_OPERATION']:
 print('injected Docker removal failure',file=sys.stderr);sys.exit(9)
"""
            )
            script.chmod(0o755)
            env = DockerEnvironment.__new__(DockerEnvironment)
            env.output = root
            env.containers = ["owned-a", "owned-b"]
            env.image = "owned-image"
            with patch.dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ["PATH"],
                ATTEMPTS=str(root / "attempts"),
                FAIL_OPERATION=fail,
            ):
                if fail:
                    with self.assertRaises(Failure):
                        env.cleanup([])
                else:
                    env.cleanup([])
            return [
                json.loads(line)
                for line in (root / "attempts").read_text().splitlines()
            ]

    def test_failed_container_removal_fails_after_attempting_all_resources(self):
        self.assertEqual(
            self.exercise("rm"),
            [["rm", "-f", "owned-a"], ["rm", "-f", "owned-b"], ["rmi", "owned-image"]],
        )

    def test_failed_image_removal_fails(self):
        self.assertEqual(self.exercise("rmi")[-1], ["rmi", "owned-image"])

    def test_successful_cleanup_removes_owned_resources(self):
        self.assertEqual(len(self.exercise("")), 3)


class BuildIdentityTest(unittest.TestCase):
    def test_stale_binary_cannot_borrow_manifest_hash(self):
        import hashlib

        try:
            from fault_isolation_framework.adapters.huatuo.agent import verify_build
        except ImportError:
            self.fail("build identity verification is missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent").write_bytes(b"first build")
            (root / "build.json").write_text(
                json.dumps(
                    {"sha256": {"agent": hashlib.sha256(b"first build").hexdigest()}}
                )
            )
            verify_build(root)
            (root / "agent").write_bytes(b"changed build")
            with self.assertRaisesRegex(Failure, "hash"):
                verify_build(root)


class SupervisorCleanupTest(unittest.TestCase):
    def test_zero_exit_without_audited_success_still_cleans_owned_resources(self):
        from fault_isolation_framework.environments.supervisor import supervise

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = root / "docker"
            docker.write_text(
                "#!"
                + sys.executable
                + '\nimport os,sys,json\nwith open(os.environ["ATTEMPTS"],"a") as s: s.write(json.dumps(sys.argv[1:])+"\\n")\n'
            )
            docker.chmod(0o755)
            (root / "ownership.jsonl").write_text(
                json.dumps(dict(kind="image", value="owned-image")) + "\n"
            )
            with patch.dict(
                os.environ,
                PATH=str(root) + os.pathsep + os.environ["PATH"],
                ATTEMPTS=str(root / "attempts"),
            ):
                result = supervise(
                    [sys.executable, "-c", "pass"], root, timeout=5, phase_timeout=5
                )
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(
                (root / "attempts").exists(),
                "zero exit skipped cleanup despite missing audited evidence",
            )
            rows = [
                json.loads(line)
                for line in (root / "attempts").read_text().splitlines()
            ]
            self.assertIn(["rmi", "owned-image"], rows)


class RankingScaleObservationTest(unittest.TestCase):
    def test_disappearing_scale_process_is_not_silently_counted_as_load(self):
        from types import SimpleNamespace
        from fault_isolation_framework.environments.resources import ResourceMonitor

        with tempfile.TemporaryDirectory() as tmp:
            owner = SimpleNamespace(
                out=Path(tmp),
                evidence=SimpleNamespace(register=lambda *a, **kw: None),
                case_name="scale",
                agent=None,
                agent_transition=False,
                probes=[],
                extra_processes=[
                    SimpleNamespace(process=SimpleNamespace(poll=lambda: 9))
                ],
            )
            monitor = ResourceMonitor(owner)
            try:
                row = monitor.record()
                self.assertIn("ranking helper", row.get("error", ""))
            finally:
                monitor.stream.close()


class InotifyObservationTest(unittest.TestCase):
    def test_counts_watches_inside_fdinfo_not_just_number_of_fds(self):
        try:
            from fault_isolation_framework.environments.resources import (
                inotify_watch_count,
            )
        except ImportError:
            self.fail("inotify watch observation is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "1").write_text("pos:\t0\nflags:\t02000000\n")
            (root / "4").write_text(
                "pos:\t0\ninotify wd:1 ino:12\ninotify wd:2 ino:13\n"
            )
            (root / "7").write_text("pos:\t0\nflags:\t02000000\n")
            self.assertEqual(inotify_watch_count(root), 2)


class CaptureDiagnosticsTest(unittest.TestCase):
    def test_timeout_records_actual_usage_instead_of_assuming_control_was_applied(self):
        from types import SimpleNamespace
        from fault_isolation_framework.core.evidence import EvidenceStore

        try:
            from fault_isolation_framework.adapters.huatuo.stability.diagnostics import (
                capture_failure,
            )
        except ImportError:
            self.fail("failed captures have no live input diagnostics")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            control, group = root / "control", root / "group"
            control.mkdir()
            group.mkdir()
            (control / "target_mb").write_text("500")
            (group / "memory.usage_in_bytes").write_text("100")
            (group / "memory.limit_in_bytes").write_text("1000")
            evidence = EvidenceStore(root / "evidence")
            owner = SimpleNamespace(
                out=evidence.output,
                evidence=evidence,
                case_name="go/capture",
                last_capture=1,
                agent=None,
                targets=[dict(language="go", pid=999999999, ctl=control, cgroup=group)],
            )
            name = capture_failure(owner, RuntimeError("missing event"))
            data = json.loads((owner.out / name).read_text())
            self.assertEqual(data["targets"][0]["requested_mb"], "500")
            self.assertEqual(data["targets"][0]["memory.usage_in_bytes"], "100")
            self.assertIn(name, evidence.artifacts)


class PerformanceTest(unittest.TestCase):
    def test_tail_percentile_requires_enough_samples(self):
        from fault_isolation_framework.core.performance import percentile
        self.assertIsNone(percentile([1, 2, 3], 99))
        self.assertEqual(percentile(list(range(1, 1001)), 99), 990)

    def test_load_includes_queue_time_errors_and_missing_arrivals(self):
        from fault_isolation_framework.core.performance import summarize_requests
        rows = [dict(target="go", scheduled=0, sent=2, ended=3, ok=True),
                dict(target="go", scheduled=1, sent=2, ended=4, ok=False)]
        result = summarize_requests(rows, 3, 4)
        self.assertEqual(result["scheduled"], 3)
        self.assertEqual(result["missing"], 1)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["latency_ms"]["p50"], 3000)
        self.assertEqual(result["send_delay_ms"]["max"], 2000)
        self.assertFalse(result["valid_load"])

    def test_failed_trial_is_excluded_from_pair_comparison(self):
        from fault_isolation_framework.core.performance import paired_comparisons
        trials = [dict(repeat=0, group="B", valid=True, metrics={"cpu_seconds": 1}),
                  dict(repeat=0, group="D", valid=False, metrics={"cpu_seconds": 0})]
        self.assertEqual(paired_comparisons(trials, "D", "B")["valid_pairs"], 0)

    def test_fixed_arrival_overload_is_recorded_not_queued_forever(self):
        import http.server, threading, time
        from fault_isolation_framework.workloads.performance_load import run_load
        class Slow(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(.04)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Slow)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rows = run_load([dict(id="go", url="http://127.0.0.1:%d" % server.server_port)],
                                Path(tmp)/"requests.jsonl", qps=200, duration=.15,
                                workers=1, pending=1, expected=b"ok")
                self.assertEqual(len(rows), 30)
                self.assertTrue(any(r.get("error") == "load queue full" for r in rows))
                self.assertTrue(any(r["ok"] for r in rows))
                self.assertTrue(all(not r["ok"] or r["ended"] >= r["sent"] >= r["scheduled"] for r in rows))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_proc_stat_parser_handles_spaces_in_name_and_cpu_units(self):
        from fault_isolation_framework.environments.performance import parse_stat
        fields = ["S"] + ["0"]*49
        fields[7], fields[9] = "12", "3"
        fields[11], fields[12], fields[19] = "100", "50", "777"
        row = parse_stat("42 (name with ) space) " + " ".join(fields), ticks=100)
        self.assertEqual(row["identity"], [42, 777])
        self.assertEqual(row["cpu_seconds"], 1.5)
        self.assertEqual(row["minor_faults"], 12)
        self.assertEqual(row["major_faults"], 3)

    def test_experiments_keep_idle_and_pressured_baselines_separate(self):
        from fault_isolation_framework.core.performance import experiment_groups
        self.assertEqual(experiment_groups("idle"), ["A", "B", "C"])
        self.assertEqual(experiment_groups("pulse"), ["A", "B", "D"])

    def test_pressure_event_must_match_target_and_success(self):
        from fault_isolation_framework.adapters.huatuo.performance import capture_records
        docs = [dict(tracer_data=dict(process_snapshots=[
            dict(pid=22, language="go", snapshot=dict(status="failed", entries=[]))]))]
        records = capture_records("memburst", docs, {22})
        self.assertFalse(records[0]["successful"])
        self.assertEqual(capture_records("memburst", docs, {99}), [])

    def test_resource_cpu_is_delta_and_pid_reuse_does_not_add_old_lifetime(self):
        from fault_isolation_framework.environments.performance import resource_metrics
        def row(at, ident, cpu):
            return dict(time=at, errors=[], cgroups={}, processes={"agent":dict(
                identity=ident, cpu_seconds=cpu, rss_bytes=10, fds=2, threads=1)})
        result = resource_metrics([row(0, [2, 10], 4), row(1, [2, 10], 5),
                                   row(2, [2, 20], 20)], 0, 2)
        self.assertEqual(result["cpu_seconds"], 1)
        self.assertEqual(result["sampled_agent_tree_rss_peak_bytes"], 10)

    def test_capacity_reports_highest_tested_slo_rate_not_invalid_fast_run(self):
        from fault_isolation_framework.core.performance import highest_tested_rate
        rows = [dict(qps=10, valid=True, p99_ms=4, error_rate=0),
                dict(qps=20, valid=True, p99_ms=12, error_rate=0),
                dict(qps=30, valid=False, p99_ms=1, error_rate=0)]
        self.assertEqual(highest_tested_rate(rows, 10, 0), 10)
        self.assertIsNone(highest_tested_rate([dict(qps=10, valid=True, p99_ms=None, error_rate=0)], 10, 0))

    def test_listener_scale_does_not_multiply_business_load(self):
        from fault_isolation_framework.adapters.huatuo.performance import select_load_targets
        targets = [dict(id="target-000-go", pid=1, role="target"),
                   dict(id="target-001-go", pid=2, role="target"),
                   dict(id="target-002-go", pid=3, role="target"),
                   dict(id="neighbor-go", pid=4, role="neighbor")]
        self.assertEqual([t["pid"] for t in select_load_targets(targets, [targets[1]], False)], [1, 2, 4])
        self.assertEqual(len(select_load_targets(targets, [], True)), 4)

    def test_final_event_decode_rejects_truncated_tail(self):
        from fault_isolation_framework.core.performance import strict_documents
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"events"
            path.write_text('{"ok":true}\n{"truncated":')
            with self.assertRaises(ValueError):
                strict_documents(path)
            path.write_text('{"ok":true}\n{"ok":false}\n')
            self.assertEqual(len(strict_documents(path)), 2)

    def test_capacity_excludes_campaign_supervisor_failure(self):
        from fault_isolation_framework.performance_matrix import capacity_summary
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"results.json").write_text(json.dumps(dict(config=dict(repeats=1, qps=20), trials=[dict(
                group="D", valid=True, load={"go":dict(latency_ms=dict(p99=2), errors=0, scheduled=1000)})])))
            result = capacity_summary([dict(name="failed", output=tmp, returncode=1)], 10, 0)
            self.assertTrue(all(r["highest_tested_slo_rate"] is None for r in result["series"].values()))

    def test_threshold_readiness_excludes_unregistered_neighbor(self):
        from fault_isolation_framework.adapters.huatuo.performance import PerformanceAdapter
        owner = PerformanceAdapter.__new__(PerformanceAdapter)
        owner.targets = [dict(role="target", pid=1), dict(role="neighbor", pid=2)]
        self.assertEqual([t["pid"] for t in owner.watch_targets()], [1])

    def test_pulse_capture_cannot_reuse_old_matching_event(self):
        from fault_isolation_framework.adapters.huatuo.performance import capture_records
        def event(at):
            return dict(started_timestamp=at, tracer_data=dict(process_snapshots=[
                dict(pid=22, language="go", snapshot=dict(status="complete", entries=[dict(bytes=1)]))]))
        docs = [event("2026-11-02T00:00:00Z"), event("2026-11-02T00:01:00Z")]
        import datetime
        start = datetime.datetime(2026, 11, 2, 0, 0, 30, tzinfo=datetime.timezone.utc).timestamp()
        records = capture_records("memburst", docs, {22}, not_before=start, not_after=start+60)
        self.assertEqual([r["event_index"] for r in records], [1])

    def test_canceled_future_pressure_does_not_outlive_trial(self):
        import threading, time
        from types import SimpleNamespace
        from fault_isolation_framework.adapters.huatuo.performance import drive_pressure
        stop = threading.Event()
        stop.set()
        pressure = dict(commands=[], events=[], errors=[])
        owner = SimpleNamespace(pressured=[], driver=None)
        args = SimpleNamespace(warmup=60, baseline=30, hold=30, experiment="pulse")
        start = time.monotonic()
        drive_pressure(owner, args, "A", start, pressure, stop)
        self.assertLess(time.monotonic()-start, .5)
        self.assertFalse(pressure["commands"])
