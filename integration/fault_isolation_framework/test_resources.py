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

    def test_cancel_does_not_send_already_queued_arrivals(self):
        import threading, time
        from fault_isolation_framework.workloads.performance_load import run_load
        stop=threading.Event()
        calls=[]
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,n):return b"ok"
        def request(*args,**kwargs):
            calls.append(time.monotonic())
            stop.wait(2)
            return Response()
        timer=threading.Timer(.1,stop.set)
        with tempfile.TemporaryDirectory() as tmp, patch("urllib.request.urlopen",side_effect=request):
            timer.start()
            rows=run_load([dict(id="go",url="http://127.0.0.1:1")],Path(tmp)/"requests.jsonl",
                          qps=1000,duration=1,workers=1,pending=128,expected=b"ok",stop=stop)
            timer.join()
        self.assertGreater(len(rows),10,"test did not queue requests before cancellation")
        self.assertEqual(len(calls),1,"cancelled queued arrivals still sent traffic")
        self.assertEqual(sum(r["sent"] is not None for r in rows),1)
        self.assertTrue(all(r.get("load_invalid") for r in rows if r["sent"] is None))

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

class WorkerResourceTest(unittest.TestCase):
    def test_worker_resources_count_towards_original_agent_budgets(self):
        from fault_isolation_framework.environments.resources import combine_worker_resources
        agent = dict(rss_bytes=10, fds=2, threads=1, inotify_watches=1)
        children = [dict(rss_bytes=20, fds=1, threads=2, inotify_watches=0),
                    dict(rss_bytes=30, fds=3, threads=2, inotify_watches=0)]
        combined = combine_worker_resources(agent, children)
        self.assertEqual(combined["rss_bytes"], 60)
        self.assertEqual(combined["agent_rss_bytes"], 10)
        self.assertEqual(combined["fds"], 6)
        self.assertEqual(combined["threads"], 5)
        self.assertEqual(agent["rss_bytes"], 10)

    def test_worker_exiting_during_sample_does_not_kill_observer(self):
        from types import SimpleNamespace
        from fault_isolation_framework.core.evidence import EvidenceStore
        from fault_isolation_framework.environments.resources import ResourceMonitor
        from fault_isolation_framework.core.util import Failure
        with tempfile.TemporaryDirectory() as tmp:
            evidence = EvidenceStore(Path(tmp)/"out")
            owner = SimpleNamespace(out=evidence.output,evidence=evidence,case_name="capture",observe_workers=True,
                                    agent_transition=False,agent=SimpleNamespace(pid=1,poll=lambda:None),probes=[],extra_processes=[])
            monitor = ResourceMonitor(owner)
            def sample(pid):
                if pid == 2:
                    raise ProcessLookupError("RSS unavailable for PID 2 state=Z (zombie)")
                return dict(agent=[1,3],rss_bytes=10,fds=2,threads=1,inotify_watches=0)
            with patch("fault_isolation_framework.environments.resources.sample_process", side_effect=sample), patch("fault_isolation_framework.environments.performance.descendants", return_value=[2]):
                row = monitor.record()
            monitor.stream.close()
            self.assertNotIn("error", row)
            self.assertEqual(row["rss_bytes"], 10)
            self.assertEqual(row["unavailable_workers"][0]["pid"], 2)


class VolatileProcessSampleTest(unittest.TestCase):
    def test_missing_rss_is_explicitly_unavailable(self):
        from fault_isolation_framework.environments import resources
        for state in ("Z (zombie)", "R (running)"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "status").write_text("State: " + state + "\nThreads: 1\n")
                with patch.object(resources, "identity", return_value=[42, 1]), \
                     patch.object(resources, "Path", return_value=root):
                    with self.assertRaises(ProcessLookupError):
                        resources.sample_process(42)

    def test_other_missing_fields_are_not_hidden_as_exit(self):
        from fault_isolation_framework.environments import resources
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "status").write_text("State: S (sleeping)\nVmRSS: 1 kB\n")
            (root / "fd").mkdir()
            with patch.object(resources, "identity", return_value=[42, 1]), \
                 patch.object(resources, "Path", return_value=root):
                with self.assertRaises(KeyError):
                    resources.sample_process(42)

    def test_missing_parent_sample_remains_a_failure(self):
        from types import SimpleNamespace
        from fault_isolation_framework.core.evidence import EvidenceStore
        from fault_isolation_framework.environments.resources import ResourceMonitor
        with tempfile.TemporaryDirectory() as tmp:
            evidence = EvidenceStore(Path(tmp) / "out")
            owner = SimpleNamespace(out=evidence.output, evidence=evidence,
                case_name="capture", agent_transition=False, probes=[],
                agent=SimpleNamespace(pid=1, poll=lambda: None))
            monitor = ResourceMonitor(owner)
            with patch("fault_isolation_framework.environments.resources.sample_process",
                       side_effect=ProcessLookupError("RSS unavailable for PID 1")):
                row = monitor.record()
            monitor.stream.close()
            self.assertIn("error", row)


class ReapedWorkerPerformanceTest(unittest.TestCase):
    def test_stat_includes_completed_children_cpu(self):
        from fault_isolation_framework.environments.performance import parse_stat
        fields = ["S"] + ["0"] * 49
        fields[13], fields[14] = "25", "15"
        self.assertEqual(parse_stat("42 (agent) " + " ".join(fields), 100)["waited_children_cpu_seconds"], .4)

    def test_completed_worker_cpu_is_counted_once_even_if_sampled(self):
        from fault_isolation_framework.environments.performance import resource_metrics
        def row(at, own, waited, child=None):
            processes = {"agent": dict(identity=[1, 1], cpu_seconds=own,
                waited_children_cpu_seconds=waited, rss_bytes=10, fds=2, threads=1)}
            if child is not None:
                processes["child-2"] = dict(identity=[2, 2], cpu_seconds=child, rss_bytes=5)
            return dict(time=at, errors=[], processes=processes)
        result = resource_metrics([row(0, 1, 0, .1), row(1, 1.1, 0, .3), row(2, 1.2, .5)], 0, 2)
        self.assertAlmostEqual(result["cpu_seconds"], .7)
        self.assertAlmostEqual(result["waited_children_cpu_seconds"], .5)
        self.assertAlmostEqual(result["sampled_tree_cpu_seconds"], .4)

    def test_unobserved_short_lived_worker_cpu_is_retained(self):
        from fault_isolation_framework.environments.performance import resource_metrics
        rows = [dict(time=t, errors=[], processes={"agent": dict(identity=[1, 1],
            cpu_seconds=1, waited_children_cpu_seconds=w, rss_bytes=10, fds=1, threads=1)})
            for t, w in [(0, 0), (1, .8)]]
        self.assertAlmostEqual(resource_metrics(rows, 0, 1)["cpu_seconds"], .8)


class PerformanceCaptureCoverageTest(unittest.TestCase):
    def test_one_success_does_not_validate_three_requested_targets(self):
        from fault_isolation_framework.adapters.huatuo.performance import captures_cover_targets
        records = [dict(pid=1, successful=True)]
        self.assertFalse(captures_cover_targets(records, {1, 2, 3}))
        self.assertTrue(captures_cover_targets(records, {1}))
        self.assertFalse(captures_cover_targets(records + [dict(pid=1, successful=False)], {1}))
        self.assertFalse(captures_cover_targets([], set()))


class SoakSamplingTest(unittest.TestCase):
    def test_long_soak_uses_two_second_resource_sampling(self):
        from fault_isolation_framework.environments.resources import resource_sample_interval
        self.assertEqual(resource_sample_interval("soak", True), 2)
        self.assertEqual(resource_sample_interval("short", True), .1)
        self.assertEqual(resource_sample_interval("short", False), 2)


class SelectionPolicyPerformanceTest(unittest.TestCase):
    def test_threshold_accepts_one_selected_candidate_not_all_pressure_edges(self):
        from fault_isolation_framework.adapters.huatuo.performance import captures_cover_targets
        records=[dict(pid=1, successful=True)]
        self.assertTrue(captures_cover_targets(records, {1,2,3}, module="memory_threshold_snapshot"))
        self.assertFalse(captures_cover_targets(records, {1,2,3}, module="memburst"))
        self.assertFalse(captures_cover_targets([dict(pid=9,successful=True)], {1}, module="memory_threshold_snapshot"))
        self.assertFalse(captures_cover_targets([dict(pid=1,successful=False)], {1}, module="memory_threshold_snapshot"))


class RedisProtocolPerformanceTest(unittest.TestCase):
    def test_resp_bulk_null_array_and_errors(self):
        import io
        from fault_isolation_framework.workloads.redis_protocol import read_reply
        self.assertEqual(read_reply(io.BytesIO(b"*3\r\n+OK\r\n$3\r\nabc\r\n:2\r\n")), [b"OK",b"abc",2])
        self.assertIsNone(read_reply(io.BytesIO(b"$-1\r\n")))
        for payload in (b"$3\r\nab", b"-ERR failed\r\n", b"$999999999\r\n"):
            with self.subTest(payload=payload), self.assertRaises((ValueError,EOFError)):
                read_reply(io.BytesIO(payload))

    def test_redis_load_checks_body_and_counts_a_real_protocol_exchange(self):
        import socketserver,threading
        from fault_isolation_framework.workloads.redis_protocol import read_reply, load_request
        class Redis(socketserver.StreamRequestHandler):
            def handle(self):
                set_args=read_reply(self.rfile)
                get_args=read_reply(self.rfile)
                count_args=read_reply(self.rfile)
                assert set_args[0]==b"SET" and get_args[0]==b"GET" and count_args[0]==b"INCR"
                body=set_args[2]
                self.wfile.write(b"+OK\r\n$"+str(len(body)).encode()+b"\r\n"+body+b"\r\n:1\r\n")
        server=socketserver.ThreadingTCPServer(("127.0.0.1",0),Redis)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            self.assertEqual(load_request(dict(url="redis://127.0.0.1:%d"%server.server_address[1],value_bytes=32,keys=2),0),1)
        finally:
            server.shutdown();server.server_close();thread.join()


class RemoteLoadPerformanceTest(unittest.TestCase):
    def test_controller_auth_and_destination_allowlist(self):
        import threading,urllib.request,urllib.error
        from fault_isolation_framework.load_controller import create_server
        with tempfile.TemporaryDirectory() as tmp:
            server=create_server(("127.0.0.1",0),Path(tmp),"secret","127.0.0.1",[12345],lease_seconds=.2)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base="http://127.0.0.1:%d"%server.server_port
            try:
                with self.assertRaises(urllib.error.HTTPError) as err:urllib.request.urlopen(base+"/health",timeout=2)
                self.assertEqual(err.exception.code,401)
                body=json.dumps(dict(targets=[dict(id="bad",url="http://example.com:12345",expected_b64="b2s=")],qps=1,duration=.2,workers=1,pending=1,start_monotonic=0)).encode()
                request=urllib.request.Request(base+"/jobs",data=body,headers={"Authorization":"Bearer secret"})
                with self.assertRaises(urllib.error.HTTPError) as err:urllib.request.urlopen(request,timeout=2)
                self.assertEqual(err.exception.code,400)
                self.assertEqual(list(Path(tmp).glob("*/requests.jsonl")),[])
            finally:server.shutdown();server.server_close();thread.join()

    def test_abandoned_job_lease_cancels_future_load(self):
        import threading,time,urllib.request
        from fault_isolation_framework.load_controller import create_server
        with tempfile.TemporaryDirectory() as tmp:
            server=create_server(("127.0.0.1",0),Path(tmp),"secret","127.0.0.1",[12345],lease_seconds=.15)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base="http://127.0.0.1:%d"%server.server_port
            def request(path,body=None):
                req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={"Authorization":"Bearer secret"})
                with urllib.request.urlopen(req,timeout=2) as reply:return json.load(reply)
            try:
                job=request("/jobs",dict(targets=[dict(id="future",url="http://127.0.0.1:12345",expected_b64="b2s=")],qps=1,duration=5,workers=1,pending=1,start_monotonic=time.monotonic()+1))
                time.sleep(.5)
                status=request("/jobs/"+job["id"])
                self.assertEqual(status["state"],"cancelled")
                self.assertEqual(status["recorded"],0)
            finally:server.shutdown();server.server_close();thread.join()

    def test_remote_requests_are_checksummed_and_mapped_to_dut_clock(self):
        import http.server,threading,time
        from fault_isolation_framework.load_controller import create_server
        from fault_isolation_framework.environments.remote_load import RemoteLoad
        class Business(http.server.BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b"ok")
            def log_message(self,*args):pass
        business=http.server.ThreadingHTTPServer(("127.0.0.1",0),Business)
        bt=threading.Thread(target=business.serve_forever,daemon=True);bt.start()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/"token").write_text("secret")
            server=create_server(("127.0.0.1",0),root/"server","secret","127.0.0.1",[business.server_port])
            st=threading.Thread(target=server.serve_forever,daemon=True);st.start()
            try:
                remote=RemoteLoad("http://127.0.0.1:%d"%server.server_port,root/"token",root/"client",max_clock_error=.1)
                remote.calibrate()
                rows=remote.run([dict(id="go",url="http://127.0.0.1:%d"%business.server_port)],10,.3,1,2,b"ok",time.monotonic()+.2)
                self.assertEqual(len(rows),3)
                self.assertTrue(all(r["ok"] and "remote_scheduled" in r for r in rows))
                self.assertTrue((root/"client/remote-requests.jsonl").exists())
                self.assertEqual(json.loads((root/"client/remote-load.json").read_text())["recorded"],3)
            finally:
                server.shutdown();server.server_close();st.join()
                business.shutdown();business.server_close();bt.join()


class RedisForkAccountingTest(unittest.TestCase):
    def test_reaped_redis_child_cpu_is_in_business_total(self):
        from fault_isolation_framework.environments.performance import resource_metrics
        rows=[dict(time=t,errors=[],processes={'neighbor-redis':dict(identity=[1,1],cpu_seconds=cpu,
            waited_children_cpu_seconds=child,rss_bytes=100,fds=1,threads=1)})
            for t,cpu,child in [(0,1,0),(1,2,.5)]]
        result=resource_metrics(rows,0,1)['business']['neighbor-redis']
        self.assertAlmostEqual(result['total_cpu_seconds'],1.5)


class RemoteSourceGuardTest(unittest.TestCase):
    def test_empty_source_hashes_cannot_validate_a_controller(self):
        import http.server,threading,time
        from fault_isolation_framework.environments.remote_load import RemoteLoad
        class Missing(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body=json.dumps(dict(monotonic=time.monotonic(),driver_sha256={})).encode()
                self.send_response(200);self.end_headers();self.wfile.write(body)
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Missing)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'token').write_text('secret')
                remote=RemoteLoad('http://127.0.0.1:%d'%server.server_port,root/'token',root/'out',max_clock_error=.1)
                with self.assertRaisesRegex(ValueError,'source'):remote.calibrate()
        finally:server.shutdown();server.server_close();thread.join()


class RedisForkWitnessTest(unittest.TestCase):
    def test_redis5_requires_new_successful_rdb_not_a_missing_fork_counter(self):
        from fault_isolation_framework.workloads.performance_redis import completed_fork
        before=dict(latest_fork_usec='0')
        after=dict(latest_fork_usec='150',rdb_bgsave_in_progress='0',rdb_last_bgsave_status='ok')
        self.assertTrue(completed_fork(before,after,1,2))
        self.assertFalse(completed_fork(before,after,2,2))
        self.assertFalse(completed_fork(before,dict(after,rdb_last_bgsave_status='err'),1,2))
        self.assertFalse(completed_fork(dict(before,total_forks='3'),dict(after,total_forks='3'),1,2))


class MixedPerformanceFixtureTest(unittest.TestCase):
    def test_memory_pressure_release_does_not_treat_redis_as_an_allocator(self):
        from types import SimpleNamespace
        from fault_isolation_framework.adapters.huatuo.performance import PerformanceTrigger
        with tempfile.TemporaryDirectory() as tmp:
            ctl=Path(tmp);(ctl/'target_mb').write_text('500');(ctl/'memory.usage_in_bytes').write_text('0')
            owner=SimpleNamespace(targets=[dict(ctl=ctl,cgroup=ctl),dict(kind='redis',role='neighbor')])
            PerformanceTrigger(owner).release_all()
            self.assertEqual((ctl/'target_mb').read_text(),'0')


class ArrivalProtocolTest(unittest.TestCase):
    def test_duplicate_arrivals_and_nonfinite_times_are_invalid(self):
        from fault_isolation_framework.core.performance import arrival_errors
        rows=[dict(target='go',ordinal=i,scheduled=i,sent=i,ended=i+.01,dispatch_lag=0,ok=True) for i in range(2)]
        self.assertEqual(arrival_errors(rows,{'go'},1,2),[])
        self.assertTrue(arrival_errors([rows[0],rows[0]],{'go'},1,2))
        self.assertTrue(arrival_errors(rows+[rows[1]],{'go'},1,2))
        self.assertTrue(arrival_errors([dict(rows[0],ended=float('nan')),rows[1]],{'go'},1,2))
        self.assertTrue(arrival_errors([dict(rows[0],target='unknown'),rows[1]],{'go'},1,2))


class RemoteClockGuardTest(unittest.TestCase):
    def test_nonfinite_clock_cannot_validate_a_controller(self):
        import http.server,threading,time
        from fault_isolation_framework.environments.remote_load import RemoteLoad
        from fault_isolation_framework.load_controller import driver_hashes
        class Invalid(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200);self.end_headers()
                self.wfile.write(json.dumps(dict(monotonic=float('nan'),driver_sha256=driver_hashes())).encode())
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Invalid)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);(root/'token').write_text('secret')
                remote=RemoteLoad('http://127.0.0.1:%d'%server.server_port,root/'token',root/'out',max_clock_error=.1)
                with self.assertRaisesRegex(ValueError,'clock'):remote.calibrate()
        finally:server.shutdown();server.server_close();thread.join()


class NativeJobGuardTest(unittest.TestCase):
    def test_native_job_rejects_command_injection_and_unbounded_work(self):
        from fault_isolation_framework.load_controller import JobManager
        import time
        with tempfile.TemporaryDirectory() as tmp:
            manager=JobManager(tmp,'127.0.0.1',[12345],10,native_tools={})
            spec=dict(native='etcd',url='http://127.0.0.1:12345',rate=10,duration=20,
                      start_monotonic=time.monotonic()+1,records=200,connections=2)
            manager.validate(spec)
            for changed in (dict(command=['sh']),dict(native='shell'),dict(rate=float('nan')),
                            dict(records=1000001),dict(url='http://example.com:12345')):
                with self.assertRaises(ValueError):manager.validate(dict(spec,**changed))

    def test_native_process_cancellation_reaps_process_group_and_accounts_cpu(self):
        import sys,threading,time
        from fault_isolation_framework.workloads.native_tools import bounded_process
        with tempfile.TemporaryDirectory() as tmp:
            stop=threading.Event();timer=threading.Timer(.2,stop.set);timer.start()
            result=bounded_process([sys.executable,'-c','while True: pass'],Path(tmp),'busy',stop,3)
            self.assertTrue(result['cancelled'])
            self.assertGreater(result['cpu_seconds'],0)
            self.assertGreater(result['peak_rss_bytes'],0)
            self.assertFalse(Path('/proc/%s'%result['pid']).exists())
            timer.join()

    def test_failed_native_job_retains_verified_raw_then_acknowledges_transfer(self):
        import threading,time
        from fault_isolation_framework.load_controller import create_server
        from fault_isolation_framework.environments.remote_load import RemoteLoad
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'token').write_text('secret')
            server=create_server(('127.0.0.1',0),root/'server','secret','127.0.0.1',[12345])
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                remote=RemoteLoad('http://127.0.0.1:%d'%server.server_port,root/'token',root/'client',max_clock_error=.1)
                with self.assertRaisesRegex(RuntimeError,'native job failed'):
                    remote.run_native(dict(native='etcd',url='http://127.0.0.1:12345',rate=1,duration=20,records=20,connections=1,start_monotonic=time.monotonic()+.1))
                result=json.loads((root/'client/native-result.json').read_text())
                self.assertFalse(result['valid']);self.assertTrue(result['errors'])
                self.assertTrue(server.manager.jobs[remote.job]['acked'])
            finally:server.shutdown();server.server_close();thread.join()


class ResidentResourceContractTest(unittest.TestCase):
    def test_v1_failure_count_is_distinct_from_oom_kills_and_missing_psi(self):
        from fault_isolation_framework.environments.performance import cgroup_memory
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,value in {'memory.usage_in_bytes':'90','memory.limit_in_bytes':'100','memory.max_usage_in_bytes':'95','memory.failcnt':'7','memory.oom_control':'under_oom 0\noom_kill 2\n','memory.stat':'rss 80\ncache 10\n'}.items():(root/name).write_text(value)
            sample=cgroup_memory(root)
            self.assertEqual(sample['oom_kills'],2);self.assertEqual(sample['allocation_failures'],7)
            self.assertEqual(sample['current_bytes'],90)
            self.assertNotIn('memory.pressure',sample['raw'])

    def test_v2_missing_peak_remains_unavailable(self):
        from fault_isolation_framework.environments.performance import cgroup_memory
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,value in {'memory.current':'90','memory.max':'100','memory.events':'oom 1\noom_kill 0\n'}.items():(root/name).write_text(value)
            sample=cgroup_memory(root)
            self.assertIsNone(sample['lifetime_peak_bytes']);self.assertIsNone(sample['allocation_failures'])
            self.assertIsNone(sample['raw']['memory.pressure']);self.assertEqual(sample['oom_kills'],0)

    def test_phase_memory_uses_time_aligned_counters_and_disjoint_sum(self):
        from fault_isolation_framework.adapters.huatuo.resident_performance import memory_window
        def sample(current,oom,fail):return dict(current_bytes=current,lifetime_peak_bytes=999,oom_kills=oom,allocation_failures=fail)
        rows=[dict(time=t,business_memory={'kv':sample(b,o,f)},memory_scopes={'agent':sample(a,0,0),'helper':sample(h,0,0),'worker-0':sample(w,0,0),'observer_parent':sample(1000,0,0)}) for t,b,o,f,a,h,w in [(0,50,0,1,10,20,0),(1,70,0,2,20,10,30),(2,60,1,4,10,15,0)]]
        window=memory_window(rows,0,2,'kv')
        self.assertEqual(window['business']['allocation_failures_delta'],1)
        self.assertEqual(window['business']['oom_kills_delta'],0)
        self.assertEqual(window['collector_simultaneous_sampled_peak_bytes'],60)
        self.assertEqual(window['collector_peak_above_baseline_bytes'],30)
        self.assertEqual(window['business']['lifetime_peak_bytes'],999)


class ResidentWindowBoundaryTest(unittest.TestCase):
    def test_canonical_arrivals_partition_each_ordinal_once_despite_clock_mapping(self):
        from fault_isolation_framework.adapters.huatuo.resident_performance import canonical_window_rows
        for offset in (-.00001,.00001):
            rows=[dict(ordinal=i,scheduled=100+i/10+offset) for i in range(30)]
            windows=[canonical_window_rows(rows,100,10,100+i,101+i) for i in range(3)]
            self.assertEqual([[r['ordinal'] for r in w] for w in windows],[list(range(i*10,(i+1)*10)) for i in range(3)])
            self.assertEqual(sum(len(w) for w in windows),30)


class ResidentHelperOutputTest(unittest.TestCase):
    def test_live_partial_row_can_complete_without_false_protocol_failure(self):
        from types import SimpleNamespace
        from fault_isolation_framework.adapters.huatuo.resident_performance import capture_rows
        with tempfile.TemporaryDirectory() as tmp:
            owner=SimpleNamespace(out=Path(tmp));path=owner.out/'snapshot-helper.jsonl'
            path.write_text('{"ready":true}\n{"id":1,"pid":7}\n{"id":2')
            self.assertEqual([r['id'] for r in capture_rows(owner)],[1])
            with path.open('a') as stream:stream.write(',"pid":7}\n')
            self.assertEqual([r['id'] for r in capture_rows(owner)],[1,2])
            with path.open('a') as stream:stream.write('{bad}\n')
            with self.assertRaisesRegex(ValueError,'malformed helper JSON'):capture_rows(owner)

    def test_truncated_helper_output_cannot_bypass_cleanup_and_saved_failure(self):
        from types import SimpleNamespace
        from fault_isolation_framework.core.evidence import EvidenceStore
        from fault_isolation_framework.adapters.huatuo.resident_performance import finalize_trial
        with tempfile.TemporaryDirectory() as tmp:
            evidence=EvidenceStore(Path(tmp)/'trial');called=[]
            owner=SimpleNamespace(out=evidence.output,cleanup=lambda:called.append('cleanup'))
            raw=b'{"ready":true}\n{"id":1,"pid":7}\n{"id":2,"pid":'
            path=owner.out/'snapshot-helper.jsonl';path.write_bytes(raw)
            outcome=dict(valid=True,errors=[],captures=[])
            finalize_trial(owner,outcome,evidence)
            saved=json.loads((owner.out/'summary.json').read_text())
            self.assertEqual(called,['cleanup']);self.assertFalse(saved['valid'])
            self.assertEqual([r['id'] for r in saved['captures']],[1])
            self.assertTrue(any('unterminated' in error for error in saved['errors']))
            self.assertEqual(path.read_bytes(),raw)


class ResidentReplayPreflightTest(unittest.TestCase):
    def test_bounded_baseline_replays_keep_every_replica_before_freezing(self):
        from fault_isolation_framework.adapters.huatuo.resident_performance import bounded_replay_calibration
        calls=[];rounds=[]
        plan=dict(records=10000,limit_bytes=100,requested_percent=90,tolerance_percent=2)
        def replay(candidate,round_index,replica_index):
            calls.append((round_index,replica_index,candidate['records'],candidate['fill_recipe']))
            value=(85+replica_index) if round_index==0 else (89+replica_index)
            return dict(valid=True,pressure_samples=[value]*5,directory='attempt-%d-%d'%(round_index,replica_index))
        result=bounded_replay_calibration(plan,replay,rounds.append)
        self.assertEqual(len(calls),4);self.assertTrue(result['frozen'])
        self.assertGreater(calls[2][2],calls[0][2])
        self.assertEqual(calls[2][3][0]['records'],1024)
        self.assertEqual([row['decision']['status'] for row in rounds],['REFINE','FROZEN'])

    def test_variance_failure_does_not_loop_until_a_lucky_replica(self):
        from fault_isolation_framework.adapters.huatuo.resident_performance import bounded_replay_calibration
        calls=[];rounds=[]
        def replay(candidate,round_index,replica_index):
            calls.append(replica_index)
            return dict(valid=True,pressure_samples=[85 if replica_index==0 else 95]*5)
        plan=dict(records=10000,limit_bytes=100,requested_percent=90,tolerance_percent=2)
        with self.assertRaisesRegex(RuntimeError,'variance'):bounded_replay_calibration(plan,replay,rounds.append)
        self.assertEqual(calls,[0,1]);self.assertEqual(len(rounds),1)

    def test_replay_calibration_stops_after_three_predetermined_rounds(self):
        from fault_isolation_framework.adapters.huatuo.resident_performance import bounded_replay_calibration
        calls=[];rounds=[]
        def replay(candidate,round_index,replica_index):
            calls.append((round_index,replica_index))
            return dict(valid=True,pressure_samples=[85+replica_index]*5)
        plan=dict(records=10000,limit_bytes=100,requested_percent=90,tolerance_percent=2)
        with self.assertRaisesRegex(RuntimeError,'three predetermined'):bounded_replay_calibration(plan,replay,rounds.append)
        self.assertEqual(calls,[(r,i) for r in range(3) for i in range(2)])
        self.assertEqual(len(rounds),3)

class ApplicationControllerTest(unittest.TestCase):
    def test_typed_application_job_uses_native_budget_not_legacy_row_cap(self):
        from fault_isolation_framework.load_controller import JobManager
        import time
        with tempfile.TemporaryDirectory() as tmp:
            manager=JobManager(tmp,'10.0.2.2',[40000],10)
            job=dict(application='cache',url='http://10.0.2.2:40000',rate=10000,duration=210,
                     start_monotonic=time.monotonic()+3,records=100000,seed=923,connections=64,
                     warmup=30,baseline=60,hold=60,trace_margin=4,diagnostic=False)
            manager.validate(job)
            with self.assertRaises(ValueError):manager.validate(dict(job,command=['sh']))

class ApplicationCPUQuotaTest(unittest.TestCase):
    def test_cpu_quota_throttle_units_and_missing_counters_are_explicit(self):
        from fault_isolation_framework.workloads.application_workloads import read_cpu_scope
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)
            empty=read_cpu_scope(path)
            self.assertIsNone(empty['throttled_seconds']);self.assertIsNone(empty['cpu_seconds'])
            (path/'cpu.stat').write_text('nr_periods 100\nnr_throttled 7\nthrottled_time 9000000\n')
            (path/'cpuacct.usage').write_text('2500000000\n')
            (path/'cpu.cfs_quota_us').write_text('400000\n');(path/'cpu.cfs_period_us').write_text('100000\n')
            measured=read_cpu_scope(path)
            self.assertEqual(measured['quota_cores'],4);self.assertEqual(measured['cpu_seconds'],2.5)
            self.assertEqual(measured['throttled_seconds'],.009)
            self.assertEqual(measured['throttled_periods'],7)

class ApplicationStartupFailureTest(unittest.TestCase):
    def test_prepare_failure_still_preserves_owned_container_logs_and_cleans(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from fault_isolation_framework.adapters.huatuo.resident_performance import ResidentAdapter
        with tempfile.TemporaryDirectory() as tmp:
            calls=[];owner=ResidentAdapter.__new__(ResidentAdapter);owner.out=Path(tmp);owner.targets=[]
            owner.stop_agent=lambda **_:calls.append('agent')
            owner.environment=SimpleNamespace(containers=['owned-startup-failure'],cleanup=lambda _:calls.append('container'))
            owner.discovery=SimpleNamespace(cleanup=lambda:calls.append('discovery'))
            result=SimpleNamespace(stdout='{"application_launch":true}\n',stderr='Tomcat startup failed: missing writable tempdir\n')
            with patch('fault_isolation_framework.adapters.huatuo.resident_performance.run',return_value=result):owner.cleanup()
            self.assertIn('Tomcat startup failed',(owner.out/'business.log').read_text())
            self.assertEqual(calls,['agent','container','discovery'])

class ApplicationArtifactRetentionTest(unittest.TestCase):
    def test_large_histograms_are_artifacts_not_bounded_status_JSON(self):
        from unittest.mock import patch
        from fault_isolation_framework.load_controller import JobManager
        import time
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manager=JobManager(root,'127.0.0.1',[12345],10)
            spec=dict(application='cache',url='http://127.0.0.1:12345',rate=100,duration=20,start_monotonic=time.monotonic(),records=1024,seed=923,connections=16,warmup=5,baseline=5,hold=5,trace_margin=4,diagnostic=False)
            def execute(spec,path,*_):
                result=dict(kind='cache',valid=True,errors=[],histograms={'large':'x'*(2<<20)})
                (path/'application-result.json').write_text(json.dumps(result));return result
            with patch('fault_isolation_framework.load_controller.run_application',execute):
                ident=manager.start(spec)['id']
                while not manager.jobs[ident].get('sealed'):time.sleep(.001)
            _,meta=manager.get(ident)
            self.assertLess(len(json.dumps(meta)),10000)
            self.assertEqual(meta['result_artifact'],'application-result.json')
            self.assertGreater(meta['files']['application-result.json']['bytes'],2<<20)

    def test_280_verified_ACKs_bound_metadata_without_pruning_unacked_jobs(self):
        from unittest.mock import patch
        from fault_isolation_framework.load_controller import JobManager
        import time
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);manager=JobManager(root,'127.0.0.1',[12345],10)
            def execute(spec,path,*_):
                result=dict(kind='cache',valid=True,errors=[])
                (path/'application-result.json').write_text(json.dumps(result));return result
            with patch('fault_isolation_framework.load_controller.run_application',execute):
                for index in range(281):
                    spec=dict(application='cache',url='http://127.0.0.1:12345',rate=100,duration=20,start_monotonic=time.monotonic(),records=1024,seed=923,connections=16,warmup=5,baseline=5,hold=5,trace_margin=4,diagnostic=False)
                    ident=manager.start(spec)['id']
                    while not manager.jobs[ident].get('sealed'):time.sleep(.001)
                    job,meta=manager.get(ident)
                    if index<280:manager.ack(ident,meta['files'])
                self.assertEqual(len(manager.jobs),65)
                self.assertIn(ident,manager.jobs);self.assertFalse(job.get('acked',False))
                self.assertEqual(sum(not row.get('acked',False) for row in manager.jobs.values()),1)

class ApplicationOwnedDBTest(unittest.TestCase):
    def test_success_removes_only_verified_owned_DB_and_failure_preserves_it(self):
        from types import SimpleNamespace
        from fault_isolation_framework.workloads.application_workloads import finish_owned_database
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/('a'*32);directory.mkdir();output=root/'evidence';output.mkdir()
            marker=dict(token='a'*32,output=str(output));(directory/'.huatuo-owned.json').write_text(json.dumps(marker));(directory/'data').write_bytes(b'database')
            finish_owned_database(directory,marker,output,False,'digest')
            self.assertTrue((directory/'data').exists())
            finish_owned_database(directory,marker,output,True,'digest')
            self.assertFalse(directory.exists())
            self.assertFalse(json.loads((output/'business-data-lifecycle.json').read_text())['retained'])

    def test_owned_DB_cleanup_refuses_changed_marker(self):
        from fault_isolation_framework.workloads.application_workloads import finish_owned_database
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);directory=root/('b'*32);directory.mkdir();output=root/'evidence';output.mkdir()
            marker=dict(token='b'*32,output=str(output));(directory/'.huatuo-owned.json').write_text(json.dumps(dict(marker,token='someoneelse')))
            with self.assertRaises(ValueError):finish_owned_database(directory,marker,output,True,'digest')
            self.assertTrue(directory.exists())
