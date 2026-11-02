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
