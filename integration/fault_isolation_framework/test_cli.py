# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class CLITest(unittest.TestCase):
    def test_unknown_adapter_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence"
            script = Path(__file__).resolve().parent / "run.py"
            result = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--adapter",
                    "unknown",
                    "--build",
                    tmp,
                    "--bpf-dir",
                    tmp,
                    "--output",
                    str(output),
                ],
                cwd=tmp,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 2)
            self.assertFalse(output.exists())

    def test_direct_help_works_outside_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(__file__).resolve().parent / "run.py"
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=tmp,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_evidence_schema_fails_even_if_legacy_shape_is_valid(self):
        import json
        from test_audit import EvidenceAuditTest
        from fault_isolation_framework.cli import audit_output

        fixture = EvidenceAuditTest("test_complete_evidence_passes")
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.fixture()
        path = fixture.root / "summary.json"
        summary = json.loads(path.read_text())
        summary["schema_version"] = 999
        path.write_text(json.dumps(summary))
        self.assertEqual(audit_output(fixture.root)["status"], "FAIL")

    def test_core_imports_without_feature_workload_or_environment_packages(self):
        parent = Path(__file__).resolve().parent.parent
        code = """import sys,importlib.abc
class Blocker(importlib.abc.MetaPathFinder):
 def find_spec(self, fullname, path=None, target=None):
  if fullname.startswith(('fault_isolation_framework.adapters','fault_isolation_framework.workloads','fault_isolation_framework.environments')):
   raise ImportError('feature dependency in core: '+fullname)
sys.meta_path.insert(0,Blocker())
from fault_isolation_framework.core import models,runner,evidence,audit,documents,util
"""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys;sys.path.insert(0," + repr(str(parent)) + ");" + code,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_performance_rejects_bad_configuration_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(__file__).resolve().parent / "performance.py"
            help_result = subprocess.run([sys.executable, str(script), "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            for option in (["--qps", "0"], ["--sample-interval", "0"], ["--repeats", "0"]):
                output = Path(tmp)/"output"
                result = subprocess.run([sys.executable, str(script), "--module", "memburst",
                                         "--build", tmp, "--bpf-dir", tmp, "--output", str(output)] + option,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(output.exists())

    def test_performance_can_run_agent_without_debug_logging(self):
        from fault_isolation_framework.adapters.huatuo.agent import command
        self.assertNotIn("--log-debug", command("/agent", "/conf", "/out", "/bpf", debug=False))
        self.assertIn("--log-debug", command("/agent", "/conf", "/out", "/bpf"))

    def test_performance_integrity_rejects_tampered_raw_data(self):
        import json
        from fault_isolation_framework.performance import seal, audit
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"results.json").write_text(json.dumps({"trials": []}))
            (root/"supervisor.json").write_text("{}")
            (root/"requests.jsonl").write_text('{"ok":true}\n')
            seal(root)
            self.assertEqual(audit(root)["status"], "PASS")
            (root/"requests.jsonl").write_text('{"ok":false}\n')
            self.assertEqual(audit(root)["status"], "FAIL")

    def test_performance_plan_has_no_side_effects_and_repeats_random_order(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(__file__).resolve().parent / "performance.py"
            command = [sys.executable, str(script), "--module", "memburst", "--experiment", "pulse",
                       "--build", tmp, "--bpf-dir", tmp, "--output", str(Path(tmp)/"run"), "--plan"]
            first = subprocess.run(command, capture_output=True, text=True, check=True)
            second = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(first.stdout, second.stdout)
            self.assertTrue(all(sorted(r["groups"]) == ["A", "B", "D"] for r in json.loads(first.stdout)["schedule"]))
            self.assertFalse((Path(tmp)/"run").exists())
