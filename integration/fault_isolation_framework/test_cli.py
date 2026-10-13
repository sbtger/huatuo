# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
