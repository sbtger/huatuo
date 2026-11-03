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


class ExternalPerformanceCLITest(unittest.TestCase):
    def invoke(self,*extra):
        script=Path(__file__).parent/'performance.py'
        return subprocess.run([sys.executable,str(script),'--module','memory_threshold_snapshot','--experiment','pulse',
            '--build','/tmp/build','--bpf-dir','/tmp/bpf','--output','/tmp/unused-performance-plan','--plan']+list(extra),capture_output=True)

    def test_external_redis_plan_has_no_side_effects(self):
        import json
        result=self.invoke('--redis','--redis-fork-interval','10','--load-controller-url','http://127.0.0.1:12345','--load-token-file','/tmp/token-path-only')
        self.assertEqual(result.returncode,0,result.stderr)
        config=json.loads(result.stdout)['config']
        self.assertTrue(config['redis']);self.assertEqual(config['service_port_base'],30000)

    def test_incomplete_external_credentials_fail_before_output(self):
        result=self.invoke('--load-controller-url','http://127.0.0.1:12345')
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'external load requires',result.stderr)

    def test_matrix_common_options_merge_without_creating_output(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);matrix=root/'matrix.json';common=root/'common.json';output=root/'out'
            matrix.write_text(json.dumps([dict(name='redis',options=dict(module='memory_threshold_snapshot',qps=80))]))
            common.write_text(json.dumps({'redis':True,'qps':40,'load-controller-url':'http://127.0.0.1:12345','load-token-file':'/tmp/path-only'}))
            result=subprocess.run([sys.executable,str(Path(__file__).parent/'performance_matrix.py'),'--matrix',str(matrix),'--common-options',str(common),
                '--build',tmp,'--bpf-dir',tmp,'--output',str(output),'--plan'],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            command=json.loads(result.stdout)[0]['command']
            self.assertIn('--redis',command);self.assertEqual(command[command.index('--qps')+1],'80')
            self.assertFalse(output.exists())


class NativeSnapshotCostCLITest(unittest.TestCase):
    def test_native_plan_uses_only_matched_b_d_groups(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            command=[sys.executable,str(Path(__file__).parent/'performance.py'),'--business','etcd',
                '--module','memory_threshold_snapshot','--experiment','pulse','--native-root',tmp,
                '--snapshot-helper',tmp+'/helper','--load-controller-url','http://127.0.0.1:19890',
                '--load-token-file',tmp+'/token','--build',tmp,'--bpf-dir',tmp,'--output',tmp+'/out','--plan']
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(all(sorted(r['groups'])==['B','D'] for r in json.loads(result.stdout)['schedule']))
            self.assertFalse((Path(tmp)/'out').exists())
            bad=subprocess.run(command+['--hold','10'],capture_output=True,text=True)
            self.assertEqual(bad.returncode,2)


class ResidentPressureCLITest(unittest.TestCase):
    def test_resident_plan_uses_abc_and_requires_90_before_95(self):
        import json
        command=[sys.executable,str(Path(__file__).parent/'performance.py'),'--business','resident',
            '--module','memory_threshold_snapshot','--output','/tmp/unused-resident-plan','--build','/tmp/build',
            '--bpf-dir','/tmp/bpf','--snapshot-helper','/tmp/helper','--resident-go','/tmp/resident-go',
            '--load-controller-url','http://127.0.0.1:19890','--load-token-file','/tmp/path-only','--plan']
        result=subprocess.run(command,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(all(sorted(row['groups'])==['A','B','C'] for row in json.loads(result.stdout)['schedule']))
        bad=subprocess.run(command+['--pressure-levels','95'],capture_output=True,text=True)
        self.assertEqual(bad.returncode,2)

class ApplicationPlanTest(unittest.TestCase):
    def test_real_application_plan_defaults_to_one_round_without_starting_jobs(self):
        from fault_isolation_framework.application_performance import parser,plan
        args=parser().parse_args(['--application','spring','--output','/unused','--plan'])
        result=plan(args)
        self.assertEqual(result['groups'],['B','C'])
        self.assertEqual(result['repeats'],1)
        self.assertEqual(result['scenarios'],[{'pressure_percent':60,'load':'normal'},{'pressure_percent':90,'load':'normal'},{'pressure_percent':90,'load':'high'}])
        self.assertEqual(result['captures_per_C'],1)
        self.assertGreaterEqual(result['phase_seconds']['baseline'],60)
        with self.assertRaises(ValueError):plan(parser().parse_args(['--application','spring','--output','/unused','--repeats','5']))

class ApplicationBudgetTest(unittest.TestCase):
    def test_invalid_native_measurement_budgets_fail_before_any_VM_work(self):
        from fault_isolation_framework.application_performance import parser,plan
        for option,value in [('--business-cpus','-1'),('--business-cpus','nan'),('--memory-limit-mib','-1'),('--sample-interval','0'),('--capture-timeout','4'),('--warmup','inf'),('--workers','0')]:
            with self.subTest(option=option,value=value):
                args=parser().parse_args(['--application','spring','--output','/unused',option,value])
                with self.assertRaises(ValueError):plan(args)


class ApplicationDiagnosticPlanTest(unittest.TestCase):
    def test_diagnostic_only_default_all_never_reuses_directory_for_ninety_percent(self):
        from fault_isolation_framework.application_performance import parser,plan
        result=plan(parser().parse_args(['--application','fastapi','--output','/unused','--diagnostic-only']))
        self.assertEqual(result['scenarios'],[dict(pressure_percent=60,load='normal')])
        self.assertEqual(result['captures_per_C'],0)
        self.assertNotIn('C',result['groups'])
