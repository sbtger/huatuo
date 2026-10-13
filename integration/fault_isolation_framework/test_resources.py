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
