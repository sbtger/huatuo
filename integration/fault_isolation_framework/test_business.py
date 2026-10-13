# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Check the real CPython fixture's externally visible transaction contract."""
import json, subprocess, sys, time, unittest, urllib.error, urllib.request
from pathlib import Path


class BusinessContractTest(unittest.TestCase):
    def setUp(self):
        self.p = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).parent / "workloads/services/python_service.py"),
                "1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = json.loads(self.p.stdout.readline())
        self.url = ready["url"]

    def tearDown(self):
        self.p.terminate()
        self.p.communicate(timeout=5)

    def call(self, path, post=False):
        req = urllib.request.Request(self.url + path, data=b"" if post else None)
        with urllib.request.urlopen(req, timeout=1) as r:
            return json.load(r)

    def test_committed_state_survives_independent_read(self):
        self.assertEqual(self.call("/txn?seq=1", True)["total"], 13)
        self.assertEqual(self.call("/txn?seq=2", True)["total"], 39)
        self.assertEqual(self.call("/txn?seq=3", True)["total"], 78)
        state = self.call("/state")
        self.assertEqual((state["seq"], state["total"]), (3, 78))

    def test_rejected_duplicate_does_not_modify_state(self):
        self.call("/txn?seq=1", True)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.call("/txn?seq=1", True)
        self.assertEqual(raised.exception.code, 409)
        state = self.call("/state")
        self.assertEqual((state["seq"], state["total"]), (1, 13))

    def test_background_progress_is_independent_of_requests(self):
        before = self.call("/state")["ticks"]
        time.sleep(0.4)
        self.assertGreater(self.call("/state")["ticks"], before)


if __name__ == "__main__":
    unittest.main()
