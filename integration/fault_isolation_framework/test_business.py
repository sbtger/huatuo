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


class IndependentProgressTest(unittest.TestCase):
    def test_pressure_worker_stall_does_not_stop_independent_tick(self):
        source = (
            Path(__file__).parent / "workloads/services/python_service.py"
        ).read_text()
        source = source.replace("    chunks = []", "    chunks = []\n    time.sleep(3)")
        p = subprocess.Popen(
            [sys.executable, "-u", "-c", source, "1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            url = json.loads(p.stdout.readline())["url"]

            def tick():
                with urllib.request.urlopen(url + "/state", timeout=1) as response:
                    return json.load(response)["ticks"]

            before = tick()
            time.sleep(0.4)
            self.assertGreater(tick(), before, "tick is coupled to the pressure worker")
        finally:
            p.terminate()
            p.communicate(timeout=5)


class PerformanceListenerTest(unittest.TestCase):
    def test_python_fixture_can_bind_a_requested_external_port(self):
        import os,socket
        with socket.socket() as listener:
            listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
        env=dict(os.environ,HUATUO_TEST_BIND="0.0.0.0",HUATUO_TEST_PORT=str(port))
        process=subprocess.Popen([sys.executable,str(Path(__file__).parent/"workloads/services/python_service.py"),"1"],
                                 env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            ready=json.loads(process.stdout.readline())
            self.assertEqual(ready["url"],"http://127.0.0.1:%d"%port)
            with urllib.request.urlopen(ready["url"]+"/work",timeout=2) as response:
                self.assertEqual(response.status,200)
        finally:
            process.terminate();process.communicate(timeout=5)
