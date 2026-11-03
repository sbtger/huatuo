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


class NativeBusinessMetricsTest(unittest.TestCase):
    def test_native_aggregates_do_not_invent_request_rows(self):
        from fault_isolation_framework.workloads.native_tools import parse_etcd, parse_kafka
        stats=parse_etcd('Requests/sec: 42.5\n  95% in 0.0020 secs\n  99% in 0.0040 secs\n')
        self.assertEqual(stats['ops_s'],42.5)
        self.assertEqual(stats['p99_ms'],4)
        self.assertEqual(stats['measurement'],'native RPC aggregate')
        with self.assertRaises(ValueError):parse_etcd('Requests/sec: 0')
        kafka=parse_kafka('100 records sent, 50.0 records/sec (0.01 MB/sec), 2.0 ms avg latency, 4.0 ms max latency, 1 ms 50th, 3 ms 95th, 4 ms 99th, 4 ms 99.9th.')
        self.assertEqual(kafka['records'],100)
        self.assertEqual(kafka['ack_p99_ms'],4)
        with self.assertRaises(ValueError):parse_kafka('0 records sent')

    def test_capacity_uses_only_valid_tested_rates_and_explicit_slo(self):
        from fault_isolation_framework.workloads.native_tools import tested_capacity
        trials=[dict(rate=r,valid=valid,group=g,repeat=0,metrics=dict(p99_ms=tail))
                for r,valid,g,tail in [(10,True,'B',2),(10,True,'D',3),(20,True,'B',4),(20,False,'D',4)]]
        self.assertEqual(tested_capacity(trials,5,1)['highest_tested_rate'],10)
        self.assertEqual(tested_capacity(trials,None,1)['status'],'NOT_EVALUATED')

    def test_etcd_requires_all_benchmark_keys_and_acknowledged_versions(self):
        from unittest.mock import patch
        from fault_isolation_framework.workloads.native_business import EtcdProduct,VALUE,b64
        product=EtcdProduct.__new__(EtcdProduct);product.role='target';product.url='http://unused'
        product.proof=lambda: {};product.expected_puts=256
        def reply(url,operation,body):
            if operation=='range':return dict(kvs=[dict(value=b64(VALUE))])
            self.assertEqual(len(body['success']),64)
            return dict(responses=[dict(response_range=dict(kvs=[dict(value=b64(b'x'*256),version=4)])) for _ in range(64)])
        with patch('fault_isolation_framework.workloads.native_business.kv',side_effect=reply):
            self.assertEqual(product.verify()['benchmark_committed_versions'],256)
            product.expected_puts=257
            with self.assertRaisesRegex(Exception,'version count mismatch'):product.verify()


class ResidentKVContractTest(unittest.TestCase):
    def test_seeded_mixed_operations_have_known_payload_checksums(self):
        from fault_isolation_framework.workloads.resident_protocol import operation,expected,payload,size
        kinds={operation(i,923,4096)[0] for i in range(1000)}
        self.assertEqual(kinds,{'GET','SET','DELETE'})
        self.assertEqual(expected(1,923,4096),expected(1,923,4096))
        self.assertNotEqual(expected(1,923,4096),expected(2,923,4096))
        self.assertEqual(len(payload(0)),65536);self.assertEqual(len(payload(1)),1024)

    def test_resident_calibration_cannot_adjust_fill_during_capture(self):
        from fault_isolation_framework.workloads.resident_kv import freeze_plan
        plan=freeze_plan(10000,512<<20,60,[306<<20,307<<20,306<<20])
        self.assertEqual(plan['records'],10000);self.assertTrue(plan['frozen'])
        with self.assertRaises(ValueError):freeze_plan(10000,512<<20,90,[350<<20,470<<20])

    def test_tail_sample_budget_distinguishes_p999_from_p99(self):
        from fault_isolation_framework.core.performance import percentile
        self.assertIsNone(percentile(list(range(9999)),99.9))
        self.assertIsNotNone(percentile(list(range(10000)),99.9))

    def test_frozen_fill_recipe_replays_identical_allocation_order_and_settling(self):
        from fault_isolation_framework.workloads.resident_kv import replay_fill
        calls=[];sleeps=[]
        plan=dict(records=3000,fill_recipe=[dict(records=n,settle_seconds=.5) for n in (1024,2000,3000)],plateau_samples=5,plateau_interval=.25)
        replay_fill(plan,calls.append,sleeps.append)
        self.assertEqual(calls,[1024,2000,3000]);self.assertEqual(sleeps,[.5,.5,.5]+[.25]*5)
        with self.assertRaises(ValueError):replay_fill(dict(plan,records=3001),calls.append,sleeps.append)

    def test_python_records_are_tracked_and_gc_timing_is_bounded(self):
        import gc,importlib.util
        path=Path(__file__).parent/'workloads/resident/python_kv.py'
        spec=importlib.util.spec_from_file_location('resident_kv_fixture_test',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        try:
            record=module.Record(10)
            self.assertTrue(gc.is_tracked(record));self.assertTrue(gc.is_tracked(record.labels))
            self.assertTrue(gc.is_tracked(record.children));self.assertTrue(gc.is_tracked(record.children[0]))
            before=module.gc_timing['collections']
            module.gc_timing_callback('start',dict(generation=2));module.gc_timing_callback('stop',dict(generation=2))
            self.assertEqual(module.gc_timing['collections'],before+1)
            self.assertFalse(module.gc_timing['active']);self.assertGreaterEqual(module.gc_timing['collector_thread_cpu_ns'],0)
        finally:gc.callbacks.remove(module.gc_timing_callback)

    def test_replay_calibration_requires_two_replicas_and_rejects_variance(self):
        from fault_isolation_framework.workloads.resident_kv import canonical_fill_recipe,replay_candidate
        recipe=canonical_fill_recipe(45000)
        self.assertEqual([s['records'] for s in recipe],[1024,21024,41024,45000])
        replica=lambda value:dict(valid=True,pressure_samples=[value]*5)
        with self.assertRaises(ValueError):replay_candidate(10000,100,90,2,[replica(90)])
        self.assertEqual(replay_candidate(10000,100,90,2,[replica(89),replica(91)])['status'],'FROZEN')
        self.assertEqual(replay_candidate(10000,100,90,2,[replica(85),replica(95)])['status'],'UNREACHABLE')
        decision=replay_candidate(10000,100,90,2,[replica(85),replica(86)])
        self.assertEqual(decision['status'],'REFINE');self.assertGreater(decision['records'],10000)
        self.assertEqual(replay_candidate(10000,100,90,2,[dict(valid=False),replica(90)])['status'],'INVALID_PREFLIGHT')
