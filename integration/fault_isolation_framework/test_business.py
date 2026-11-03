# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Check the real CPython fixture's externally visible transaction contract."""
import json, subprocess, sys, time, unittest, urllib.error, urllib.request, tempfile
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


class ApplicationOracleTest(unittest.TestCase):
    def test_hotspot_recipe_uses_full_working_set_and_real_payload(self):
        from fault_isolation_framework.workloads.application_protocol import cache_operation,payload
        ops=[cache_operation(i,923,100000) for i in range(10000)]
        self.assertTrue(any(key>20000 for _,key in ops))
        self.assertTrue(any(key>1024 for _,key in ops))
        self.assertEqual({op for op,_ in ops},{'GET','SET','DELETE'})
        self.assertEqual(payload(10),bytes([107])*65536)
        self.assertEqual(payload(11),bytes([108])*1024)

    def test_capacity_refuses_client_limited_or_unstable_baseline(self):
        from fault_isolation_framework.workloads.application_protocol import capacity_state
        stable=dict(offered_rps=1000,success_rps=995,errors=0,timeouts=0,body_errors=0,
                    client_cpu_cores=1,client_cores=4,initial_p99_ms=3,final_p99_ms=3.1,
                    initial_backlog_ms=1,final_backlog_ms=1.1)
        self.assertEqual(capacity_state(stable)['state'],'STABLE_TESTED_RATE')
        self.assertEqual(capacity_state(dict(stable,client_cpu_cores=3.8))['state'],'CLIENT_LIMITED')
        self.assertEqual(capacity_state(dict(stable,success_rps=800))['state'],'APPLICATION_UNSTABLE')
        self.assertEqual(capacity_state(dict(stable,final_p99_ms=20))['state'],'APPLICATION_UNSTABLE')

class ApplicationNativeTest(unittest.TestCase):
    def test_hdr_counts_merge_before_tail_and_preserve_sample_scope(self):
        from fault_isolation_framework.workloads.application_tools import merge_wrk_histograms, histogram_metrics
        with tempfile.TemporaryDirectory() as tmp:
            paths=[]
            for name,rows in [('a','B,9,1000,999\nB,9,50000,1\n'),('b','B,9,2000,1000\n')]:
                path=Path(tmp)/(name+'.csv');path.write_text('H,1,60000000,3,0\nC,3,1000,0\n'+rows);paths.append(path)
            merged=merge_wrk_histograms(paths)
            self.assertEqual(merged['slots']['3']['count'],2000)
            tails=histogram_metrics(merged['histograms']['9'])
            self.assertEqual(tails['p99_ms'],2)
            self.assertIsNone(tails['p999_ms'])
            self.assertEqual(tails['max_ms'],50)
            self.assertEqual(tails['count'],2000)

    def test_application_jobs_are_typed_bounded_and_cannot_choose_tools(self):
        from fault_isolation_framework.workloads.application_tools import validate_application
        import time
        job=dict(application='cache',url='http://10.0.2.2:40000',rate=10000,duration=210,
                 start_monotonic=time.monotonic()+3,records=100000,seed=923,connections=64,
                 warmup=30,baseline=60,hold=60,trace_margin=4,diagnostic=False)
        validate_application(job,'10.0.2.2',{40000})
        with self.assertRaises(ValueError):validate_application(dict(job,tool='/bin/sh'),'10.0.2.2',{40000})
        with self.assertRaises(ValueError):validate_application(dict(job,url='http://127.0.0.1:40000'),'10.0.2.2',{40000})
        with self.assertRaises(ValueError):validate_application(dict(job,duration=10000),'10.0.2.2',{40000})
        with self.assertRaises(ValueError):validate_application(dict(job,diagnostic='true'),'10.0.2.2',{40000})

class ApplicationDatasetTest(unittest.TestCase):
    def test_dataset_digest_matches_actual_ascending_payload_contract(self):
        from fault_isolation_framework.workloads.application_protocol import dataset_digest,payload
        import hashlib
        digest=hashlib.sha256()
        for key in range(1024):
            body=payload(key)
            digest.update(('%d:%d:%s\n'%(key,len(body),hashlib.sha256(body).hexdigest())).encode())
        self.assertEqual(dataset_digest(1024),digest.hexdigest())

class ApplicationCapacityResolutionTest(unittest.TestCase):
    def test_insufficient_backlog_samples_are_unstable_not_zero_or_exception(self):
        from fault_isolation_framework.workloads.application_protocol import capacity_state
        row=dict(offered_rps=1,success_rps=1,errors=0,client_cpu_cores=.1,client_cores=4,
                 initial_p99_ms=None,final_p99_ms=None,initial_backlog_ms=None,final_backlog_ms=None)
        self.assertEqual(capacity_state(row)['state'],'APPLICATION_UNSTABLE')

class ApplicationQualityTest(unittest.TestCase):
    def test_completed_C_keeps_body_failure_and_timeout_as_quality_failures(self):
        from fault_isolation_framework.workloads.application_tools import business_quality
        window=dict(requests=60000,response_errors=0,success_rps=1000,offered_rps=1000)
        for name in ('body_errors','timeouts'):
            native=dict(counters={name:1})
            result=business_quality(native,{'capture':window})
            self.assertFalse(result['valid']);self.assertTrue(any(name in e for e in result['errors']))
        self.assertTrue(business_quality(dict(counters={}),{'capture':window})['valid'])

    def test_one_pair_large_positive_and_negative_deltas_are_descriptive(self):
        from fault_isolation_framework.adapters.huatuo.application_performance import report
        for delta in (20,-20):
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)
                trials=[dict(group=g,pressure_percent=60,scenario='normal',valid=True,metrics={'capture.p99_ms':value}) for g,value in [('B',30),('C',30+delta)]]
                (path/'results.json').write_text(json.dumps(dict(config=dict(calibration_only=False,scenario='normal60'),trials=trials,error='')))
                comparison=report(path)['comparisons'][0]
                self.assertEqual(comparison['state'],'DESCRIPTIVE_ONE_PAIR')
                self.assertEqual(comparison['C_minus_B']['capture.p99_ms'],delta)
                self.assertEqual(comparison['B']['capture.p99_ms'],30)
                self.assertEqual(comparison['C']['capture.p99_ms'],30+delta)

class ApplicationLuaOracleTest(unittest.TestCase):
    def test_luajit_recipe_matches_independent_oracle_above_ten_million(self):
        import os,shutil
        from fault_isolation_framework.workloads.application_protocol import cache_operation
        interpreter=os.environ.get('HUATUO_LUAJIT') or shutil.which('luajit')
        if not interpreter:self.skipTest('pinned LuaJIT external tool integration is separate')
        path=Path(__file__).parent/'workloads/applications/cache_recipe.lua'
        cases=[(ordinal,seed) for ordinal in (0,1,10000001,30000000) for seed in (0,923)]
        script='local recipe=dofile('+json.dumps(str(path))+');'+''.join('do local op,key=recipe(%d,%d,100000);print(op..","..key) end;'%case for case in cases)
        result=subprocess.run([interpreter,'-e',script],check=True,capture_output=True,text=True)
        self.assertEqual(result.stdout.splitlines(),['%s,%d'%cache_operation(ordinal,seed,100000) for ordinal,seed in cases])

class ApplicationBracketTest(unittest.TestCase):
    def test_finite_B_refinement_freezes_only_actually_tested_stable_rate(self):
        from fault_isolation_framework.workloads.application_protocol import bracket_capacity
        calls=[]
        def probe(rate):
            calls.append(rate);return dict(state='STABLE_TESTED_RATE' if rate<=9000 else 'APPLICATION_UNSTABLE',offered_rps=rate)
        result=bracket_capacity([100,300,1000,3000,10000,30000],probe)
        self.assertEqual(len(calls),9)
        self.assertEqual(result['status'],'BRACKETED_TESTED_CAPACITY')
        self.assertEqual(result['highest_tested_stable_rps'],8687)
        self.assertIn(result['highest_tested_stable_rps'],calls)
        self.assertLessEqual(result['relative_bracket_width'],.1)
        self.assertLessEqual(result['first_tested_unstable_rps'],10000)

    def test_client_limit_and_stable_ladder_ceiling_do_not_define_app_capacity(self):
        from fault_isolation_framework.workloads.application_protocol import bracket_capacity
        for probe in (lambda rate:dict(state='STABLE_TESTED_RATE'),lambda rate:dict(state='CLIENT_LIMITED')):
            self.assertEqual(bracket_capacity([100,1000],probe)['status'],'CAPACITY_NOT_BRACKETED')

class ApplicationFrozenProfileTest(unittest.TestCase):
    def test_reused_B_calibration_rejects_other_app_rate_or_source_identity(self):
        from fault_isolation_framework.workloads.application_protocol import validate_frozen_profile
        expected=dict(application='spring',seed=923,connections=128,source_sha256='abc')
        frozen=dict(profile_identity=expected)
        validate_frozen_profile(frozen,expected)
        for key,value in [('application','fastapi'),('connections',16),('source_sha256','changed')]:
            with self.assertRaises(ValueError):validate_frozen_profile(frozen,dict(expected,**{key:value}))

class ApplicationCapacityClassificationTest(unittest.TestCase):
    def test_business_capacity_failure_is_unstable_upper_bound_but_bad_protocol_is_invalid(self):
        from fault_isolation_framework.workloads.application_protocol import capacity_probe_state
        row=dict(valid=False,measurement_protocol_valid=True,frozen_pressure={'frozen':True},capture_quality_errors=[],errors=['business quality: timeouts=3'],capacity_probe={'decision':{'state':'APPLICATION_UNSTABLE'}})
        self.assertEqual(capacity_probe_state(row),'APPLICATION_UNSTABLE')
        self.assertEqual(capacity_probe_state(dict(row,measurement_protocol_valid=False)),'INVALID_PREFLIGHT')
        self.assertEqual(capacity_probe_state(dict(row,errors=row['errors']+['cleanup failed'])),'INVALID_PREFLIGHT')
        self.assertEqual(capacity_probe_state(dict(row,frozen_pressure=None)),'INVALID_PREFLIGHT')

class ApplicationSDKCounterTest(unittest.TestCase):
    def test_missing_SDK_error_taxonomy_is_protocol_failure_not_zero_errors(self):
        from fault_isolation_framework.workloads.application_tools import validate_sdk_result
        with self.assertRaises(ValueError):validate_sdk_result({'metrics':{}},2)
        counters=dict(requests=2,timeouts=0,body_errors=1,queue_full=0,rpc_errors=0,protocol_errors=0,cancelled=0)
        result=dict(counters=counters,metrics={'1:GET':{'count':2,'errors':1}},cancelled=False)
        validate_sdk_result(result,2)
        with self.assertRaises(ValueError):validate_sdk_result(result,3)

class ApplicationReviewRegressionTest(unittest.TestCase):
    def test_HTTP_subwindow_uses_intended_arrival_when_completion_crosses_phase(self):
        import os,shutil
        interpreter=os.environ.get('HUATUO_LUAJIT') or shutil.which('luajit')
        if not interpreter:self.skipTest('pinned LuaJIT integration executed on builder')
        from fault_isolation_framework.workloads.application_protocol import cache_operation
        operation,key=cache_operation(1,923,1024);size=65536 if key%10==0 else 1024
        path=Path(__file__).parent/'workloads/applications/cache.lua'
        with tempfile.TemporaryDirectory() as tmp:
            script='dofile('+json.dumps(str(path))+');bench_index=0;wrk={bench_record=function(p,o,w,...) print(p..","..w) end,bench_dump=function()end};'
            script+='init({"1024","923","1","60","60","60","60","1000","1000","1300",'+json.dumps(tmp)+',"0"});'
            script+='response(200,{["X-Bench-Ordinal"]="1",["X-Bench-Operation"]="%s",["X-Bench-Key"]="%d"},string.rep(string.char(%d),%d),1119900000,1120000000,1125100000,"GET /cache/%d?ordinal=1&seed=923 HTTP/1.1");bench_finish();'%(operation,key,97+key%26,size,key)
            result=subprocess.run([interpreter,'-e',script],check=True,capture_output=True,text=True)
            self.assertEqual(result.stdout.strip(),'1,23')

    def test_SDK_reports_single_application_invocation_without_claiming_one_wire_attempt(self):
        import os
        binary=os.environ.get('HUATUO_ETCD_SDK')
        if not binary:self.skipTest('pinned SDK integration executed on builder')
        result=subprocess.run([binary,'--mode=config','--endpoint=http://127.0.0.1:1'],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        config=json.loads(result.stdout)
        self.assertEqual(config['max_unary_attempts'],1)
        self.assertTrue(config['configured_grpc_retry_disabled'])
        self.assertTrue(config['transparent_transport_retries_possible'])
        self.assertIsNone(config['wire_attempts_measured'])
