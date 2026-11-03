# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""B/D native-business trials using existing ownership, Agent and sampling."""
import hashlib
import json
import os
import random
import threading
import time
from pathlib import Path
from ...core.documents import read_documents
from ...core.evidence import EvidenceStore
from ...core.performance import paired_comparisons, strict_documents
from ...core.util import require, write_control, wait_for
from ...environments.linux import ManagedProcess, identity
from ...environments.supervisor import own
from ...environments.docker import DockerEnvironment
from ...environments.performance import PerformanceSampler, resource_metrics
from ...environments.remote_load import RemoteLoad
from ...workloads.native_business import PRODUCTS
from ...workloads.native_tools import tested_capacity
from .agent import verify_build
from .discovery import Discovery
from .memsnapshot.adapter import MemsnapshotAdapter
from .performance import PerformanceAdapter, capture_records, captures_cover_targets


class RealBusinessAdapter(PerformanceAdapter):
    def prepare(self):
        verify_build(self.build)
        self.products=[];self.extra_processes=[];self.redis=None
        self.environment=DockerEnvironment(self.out);self.environment.build_image(self.build/'business-go')
        self.discovery=Discovery(self.environment.driver);self.discovery.start()
        self.server,self.api=self.discovery.server,self.environment.api
        self.targets=[]
        for role,offset in [('target',0),('neighbor',32)]:
            product=PRODUCTS[self.a.business](self,role,offset);self.products.append(product)
            target=product.start();self.targets.append(target)
            if role=='target':self.discovery.register(target)
            product.seed_proof=product.pressure()
        self.pressured=[self.targets[0]];self.measurement_targets=self.targets;self.driver=None
        self.snapshot_control=self.out/'snapshot-command.json';write_control(self.snapshot_control,'{"id":0}')
        self.helper_process=ManagedProcess()
        helper=self.helper_process.start([self.a.snapshot_helper,'--control',str(self.snapshot_control),'--worker',str(self.build/'huatuo-memsnapshot-worker'),'--cgroup-root',str(self.environment.mount/('huatuo-memsnapshot-worker-cost-'+self.out.name)),'--timeout','%ds'%self.a.capture_timeout,'--top-k',str(self.a.top_k)],self.out/'snapshot-helper.jsonl',dict(os.environ))
        self.snapshot_helper=helper
        self.helper_cgroup=self.environment.mount/('huatuo-memsnapshot-worker-cost-'+self.out.name)
        wait_for('snapshot helper ready',lambda:any(json.loads(line).get('ready') for line in (self.out/'snapshot-helper.jsonl').read_text().splitlines() if line.startswith('{')),timeout=20)
        for path in sorted(self.helper_cgroup.iterdir()):
            if path.is_dir():own('cgroup',str(path))
        own('cgroup',str(self.helper_cgroup))
        manifest=dict(claim='real product snapshot-cost experiment; persistent test helper invokes unchanged production collector and WorkerManager',
                      kernel=os.uname().release,cpu_count=os.cpu_count(),business=self.a.business,
                      snapshot_helper_sha256=hashlib.sha256(Path(self.a.snapshot_helper).read_bytes()).hexdigest(),
                      route='Agent feature disabled in both groups; helper idle in B, controlled collector snapshots in D; excludes daemon detection/ranking/persistence overhead',
                      seeds={p.role:p.seed_proof for p in self.products},
                      native_manifest=json.loads((Path(self.a.native_root)/'manifest.json').read_text()),
                      build=json.loads((self.build/'build.json').read_text()),
                      agent_sha256=hashlib.sha256((self.build/'agent').read_bytes()).hexdigest(),
                      bpf_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(self.a.bpf_dir).glob('*.o')},
                      targets=[{k:(str(v) if isinstance(v,Path) else v) for k,v in t.items()} for t in self.targets])
        (self.out/'environment.json').write_text(json.dumps(manifest,indent=2)+'\n')

    def start_agent(self,**kwargs):
        return MemsnapshotAdapter.start_agent(self,**kwargs)

    def cleanup(self):
        errors=[]
        try:self.stop_agent(kill=True)
        except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'helper_process'):
            try:
                self.helper_process.stop()
                if hasattr(self,'helper_cgroup'):
                    for child in self.helper_cgroup.iterdir():
                        if child.is_dir():child.rmdir()
                    self.helper_cgroup.rmdir()
            except Exception as exc:errors.append(repr(exc))
        for product in getattr(self,'products',[]):
            try:product.close()
            except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'environment'):
            try:self.environment.cleanup([])
            except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'discovery'):self.discovery.cleanup()
        require(not errors,'native cleanup failed: '+repr(errors))


def execute_trial(args,directory,group,repeat,rate):
    evidence=EvidenceStore(directory);owner=RealBusinessAdapter(args,evidence)
    result=dict(group=group,repeat=repeat,rate=rate,valid=False,errors=[],metrics={},windows={})
    sampler=None;remote=None;pressure_thread=None;stop=threading.Event();pressure=dict(errors=[])
    try:
        owner.prepare();owner.start_agent(plain=True,disabled=True)
        sampler=PerformanceSampler(owner,evidence.output/'resources.jsonl',args.sample_interval);sampler.start()
        url='http://%s:%d'%(args.load_target_host,args.load_target_base_port)
        for name,duration in [('warmup',args.warmup),('baseline',args.baseline),('trigger',args.hold),('recovery',args.recovery)]:
            window=evidence.output/name;window.mkdir()
            remote=RemoteLoad(args.load_controller_url,args.load_token_file,window,args.max_clock_error);remote.calibrate()
            start=time.monotonic()+3
            if name=='trigger' and group=='D':
                def apply(at=start):
                    try:
                        for index in range(args.snapshot_count):
                            if stop.wait(max(0,at+12+index*args.snapshot_interval-time.monotonic())):return
                            pressure.setdefault('commands',[]).append(dict(id=index+1,time=time.monotonic(),epoch=time.time(),target_pid=owner.targets[0]['pid']))
                            target=owner.targets[0]
                            write_control(owner.snapshot_control,json.dumps(dict(id=index+1,pid=target['pid'],start_ticks=target['identity'][1])))
                            wait_for('controlled production collector result',lambda:any(json.loads(line).get('id')==index+1 for line in (owner.out/'snapshot-helper.jsonl').read_text().splitlines() if line.startswith('{')),timeout=args.capture_timeout+10)
                    except Exception as exc:pressure['errors'].append(repr(exc))
                pressure_thread=threading.Thread(target=apply,daemon=True);pressure_thread.start()
            begin=time.monotonic()
            native=remote.run_native(dict(native=args.business,url=url,rate=rate,duration=duration,
                                          records=int(rate*duration),connections=args.workers,start_monotonic=start))
            if args.business=='etcd':owner.products[0].expected_puts=getattr(owner.products[0],'expected_puts',0)+int(rate*duration)
            end=time.monotonic()
            result['windows'][name]=dict(begin=begin,end=end,native=native,resources=resource_metrics(sampler.rows,begin,end))
            if pressure_thread and name=='trigger':
                pressure_thread.join(args.capture_timeout+12);require(not pressure_thread.is_alive(),'snapshot schedule did not finish')
                require(not pressure['errors'],'snapshot schedule failed: '+repr(pressure['errors']))
            if name!='warmup':
                for key,value in native['metrics'].items():result['metrics'][name+'.'+key]=value
        result['metrics']['p99_ms']=result['windows']['trigger']['native']['metrics']['p99_ms']
        sampler.close()
        resources=resource_metrics(sampler.rows,result['windows']['baseline']['begin'],result['windows']['recovery']['end'])
        require(resources['samples']>=2 and not resources['errors'],'native resource samples incomplete')
        result.update(resources=resources,correctness={p.role:p.verify() for p in owner.products})
        result['metrics'].update(cpu_seconds=resources['cpu_seconds'],sampled_agent_tree_rss_peak_bytes=resources['sampled_agent_tree_rss_peak_bytes'])
        require(owner.agent.poll() is None,'Agent exited during native business load');owner.stop_agent()
        docs=strict_documents(owner.event_path)
        require(not docs,'Agent feature must remain disabled in both cost groups')
        helper_rows=[json.loads(line) for line in (owner.out/'snapshot-helper.jsonl').read_text().splitlines() if line.startswith('{')]
        captures=[r for r in helper_rows if 'id' in r]
        result['metrics'].update(snapshot_calls=len(captures),snapshot_wall_total_ms=sum(c.get('wall_ms',0) for c in captures),snapshot_wall_max_ms=max((c.get('wall_ms',0) for c in captures),default=0),snapshot_provider_total_ms=sum((c.get('result') or {}).get('Snapshot',{}).get('duration_ms',0) for c in captures))
        result.update(captures=captures,neighbor_selected=any(r['pid']==owner.targets[1]['pid'] for r in captures),
                      capture_route='test-only persistent production collector.Snapshot + WorkerManager',
                      agent_triggers_disabled=True,business_footprint_fixed=True)
        samples=[r['cgroups'][owner.targets[0]['id']]['memory.usage_in_bytes'] for r in sampler.rows if owner.targets[0]['id'] in r.get('cgroups',{})]
        result['observed_target_cgroup_peak_bytes']=max(map(int,samples),default=0)
        helper_samples=[]
        for row in sampler.rows:
            procs={}
            for key,proc in row['processes'].items():
                if key=='snapshot-helper':procs['agent']=proc
                elif key.startswith('snapshot-child-'):procs['child-'+key[len('snapshot-child-'):]]=proc
            helper_samples.append(dict(time=row['time'],errors=row['errors'],processes=procs))
        begin=result['windows']['trigger']['begin'];end=result['windows']['trigger']['end']
        helper_resources=resource_metrics(helper_samples,begin,end)
        helper_resources['helper_self_cpu_seconds']=helper_resources.pop('agent_self_cpu_seconds')
        helper_resources['cpu_accounting']=helper_resources['cpu_accounting'].replace('Agent','Snapshot helper')
        result['snapshot_resources']=helper_resources
        result['metrics'].update(snapshot_cpu_seconds=helper_resources['cpu_seconds'],snapshot_sampled_tree_rss_peak_bytes=helper_resources['sampled_agent_tree_rss_peak_bytes'])
        require(not result['neighbor_selected'],'uncollected neighbor was captured')
        if group=='D':
            require(len(captures)==args.snapshot_count,'missing controlled snapshots')
            for capture in captures:
                result_data=capture.get('result') or {};snapshot=result_data.get('Snapshot') or {}
                status=snapshot.get('status');language=result_data.get('Language')
                require(capture['pid']==owner.targets[0]['pid'] and result_data.get('Process',{}).get('start_time_ticks')==owner.targets[0]['identity'][1],'snapshot process identity mismatch')
                require(language==owner.targets[0]['language'],'snapshot provider language mismatch')
                require(not capture.get('error') and status in (('complete',) if language=='go' else ('complete','partial')) and bool(snapshot.get('entries')),'controlled snapshot unavailable/empty/failed; never count as cheap success: '+repr(capture))
        else:require(not captures,'unexpected controlled snapshot in B')
        result['valid']=True
    except Exception as exc:result['errors'].append(repr(exc))
    finally:
        stop.set()
        if remote:
            try:remote.cancel()
            except Exception as exc:result['errors'].append('remote cleanup: '+repr(exc))
        if pressure_thread and pressure_thread.is_alive():pressure_thread.join(120)
        if sampler and not sampler.stream.closed:
            try:sampler.close()
            except Exception as exc:result['errors'].append(repr(exc))
        try:owner.cleanup()
        except Exception as exc:result['errors'].append(repr(exc))
        result['valid']=result['valid'] and not result['errors']
        (evidence.output/'pressure.json').write_text(json.dumps(pressure,indent=2)+'\n')
        evidence.save(result)
    return result


def campaign(args,output):
    trials=[];rng=random.Random(args.seed);output=Path(output)
    for rate in map(int,args.rates.split(',')):
        for repeat in range(args.repeats):
            groups=['B','D'];rng.shuffle(groups)
            for group in groups:
                name='rate-%d-repeat-%02d-%s'%(rate,repeat,group)
                write_control(output/'progress.json',json.dumps(dict(phase=name,started=time.monotonic(),idle_budget=args.phase_timeout)))
                trial=execute_trial(args,output/name,group,repeat,rate);trial['directory']=name;trials.append(trial)
                write_control(output/'results.json',json.dumps(dict(config=vars(args),trials=trials),indent=2)+'\n')
    return trials


def report(output):
    output=Path(output);data=json.loads((output/'results.json').read_text());trials=data['trials'];config=data['config']
    supervisor=json.loads((output/'supervisor.json').read_text()) if (output/'supervisor.json').exists() else dict(reason='missing supervisor')
    complete=len(trials)==len(config['rates'].split(','))*config['repeats']*2
    valid=complete and all(t['valid'] for t in trials) and not any(supervisor.get(k) for k in ('returncode','reason','cleanup_errors'))
    # Pair per rate; otherwise repeat IDs collide across the sweep.
    comparisons={str(rate):paired_comparisons([t for t in trials if t['rate']==rate],'D','B') for rate in sorted({t['rate'] for t in trials})}
    summary=dict(status='VALIDATION_PASS' if valid else 'INVALID_OR_FAILED',performance_acceptance='NOT_EVALUATED',
                 business=config['business'],comparisons=comparisons,capacity=tested_capacity(trials,config.get('slo_p99_ms'),config['repeats']),
                 valid_trials=sum(t['valid'] for t in trials),total_trials=len(trials),supervisor=supervisor)
    (output/'analysis.json').write_text(json.dumps(summary,indent=2)+'\n')
    lines=['# Native business performance','', 'Status: '+summary['status'],'','Business: '+config['business'],
           '','B/D both run Agent with feature disabled and an identical persistent helper. D adds successful production collector snapshots.',
           'Native latency aggregates retain tool-specific semantics; no synthetic per-request data.',
           'etcd random PUT payload values are not known-input checked. Deterministic CRUD prefix is checked separately.',
           'Kafka producer ack latency differs from consumer throughput/lag. wrk2 bodies are checked for every completed response.',
           'Fixed business data/retention and offered load in B/D. No trigger or pressure change is used to request snapshots. Daemon threshold/burst detection is excluded.',
           'Helper self plus reaped-child CPU is separate from Agent CPU. Sampled simultaneous tree RSS is a lower-bound peak; RSS sums shared pages.',
           'Tool startup and consecutive PUT/GET/consumer stages remain in raw process timestamps; aggregates are not apportioned to invented subwindows.',
           'Performance acceptance: NOT_EVALUATED. Capacity is the highest TESTED rate satisfying the configured SLO in every B/D repeat.',
           '', '| Trial | Valid | Capture records | Trigger native metrics | Errors |','|---|---|---:|---|---|']
    for t in trials:lines.append('| %s | %s | %d | %s | %s |'%(t['directory'],t['valid'],len(t.get('captures',[])),json.dumps(t.get('windows',{}).get('trigger',{}).get('native',{}).get('metrics',{})),'; '.join(t['errors']).replace('|','/')))
    lines+=['','## Paired D−B results','', '```json',json.dumps(comparisons,indent=2),'```','', '## Tested capacity','', '```json',json.dumps(summary['capacity'],indent=2),'```']
    (output/'REPORT.md').write_text('\n'.join(lines)+'\n');return summary
