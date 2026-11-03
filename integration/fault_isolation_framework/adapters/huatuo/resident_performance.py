# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Controlled resident-KV A/B/C snapshot pressure experiments."""
import hashlib
import json
import math
import os
import random
import threading
import time
from pathlib import Path
from ...core.evidence import EvidenceStore
from ...core.performance import arrival_errors, paired_comparisons, summarize_requests, distribution
from ...core.util import require, run, wait_for, write_control
from ...environments.docker import DockerEnvironment
from ...environments.linux import ManagedProcess, identity
from ...environments.performance import PerformanceSampler, resource_metrics, cgroup_memory
from ...environments.remote_load import RemoteLoad
from ...environments.supervisor import own
from ...workloads.resident_kv import ResidentKV, freeze_plan, replay_fill, canonical_fill_recipe, replay_candidate
from ...workloads.resident_protocol import operation
from .agent import verify_build
from .discovery import Discovery, parse_timestamp
from .memsnapshot.adapter import MemsnapshotAdapter
from .performance import PerformanceAdapter


class ScopedProcess(ManagedProcess):
    def __init__(self,scope):super().__init__();self.scope=scope
    def start(self,command,logfile,env):
        # Move before exec so startup allocations are charged to this scope.
        wrapper=['/bin/sh','-c','printf "%s\\n" "$$" > "$1/cgroup.procs"; shift; exec "$@"','resident-scope',str(self.scope)]
        return super().start(wrapper+list(command),logfile,env)


def canonical_window_rows(rows,start,qps,begin,end):
    return [row for row in rows if begin<=start+row['ordinal']/qps<end]


def helper_resources(rows,begin,end):
    normalized=[]
    for row in rows:
        procs={}
        for key,value in row['processes'].items():
            if key=='snapshot-helper':procs['agent']=value
            elif key.startswith('snapshot-child-'):procs['child-'+key[len('snapshot-child-'):]]=value
        normalized.append(dict(time=row['time'],errors=row['errors'],processes=procs))
    result=resource_metrics(normalized,begin,end)
    result['helper_self_cpu_seconds']=result.pop('agent_self_cpu_seconds')
    result['cpu_accounting']=result['cpu_accounting'].replace('Agent','Snapshot helper')
    return result


def memory_window(rows,begin,end,target_id):
    chosen=[row for row in rows if begin<=row['time']<end]
    if not chosen:raise ValueError('no cgroup samples in measured window')
    def stats(samples):
        first,last=samples[0],samples[-1]
        result=dict(sampled_peak_bytes=max(s['current_bytes'] for s in samples),baseline_bytes=first['current_bytes'],
                    peak_above_baseline_bytes=max(s['current_bytes'] for s in samples)-first['current_bytes'],
                    lifetime_peak_bytes=last['lifetime_peak_bytes'],lifetime_high_water_increase_bytes=max(0,last['lifetime_peak_bytes']-first['lifetime_peak_bytes']) if first['lifetime_peak_bytes'] is not None and last['lifetime_peak_bytes'] is not None else None,begin=first,end=last)
        for name in ('oom_kills','allocation_failures'):
            result[name+'_delta']=last[name]-first[name] if first[name] is not None and last[name] is not None else None
        return result
    result=dict(sample_boundary=dict(first=chosen[0]['time'],last=chosen[-1]['time'],start_lag_seconds=chosen[0]['time']-begin,end_lag_seconds=end-chosen[-1]['time']),
                business=stats([row['business_memory'][target_id] for row in chosen]),scopes={})
    for name in chosen[0].get('memory_scopes',{}):result['scopes'][name]=stats([row['memory_scopes'][name] for row in chosen if name in row.get('memory_scopes',{})])
    # Agent/helper leaves and worker slots are disjoint. The observer/VM parent
    # can contain these scopes and is never added to this simultaneous sum.
    collector_values=[sum(value['current_bytes'] for key,value in row.get('memory_scopes',{}).items() if key in ('agent','helper') or key.startswith('worker-')) for row in chosen]
    result['collector_simultaneous_sampled_peak_bytes']=max(collector_values)
    result['collector_peak_above_baseline_bytes']=max(collector_values)-collector_values[0]
    return result


class ResidentAdapter(PerformanceAdapter):
    def prepare(self,group):
        verify_build(self.build);self.group=group;self.extra_processes=[];self.redis=None;self.targets=[];self.snapshot_helper=None
        self.environment=DockerEnvironment(self.out);self.environment.build_image(self.build/'business-go')
        self.discovery=Discovery(self.environment.driver);self.discovery.start();self.server,self.api=self.discovery.server,self.environment.api
        self.kv=ResidentKV(self,self.a.resident_language);self.targets=[self.kv.start()];self.measurement_targets=self.targets;self.pressured=self.targets;self.driver=None
        self.discovery.register(self.targets[0]);self.memory_scopes={};self.scope_directories=[]
        memory_path=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if 'memory' in line.split(':')[1].split(','))
        self.memory_scopes['observer_parent']=self.environment.mount/memory_path.lstrip('/')
        root=self.environment.mount/('huatuo-resident-cost-'+self.out.name)
        root.mkdir();self.scope_directories.append(root)
        for name in ['agent']+(['helper'] if group!='A' else []):
            scope=root/name;scope.mkdir();(scope/'memory.limit_in_bytes').write_text(str(512<<20));self.memory_scopes[name]=scope;self.scope_directories.append(scope)
        self.process=ScopedProcess(self.memory_scopes['agent'])
        self.helper_process=None
        environment=dict(kernel=os.uname().release,language=self.a.resident_language,cpus=self.a.business_cpus,memory_limit_mib=self.a.memory_limit_mib,target={k:(str(v) if isinstance(v,Path) else v) for k,v in self.targets[0].items()},agent_build=json.loads((self.build/'build.json').read_text()),lifecycle='Shipping Agent initializes its own manager in A/B/C; B adds test helper plus second manager; C adds controlled snapshots',business_objects='retained Record/nested containers, mixed1KiB/64KiB real payloads, bounded64slot churn; no external filler')
        (self.out/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
        for scope in reversed(self.scope_directories):own('cgroup',str(scope))

    def start_agent(self,**kwargs):return MemsnapshotAdapter.start_agent(self,plain=True,disabled=True)

    def start_helper(self):
        if self.group=='A':return
        self.snapshot_control=self.out/'snapshot-command.json';write_control(self.snapshot_control,'{"id":0}')
        worker_root=self.environment.mount/('huatuo-memsnapshot-worker-resident-'+self.out.name)
        self.worker_root=worker_root
        output=self.out/'snapshot-output';output.mkdir()
        command=[self.a.snapshot_helper,'--control',str(self.snapshot_control),'--worker',str(self.build/'huatuo-memsnapshot-worker'),'--cgroup-root',str(worker_root),'--timeout','%ds'%self.a.capture_timeout,'--top-k',str(self.a.top_k),'--output-dir',str(output)]
        self.helper_process=ScopedProcess(self.memory_scopes['helper']);self.snapshot_helper=self.helper_process.start(command,self.out/'snapshot-helper.jsonl',dict(os.environ))
        wait_for('resident snapshot helper ready',lambda:any(json.loads(line).get('ready') for line in (self.out/'snapshot-helper.jsonl').read_text().splitlines() if line.startswith('{')),timeout=20)
        for slot in sorted(worker_root.iterdir()):
            if slot.is_dir():self.memory_scopes['worker-'+slot.name]=slot;own('cgroup',str(slot))
        own('cgroup',str(worker_root))
        for scope in reversed(self.scope_directories):own('cgroup',str(scope))

    def cleanup(self):
        errors=[]
        for operation in [lambda:self.stop_agent(kill=True),lambda:self.helper_process.stop() if self.helper_process else None]:
            try:operation()
            except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'worker_root') and self.worker_root.exists():
            try:
                for child in self.worker_root.iterdir():
                    if child.is_dir():child.rmdir()
                self.worker_root.rmdir()
            except Exception as exc:errors.append(repr(exc))
        for scope in reversed(getattr(self,'scope_directories',[])):
            try:scope.rmdir()
            except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'environment'):
            for target in self.targets:
                log=run('docker','logs',target['cid'],check=False);(self.out/'business.log').write_text(log.stdout+log.stderr)
            try:self.environment.cleanup([])
            except Exception as exc:errors.append(repr(exc))
        if hasattr(self,'discovery'):self.discovery.cleanup()
        require(not errors,'resident cleanup failed: '+repr(errors))


def read_capture_output(path,final=False):
    path=Path(path);rows=[];errors=[];pending=0
    if not path.exists():return dict(rows=rows,errors=errors,pending_tail_bytes=pending)
    for number,line in enumerate(path.read_bytes().splitlines(keepends=True),1):
        stripped=line.lstrip()
        if not stripped.startswith(b'{'):continue
        if not line.endswith(b'\n'):
            pending=len(line)
            if final:errors.append('unterminated helper JSON line %d (%d bytes); raw tail retained'%(number,pending))
            # The writer can be between writes. Poll only complete records.
            continue
        try:
            value=json.loads(line)
            if not isinstance(value,dict):raise ValueError('helper row must be an object')
            if 'id' in value:rows.append(value)
            elif value.get('ready') is not True:errors.append('unexpected helper JSON record at line %d'%number)
        except (ValueError,UnicodeDecodeError) as exc:
            errors.append('malformed helper JSON at line %d: %s; raw line retained'%(number,str(exc)))
    return dict(rows=rows,errors=errors,pending_tail_bytes=pending)


def capture_rows(owner):
    parsed=read_capture_output(owner.out/'snapshot-helper.jsonl')
    if parsed['errors']:raise ValueError('; '.join(parsed['errors']))
    return parsed['rows']


def finalize_trial(owner,outcome,evidence):
    # Cleanup stops the writer before strict parsing. Neither parse nor cleanup
    # failures may skip the other operation or the failed-trial summary.
    try:owner.cleanup()
    except Exception as exc:outcome['errors'].append('resident cleanup: '+repr(exc))
    try:
        parsed=read_capture_output(owner.out/'snapshot-helper.jsonl',final=True)
        outcome['captures']=parsed['rows']
        outcome['capture_output_protocol']={k:v for k,v in parsed.items() if k!='rows'}
        outcome['errors']+=parsed['errors']
    except Exception as exc:outcome['errors'].append('helper output read: '+repr(exc))
    outcome['valid']=outcome['valid'] and not outcome['errors']
    evidence.save(outcome)


def validate_captures(captures,target,expected):
    if len(captures)!=expected:return ['snapshot count differs from requested count']
    errors=[]
    for capture in captures:
        result=capture.get('result') or {};snapshot=result.get('Snapshot') or {};language=result.get('Language')
        if capture['pid']!=target['pid'] or result.get('Process',{}).get('start_time_ticks')!=target['identity'][1]:errors.append('capture process identity mismatch')
        if language!=target['language']:errors.append('capture provider differs from target runtime')
        if capture.get('error') or capture.get('output_error') or not snapshot.get('entries') or snapshot.get('status') not in (('complete',) if language=='go' else ('complete','partial')):errors.append('snapshot failed/unavailable/empty; retain raw result without cheap-success scoring')
    return errors


def baseline_replay(args,directory,plan):
    evidence=EvidenceStore(directory);owner=ResidentAdapter(args,evidence);sampler=None;remote=None;thread=None;stop=threading.Event()
    outcome=dict(valid=False,errors=[],captures=[],pressure_samples=[],directory=str(directory))
    try:
        available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
        require(available>(args.memory_limit_mib<<20)+(768<<20),'fresh replay lacks VM memory headroom')
        owner.prepare('A');replay_fill(plan,owner.kv.fill);owner.start_agent()
        outcome['before']=owner.kv.verify();sampler=PerformanceSampler(owner,owner.out/'resources.jsonl',args.sample_interval);sampler.start()
        remote=RemoteLoad(args.load_controller_url,args.load_token_file,owner.out,args.max_clock_error);remote.calibrate()
        prefix=args.warmup+args.baseline;duration=prefix+2;start=time.monotonic()+3;observation_errors=[]
        def observe():
            try:
                if stop.wait(max(0,start+prefix-time.monotonic())):return
                for _ in range(5):
                    outcome['pressure_samples'].append(owner.kv.memory()['current_bytes'])
                    if stop.wait(.25):return
            except Exception as exc:observation_errors.append(repr(exc))
        thread=threading.Thread(target=observe,daemon=True);thread.start()
        target=dict(id=owner.targets[0]['id'],kind='resident',url='http://%s:%d'%(args.load_target_host,args.load_target_base_port),seed=args.seed,records=plan['records'])
        rows=remote.run([target],args.qps,duration,args.workers,args.pending,None,start)
        thread.join(5);require(not thread.is_alive(),'fresh replay pressure observer did not finish')
        require(not observation_errors,'fresh replay observation failed: '+repr(observation_errors))
        require(not arrival_errors(rows,{target['id']},args.qps,duration,start),'fresh replay arrival protocol invalid')
        load=summarize_requests(rows,math.ceil(args.qps*duration),duration,args.max_dispatch_lag)
        require(load['valid_load'] and not load['errors'],'fresh replay offered load invalid')
        expected={kind:sum(operation(i,args.seed,plan['records'])[0]==kind for i in range(math.ceil(args.qps*duration))) for kind in ('GET','SET','DELETE')}
        outcome.update(load=load,after=owner.kv.verify(expected),pre_capture_recipe=dict(warmup=args.warmup,baseline=args.baseline,qps=args.qps,seed=args.seed,probe_samples=5,probe_interval=.25,snapshots=0))
        require(len(outcome['pressure_samples'])==5,'fresh replay pressure samples incomplete')
        outcome['valid']=True
    except Exception as exc:outcome['errors'].append(repr(exc))
    finally:
        stop.set()
        if remote:
            try:remote.cancel()
            except Exception as exc:outcome['errors'].append(repr(exc))
        if thread and thread.is_alive():thread.join(5)
        if sampler and not sampler.stream.closed:
            try:sampler.close()
            except Exception as exc:outcome['errors'].append(repr(exc))
        finalize_trial(owner,outcome,evidence)
    return outcome


def bounded_replay_calibration(plan,replay,record_round):
    candidate=dict(plan,frozen=False)
    for round_index in range(3):
        candidate['fill_recipe']=canonical_fill_recipe(candidate['records'])
        replicas=[replay(candidate,round_index,index) for index in range(2)]
        decision=replay_candidate(candidate['records'],candidate['limit_bytes'],candidate['requested_percent'],candidate['tolerance_percent'],replicas)
        record_round(dict(round=round_index,records=candidate['records'],fill_recipe=candidate['fill_recipe'],replicas=replicas,decision=decision))
        if decision['status']=='FROZEN':
            candidate.update(frozen=True,observed_percent=decision['observed_percent'],preflight_replicas=2,preflight_rounds=round_index+1)
            return candidate
        if decision['status']!='REFINE':raise RuntimeError('resident replay calibration '+decision['status']+': '+decision['reason'])
        candidate['records']=decision['records']
    raise RuntimeError('resident replay calibration UNREACHABLE after three predetermined candidate rounds')


def calibrate(args,output,percent):
    available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
    require(available>(args.memory_limit_mib<<20)+(768<<20),'resident business plus Agent/worker preflight exceeds VM available-memory headroom')
    evidence=EvidenceStore(output);owner=ResidentAdapter(args,evidence);rounds=[]
    try:
        owner.prepare('A');plan=owner.kv.calibrate(percent);proof=owner.kv.verify();plan['frozen']=False
        (evidence.output/'provisional-plan.json').write_text(json.dumps(dict(plan=plan,proof=proof),indent=2)+'\n')
    finally:owner.cleanup()
    def replay(candidate,round_index,index):return baseline_replay(args,evidence.output/('replay-round-%d-replica-%d'%(round_index,index)),candidate)
    def record(row):
        rounds.append(row);(evidence.output/'replay-calibration.json').write_text(json.dumps(rounds,indent=2)+'\n')
    try:
        final=bounded_replay_calibration(plan,replay,record)
        (evidence.output/'plan.json').write_text(json.dumps(dict(plan=final,provisional_proof=proof,replay_evidence='replay-calibration.json'),indent=2)+'\n')
        return final
    except Exception as exc:
        (evidence.output/'calibration-summary.json').write_text(json.dumps(dict(status='INVALID_OR_UNREACHABLE',reason=repr(exc),attempts='replay-calibration.json'),indent=2)+'\n')
        raise


def execute_trial(args,directory,group,repeat,percent,plan):
    evidence=EvidenceStore(directory);owner=ResidentAdapter(args,evidence);sampler=None;remote=None;thread=None;stop=threading.Event()
    outcome=dict(group=group,repeat=repeat,pressure_percent=percent,valid=False,errors=[],metrics={},captures=[])
    commands=[];capture_errors=[]
    try:
        owner.prepare(group);replay_fill(plan,owner.kv.fill);owner.start_agent();owner.start_helper()
        before=owner.kv.verify();require(before['stats']['records']==plan['records'],'frozen resident record count differs')
        sampler=PerformanceSampler(owner,owner.out/'resources.jsonl',args.sample_interval);sampler.start()
        remote=RemoteLoad(args.load_controller_url,args.load_token_file,owner.out,args.max_clock_error);remote.calibrate()
        duration=args.warmup+args.baseline+args.hold+args.recovery;start=time.monotonic()+3
        anchor=dict(monotonic=time.monotonic(),epoch=time.time());outcome["local_clock_anchor"]=anchor
        def capture():
            try:
                due=start+args.warmup+args.baseline
                if stop.wait(max(0,due-time.monotonic())):return
                # No FILL or memory tuning is permitted after this boundary.
                samples=[owner.kv.memory()['current_bytes'] for _ in range(3)]
                outcome['frozen_pressure']=freeze_plan(plan['records'],plan['limit_bytes'],percent,samples,args.pressure_tolerance)
                if group=='C':
                    for index in range(args.snapshot_count):
                        if stop.wait(max(0,due+1+index*args.snapshot_interval-time.monotonic())):return
                        target=owner.targets[0];commands.append(dict(id=index+1,time=time.monotonic(),epoch=time.time(),pid=target['pid']))
                        write_control(owner.snapshot_control,json.dumps(dict(id=index+1,pid=target['pid'],start_ticks=target['identity'][1])))
                        wait_for('resident controlled snapshot result',lambda:len(capture_rows(owner))>=index+1,timeout=args.capture_timeout+8)
            except Exception as exc:capture_errors.append(repr(exc))
        thread=threading.Thread(target=capture,daemon=True);thread.start()
        target=dict(id=owner.targets[0]['id'],kind='resident',url='http://%s:%d'%(args.load_target_host,args.load_target_base_port),seed=args.seed,records=plan['records'])
        rows=remote.run([target],args.qps,duration,args.workers,args.pending,None,start)
        thread.join(args.capture_timeout+10);require(not thread.is_alive(),'resident capture schedule did not stop')
        sampler.close()
        require(not arrival_errors(rows,{target['id']},args.qps,duration,start),'resident fixed-arrival coverage invalid')
        expected={kind:sum(operation(i,args.seed,plan['records'])[0]==kind for i in range(math.ceil(args.qps*duration))) for kind in ('GET','SET','DELETE')}
        after=owner.kv.verify(expected);require(identity(owner.targets[0]['pid'])==owner.targets[0]['identity'],'resident target lifetime changed')
        outcome.update(before=before,after=after,commands=commands,plan=plan,captures=capture_rows(owner),windows={})
        for name,begin,end in [('baseline',start+args.warmup,start+args.warmup+args.baseline),('capture',start+args.warmup+args.baseline,start+args.warmup+args.baseline+args.hold),('recovery',start+duration-args.recovery,start+duration)]:
            chosen=canonical_window_rows(rows,start,args.qps,begin,end);expected_n=sum(begin<=start+i/args.qps<end for i in range(math.ceil(duration*args.qps)))
            load=summarize_requests(chosen,expected_n,end-begin,args.max_dispatch_lag);resources=resource_metrics(sampler.rows,begin,end);helper=helper_resources(sampler.rows,begin,end)
            memory=memory_window(sampler.rows,begin,end,target['id']);scopes=memory['scopes']
            memory_samples=[int(r['cgroups'][target['id']]['memory.usage_in_bytes']) for r in sampler.rows if begin<=r['time']<end and target['id'] in r.get('cgroups',{})]
            pressure_band=dict(sampled_min_percent=min(memory_samples,default=0)*100/plan['limit_bytes'],sampled_max_percent=max(memory_samples,default=0)*100/plan['limit_bytes'])
            outcome['windows'][name]=dict(business_pressure=pressure_band,begin=begin,end=end,load=load,agent_business_resources=resources,snapshot_resources=helper,memory_scopes=scopes,memory=memory)
            prefix=name+'.';outcome['metrics'].update({prefix+'rps':load['success_rps'],prefix+'p99_ms':load['latency_ms']['p99'],prefix+'p999_ms':load['latency_ms']['p999'],prefix+'agent_cpu_seconds':resources['cpu_seconds'],prefix+'snapshot_cpu_seconds':helper['cpu_seconds'],prefix+'snapshot_sampled_rss_peak_bytes':helper['sampled_agent_tree_rss_peak_bytes']})
            outcome['metrics'].update({prefix+'business_memory_sampled_peak_bytes':memory['business']['sampled_peak_bytes'],prefix+'business_memory_peak_above_baseline_bytes':memory['business']['peak_above_baseline_bytes'],prefix+'collector_memory_simultaneous_sampled_peak_bytes':memory['collector_simultaneous_sampled_peak_bytes'],prefix+'collector_memory_peak_above_baseline_bytes':memory['collector_peak_above_baseline_bytes']})
            for scope in ['agent','helper','worker-0','worker-1']:
                stats=memory['scopes'].get(scope)
                outcome['metrics'][prefix+scope+'_memory_sampled_peak_bytes']=stats['sampled_peak_bytes'] if stats else 0
                outcome['metrics'][prefix+scope+'_peak_above_baseline_bytes']=stats['peak_above_baseline_bytes'] if stats else 0
                outcome['metrics'][prefix+scope+'_lifetime_high_water_increase_bytes']=stats['lifetime_high_water_increase_bytes'] if stats else 0
                for counter in ('oom_kills_delta','allocation_failures_delta'):
                    outcome['metrics'][prefix+scope+'_'+counter]=stats[counter] if stats else 0
            for counter in ('oom_kills_delta','allocation_failures_delta'):
                outcome['metrics'][prefix+'business_'+counter]=memory['business'][counter]
            require(load['valid_load'] and not load['errors'] and not load['missing'],'resident business errors or invalid offered load')
            require(not resources['errors'],'resident resource observations incomplete')
        outcome['active_capture_windows']=[]
        clock_meta=json.loads((owner.out/'remote-load.json').read_text())
        uncertainty=clock_meta['clock_before']['rtt']/2+clock_meta['clock_after']['rtt']/2+abs(clock_meta['clock_after']['offset']-clock_meta['clock_before']['offset'])
        for capture in outcome['captures']:
            begin=parse_timestamp(capture['started']).timestamp()-anchor['epoch']+anchor['monotonic']
            end=parse_timestamp(capture['ended']).timestamp()-anchor['epoch']+anchor['monotonic']
            definite=[r for r in rows if begin+uncertainty<=r['scheduled']<end-uncertainty]
            possible=[r for r in rows if begin-uncertainty<=r['scheduled']<end+uncertainty]
            inflight=[r for r in rows if r.get('sent') is not None and r['sent']-uncertainty<=end and r['ended']+uncertainty>=begin]
            active=dict(id=capture['id'],begin=begin,end=end,duration_ms=(end-begin)*1000,clock_uncertainty_ms=uncertainty*1000,
                        resolution_limited=2*uncertainty>=end-begin,definite_scheduled_count=len(definite),possible_scheduled_ordinals=[r['ordinal'] for r in possible],possible_inflight_ordinals=[r['ordinal'] for r in inflight],
                        definite_arrival_latency_ms=distribution([(r['ended']-r['scheduled'])*1000 for r in definite if r['ok']]),
                        possible_inflight_errors=sum(not r['ok'] for r in inflight),scope='actual collector + bounded serialization/disk interval, distinct from 10s phase window; membership bounded by remote clock uncertainty')
            outcome['active_capture_windows'].append(active)
            (owner.out/('active-capture-%d-requests.jsonl'%capture['id'])).write_text(''.join(json.dumps(r)+'\n' for r in inflight))
        outcome['metrics'].update(snapshot_wall_total_ms=sum(c['wall_ms'] for c in outcome['captures']),snapshot_output_bytes=sum(c.get('output_bytes',0) for c in outcome['captures']))
        outcome['errors']+=capture_errors+validate_captures(outcome['captures'],owner.targets[0],args.snapshot_count if group=='C' else 0)
        manifest=dict(route='test-only persistent collector.Snapshot + unchanged production WorkerManager/worker; bounded result JSON write+fsync',
                      lifecycle='A: Agent only; B: Agent plus idle helper/manager; C: same B plus captures. A already initializes the shipping Agent manager; B-A includes a second manager and test scaffold startup/residency, not a production toggle.',
                      agent_feature_disabled_in_all_groups=True,kernel=os.uname().release,language=args.resident_language,source_build=json.loads((Path(args.build)/'build.json').read_text()),
                      business_sha256=hashlib.sha256(Path(args.resident_go).read_bytes()).hexdigest() if args.resident_language=='go' else hashlib.sha256((Path(__file__).parents[2]/'workloads/resident'/('ResidentKV.java' if args.resident_language=='java' else 'python_kv.py')).read_bytes()).hexdigest(),
                      helper_sha256=hashlib.sha256(Path(args.snapshot_helper).read_bytes()).hexdigest(),memory_accounting='business cgroup plus distinct helper, Agent and worker-slot scopes; raw VM/parent vmstat/PSI in resources; max_usage is lifetime, sampled peaks are window-scoped; failcnt is not OOM kills')
        manifest.update(json.loads((owner.out/'environment.json').read_text()))
        (owner.out/'environment.json').write_text(json.dumps(manifest,indent=2)+'\n')
        outcome['valid']=not outcome['errors']
    except Exception as exc:outcome['errors'].append(repr(exc))
    finally:
        stop.set()
        if remote:
            try:remote.cancel()
            except Exception as exc:outcome['errors'].append(repr(exc))
        if thread and thread.is_alive():thread.join(args.capture_timeout+10)
        if sampler and not sampler.stream.closed:
            try:sampler.close()
            except Exception as exc:outcome['errors'].append(repr(exc))
        finalize_trial(owner,outcome,evidence)
    return outcome


def campaign(args,output):
    output=Path(output);trials=[];rng=random.Random(args.seed)
    for percent in map(int,args.pressure_levels.split(',')):
        if percent==95:
            preflight=[t for t in trials if t['pressure_percent']==90]
            require(args.allow_95 and len(preflight)==args.repeats*3 and all(t['valid'] for t in preflight),'95% bounded preflight requires valid90% A/B/C trials')
            available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
            require(available>(args.memory_limit_mib<<20)+(768<<20),'95% preflight lacks VM headroom for business plus observer/worker')
        plan=calibrate(args,output/('calibration-%d'%percent),percent)
        for repeat in range(args.repeats):
            groups=['A','B','C'];rng.shuffle(groups)
            for group in groups:
                name='pressure-%d-repeat-%02d-%s'%(percent,repeat,group)
                write_control(output/'progress.json',json.dumps(dict(phase=name,started=time.monotonic(),idle_budget=args.phase_timeout)))
                trial=execute_trial(args,output/name,group,repeat,percent,plan);trial['directory']=name;trials.append(trial)
                write_control(output/'results.json',json.dumps(dict(config=vars(args),trials=trials),indent=2)+'\n')
    return trials


def report(output):
    output=Path(output);data=json.loads((output/'results.json').read_text());trials=data['trials'];config=data['config']
    supervisor=json.loads((output/'supervisor.json').read_text()) if (output/'supervisor.json').exists() else dict(reason='missing supervisor')
    complete=len(trials)==len(config['pressure_levels'].split(','))*config['repeats']*3
    valid=complete and all(t['valid'] for t in trials) and not any(supervisor.get(k) for k in ('returncode','reason','cleanup_errors'))
    comparisons={}
    for level in sorted({t['pressure_percent'] for t in trials}):
        subset=[t for t in trials if t['pressure_percent']==level]
        comparisons[str(level)]=[paired_comparisons(subset,a,b) for a,b in [('B','A'),('C','B'),('C','A')]]

    result=dict(status='VALIDATION_PASS' if valid else 'INVALID_OR_FAILED',performance_acceptance='NOT_EVALUATED',comparisons=comparisons,valid_trials=sum(t['valid'] for t in trials),total_trials=len(trials),supervisor=supervisor)
    (output/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    text=['# Resident KV snapshot pressure validation','','Status: '+result['status'],'','A: identical Agent, no explicit test helper. B: idle helper/WorkerManager. C: B plus production snapshots and bounded JSON write+fsync.',
          'B−A includes test scaffold residency; this is not a production feature toggle. C−B measures snapshot work under the same frozen retained dataset and seeded offered load.',
          'Pressure is actual business cgroup usage/limit. No fill adjustment during capture. Runtime GC remains enabled. Failed/empty captures are excluded from valid paired cost conclusions.',
          'Short correctness validation is not performance acceptance. P99 needs 1000 successful samples/window, P999 needs 10000; these minima still give limited tail precision. Unsupported counters remain null; failcnt is not OOM kills.',
          'The capture phase is a fixed hold window, not a provider-only latency interval. Actual capture intervals, aligned raw request ordinals, overlap sample counts and cross-VM clock uncertainty are retained separately; active-window tails remain null when sparse. No-effect claims are limited by that detection resolution.',
          '', '| Trial | Valid | Capture status | Errors |','|---|---|---|---|']
    for trial in trials:
        statuses=[(c.get('result') or {}).get('Snapshot',{}).get('status') for c in trial['captures']]
        text.append('| %s | %s | %s | %s |'%(trial['directory'],trial['valid'],statuses,'; '.join(trial['errors']).replace('|','/')))
    text+=['','## Paired deltas','','```json',json.dumps(comparisons,indent=2),'```']
    (output/'REPORT.md').write_text('\n'.join(text)+'\n');return result
