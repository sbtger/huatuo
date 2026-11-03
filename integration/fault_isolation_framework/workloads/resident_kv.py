# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real resident objects, cgroup pressure calibration and immutable fill plans."""
import hashlib
import json
import os
import re
import time
import urllib.request
from pathlib import Path
from ..core.util import run, require, wait_for
from ..environments.performance import cgroup_memory
from .resident_protocol import dataset_digest


def rpc(url,path,post=False):
    request=urllib.request.Request(url+path,data=b'' if post else None)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=120) as response:return json.loads(response.read(1<<20))



def freeze_plan(records,limit,percent,samples,tolerance=2):
    if records<1024 or not samples or max(samples)-min(samples)>limit*.015 or any(abs(value*100/limit-percent)>tolerance for value in samples):
        raise ValueError('resident object plateau is unstable or outside pressure band')
    return dict(records=records,limit_bytes=limit,requested_percent=percent,observed_percent=[value*100/limit for value in samples],frozen=True,tolerance_percent=tolerance)


def replay_fill(plan,fill,sleep=time.sleep):
    recipe=plan['fill_recipe']
    if not recipe or recipe[-1]['records']!=plan['records']:raise ValueError('frozen fill recipe differs from retained count')
    for step in recipe:
        fill(step['records']);sleep(step['settle_seconds'])
    for _ in range(plan.get('plateau_samples',5)):sleep(plan.get('plateau_interval',.25))


class ResidentKV:
    def __init__(self,owner,language):
        self.owner=owner;self.a=owner.a;self.language=language;self.root=owner.out/'business';self.root.mkdir()
        self.url='http://127.0.0.1:%d'%self.a.service_port_base

    def start(self):
        a=self.a;source=Path(__file__).parent/'resident'
        args=['--network','host','--memory','%dm'%a.memory_limit_mib,'--memory-swap','%dm'%a.memory_limit_mib,'--cpus',str(a.business_cpus),'-e','HUATUO_TEST_PORT='+str(a.service_port_base),'-v',str(source)+':/resident:ro']
        for root in ('/usr','/lib','/lib64','/bin','/etc'):args+=['-v',root+':'+root+':ro']
        if self.language=='go':
            args+=['-e','GOMEMLIMIT=%dMiB'%int(a.memory_limit_mib*.9),'-v',a.resident_go+':/resident-go:ro'];command=['/resident-go']
        elif self.language=='java':
            run(a.java_home+'/bin/javac','-d',str(self.root/'classes'),str(source/'ResidentKV.java'))
            args+=['-v',str(self.root/'classes')+':/classes:ro','-v',str(self.root)+':/resident-work'];command=[a.java_home+'/bin/java','-Xlog:gc:file=/resident-work/gc.log:time,uptime,level,tags:filecount=2,filesize=5M','-Xms64m','-Xmx%dm'%int(a.memory_limit_mib*.92-64),'-XX:+UseG1GC','-cp','/classes','ResidentKV']
        else:command=[a.python,'/resident/python_kv.py']
        target=self.owner.environment.launch(args,command)
        target.update(id='resident-'+self.language,role='target',language=self.language,url=self.url)
        self.target=target
        self.initial_memory=cgroup_memory(target['cgroup'])
        return target

    def fill(self,count):return rpc(self.url,'/fill?records=%d'%count,True)
    def stats(self):return rpc(self.url,'/stats')
    def memory(self):return cgroup_memory(self.target['cgroup'])

    def calibrate(self,percent):
        limit=self.a.memory_limit_mib<<20;count=1024;trace=[]
        for iteration in range(40):
            stats=self.fill(count);time.sleep(.5);memory=self.memory();usage=memory['current_bytes']
            trace.append(dict(iteration=iteration,records=count,memory=memory,stats=stats,epoch=time.time()))
            (self.owner.out/'calibration.json').write_text(json.dumps(trace,indent=2)+'\n')
            require(memory['oom_kills']==self.initial_memory['oom_kills'],'calibration OOM kill observed')
            ratio=usage*100/limit
            if percent-self.a.pressure_tolerance<=ratio<=percent+self.a.pressure_tolerance:
                values=[]
                for _ in range(5):time.sleep(.25);values.append(self.memory()['current_bytes'])
                plan=freeze_plan(count,limit,percent,values,self.a.pressure_tolerance)
                plan.update(fill_recipe=[dict(records=row['records'],settle_seconds=.5) for row in trace],plateau_samples=5,plateau_interval=.25,seed=self.a.seed,language=self.language,trace='calibration.json',object_shape='90% 1KiB / 10% 64KiB values, Record and nested containers; 64 churn slots')
                return plan
            require(ratio<percent+self.a.pressure_tolerance,'calibration overshot pressure band; preserve and use a new configuration')
            gap=limit*percent/100-usage
            estimate=max(8192,usage/count)
            count+=max(64,min(20000,int(gap/estimate*.55)))
        raise RuntimeError('resident pressure calibration did not converge')

    def verify(self,expected_counts=None):
        stats=self.stats();memory=self.memory()
        require(memory['oom_kills']==self.initial_memory['oom_kills'],'business OOM kill counter changed')
        require(memory['allocation_failures']==self.initial_memory['allocation_failures'],'business allocation failure counter changed (not an OOM-kill count)')
        require(stats['dataset_sha256']==dataset_digest(stats['records']),'resident dataset digest differs from independent payload oracle')
        if self.language=='go':require(stats['profile_rate']==524288 and stats['published_profile_records']>0,'Go normal-rate published profile metadata unavailable')
        if self.language=='python':require(stats['gc']['enabled'] and stats['tracked_samples'] and all(all(row.values()) for row in stats['tracked_samples']),'Python Record/nested samples are not GC tracked')
        if expected_counts is not None:require(stats['operations']==expected_counts,'KV acknowledged operation counters differ from seeded request plan')
        proof=dict(stats=stats,memory=memory,initial_memory=self.initial_memory)
        if self.language=='java':
            logs=list(self.root.glob('gc.log*'));pauses=[]
            for path in logs:
                for line in path.read_text().splitlines():
                    match=re.search(r'Pause.* ([0-9.]+)ms$',line)
                    if match:pauses.append(float(match[1]))
            proof['gc_log']=dict(pause_entries=len(pauses),pause_total_ms=sum(pauses),gc_cpu_seconds=None,scope='bounded HotSpot GC log pause wall durations, not GC CPU',files={p.name:dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in logs})
        return proof


def canonical_fill_recipe(records):
    if not 1024<=records<=1000000:raise ValueError('candidate record count outside object budget')
    counts=[1024]
    while counts[-1]<records:counts.append(min(records,counts[-1]+20000))
    return [dict(records=count,settle_seconds=.5) for count in counts]


def replay_candidate(records,limit,percent,tolerance,replicas):
    """Use all predetermined baseline replicas, never snapshot cost or luck."""
    if len(replicas)!=2:raise ValueError('exactly two fresh baseline replicas required')
    values=[]
    for replica in replicas:
        if not replica['valid']:return dict(status='INVALID_PREFLIGHT',reason='baseline load/state validation failed')
        samples=replica['pressure_samples']
        if not samples or max(samples)-min(samples)>limit*.015:return dict(status='UNREACHABLE',reason='fresh baseline plateau is unstable')
        values+=samples
    percentages=[value*100/limit for value in values]
    if max(percentages)-min(percentages)>2*tolerance:return dict(status='UNREACHABLE',reason='fresh replay residency variance exceeds the pressure band',observed_percent=percentages)
    if all(abs(value-percent)<=tolerance for value in percentages):return dict(status='FROZEN',observed_percent=percentages)
    center=sum(percentages)/len(percentages)
    candidate=round(records*percent/center)
    if candidate==records or not 1024<=candidate<=1000000:return dict(status='UNREACHABLE',reason='baseline pressure cannot refine a bounded object count',observed_percent=percentages)
    return dict(status='REFINE',records=candidate,observed_percent=percentages,rule='scale retained Record count from all fresh baseline pressure samples')
