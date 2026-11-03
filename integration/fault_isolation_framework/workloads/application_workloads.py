# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""One genuine service per business cgroup; no byte-only pressure filler."""
import hashlib
import json
import os
import re
import time
import shutil
import uuid
import urllib.request
from pathlib import Path
from ..core.util import run,require,wait_for
from ..environments.performance import cgroup_memory
from .resident_kv import rpc,freeze_plan
from .application_protocol import dataset_digest


class ApplicationWorkload:
    def __init__(self,owner,language):
        self.owner=owner;self.a=owner.a;self.language=language
        self.root=owner.out/'business';self.root.mkdir()
        self.url='http://127.0.0.1:%d'%self.a.service_port_base
        self.records=0;self.allow_db_cleanup=False;self.last_digest=None

    def start(self):
        a=self.a;source=Path(__file__).parent/'applications';tools=Path(a.application_tools).resolve()
        args=['--network','host','--memory','%dm'%a.memory_limit_mib,'--memory-swap','%dm'%a.memory_limit_mib,'--cpus',str(a.business_cpus),'-e','HUATUO_TEST_PORT='+str(a.service_port_base),'-e','APP_DIAGNOSTIC='+str(int(a.application_diagnostic)),'-v',str(source)+':/application:ro','-v',str(tools)+':'+str(tools)+':ro','-v',str(self.root)+':/application-work']
        for root in ('/usr','/lib','/lib64','/bin','/etc'):args+=['-v',root+':'+root+':ro']
        if self.language=='go':
            runtime=Path(a.runtime_data_root).resolve();runtime.mkdir(parents=True,exist_ok=True)
            require(shutil.disk_usage(runtime).free>9<<30,'owned etcd store requires9GiBdisk headroom; preserve old failures')
            self.database=runtime/uuid.uuid4().hex;self.database.mkdir(mode=0o700)
            self.database_marker=dict(token=self.database.name,output=str(self.owner.out))
            (self.database/'.huatuo-owned.json').write_text(json.dumps(self.database_marker))
            args+=['-v',str(self.database)+':/application-db','-e','GOMAXPROCS=4']
            command=[str(tools/'etcd/etcd'),'--data-dir=/application-db','--listen-client-urls='+self.url.replace('127.0.0.1','0.0.0.0'),'--advertise-client-urls='+self.url,'--quota-backend-bytes=8589934592']
        elif self.language=='java':
            (self.root/'tmp').mkdir()
            heap=int(a.memory_limit_mib*.85-64)
            require(heap>128,'JVM profile lacks real heap headroom')
            command=[a.java_home+'/bin/java','-Djava.io.tmpdir=/application-work/tmp','-Xms%dm'%heap,'-Xmx%dm'%heap,'-XX:+UseG1GC','-XX:ActiveProcessorCount=4','-Xlog:gc:file=/application-work/gc.log:time,uptime,level,tags:filecount=2,filesize=5M','-jar',str(tools/'spring-cache/target/spring-cache-1.0.0.jar')]
        else:command=[str(tools/'fastapi/bin/python'),'/application/fastapi_cache.py']
        wrapper=['/bin/sh','-c','printf \'{"application_launch":true}\\n\'; exec "$@"','application']
        target=self.owner.environment.launch(args,wrapper+command,retain_exit_logs=True)
        target.update(id='application-'+self.language,role='target',language=self.language,url=self.url)
        self.target=target;self.owner.targets=[target];self.initial_memory=self.memory()
        wait_for('real application HTTP readiness',lambda:self.health(),timeout=45)
        (self.owner.out/'application-profile.json').write_text(json.dumps(dict(language=self.language,command=command,diagnostic=a.application_diagnostic,topology='one business process; FastAPI one Uvicorn worker, Spring Tomcat32threads',java_heap_profile='fixed Xms=Xmx normalG1, no pretouch' if self.language=='java' else None,go_profile='GOMAXPROCS4, ordinary etcd runtime GC and MemProfileRate default; actual metadata validated by C provider' if self.language=='go' else None),indent=2)+'\n')
        return target

    def health(self):
        try:
            if self.language=='go':return rpc(self.url,'/health')
            return self.stats()
        except (OSError,ValueError):return None

    def sdk(self,mode,count):
        result=run(str(Path(self.a.application_tools)/'etcd-load-tool'),'--mode='+mode,'--endpoint='+self.url,'--records='+str(count),'--fill-from='+str(self.records if mode=='fill' else 0),timeout=600)
        return json.loads(result.stdout)

    def fill(self,count):
        if self.language=='go':result=self.sdk('fill',count)
        else:result=rpc(self.url,'/fill?records=%d&seed=%d'%(count,self.a.seed),True)
        self.records=count;return result

    def freeze(self):
        if self.language!='go':return rpc(self.url,'/freeze',True)
        return dict(frozen=True,records=self.records,scope='no more SDK fill calls; etcd remains a normal read/write KV')

    def stats(self):
        if self.language!='go':
            result=rpc(self.url,'/stats');result['cpu_quota']=cpu_scope_for_pid(self.target['pid']);return result
        with urllib.request.urlopen(self.url+'/metrics',timeout=5) as response:text=response.read(4<<20).decode()
        metrics={}
        for line in text.splitlines():
            if line and not line.startswith('#'):
                fields=line.split()
                if len(fields)==2 and '{' not in fields[0]:
                    try:metrics[fields[0]]=float(fields[1])
                    except ValueError:pass
        return dict(cpu_quota=cpu_scope_for_pid(self.target['pid']),records=self.records,runtime=dict(framework='etcd3.6.5',gomaxprocs=4,workers=1),metrics=metrics,
                    heap_used_bytes=metrics.get('go_memstats_heap_alloc_bytes'),heap_committed_bytes=metrics.get('go_memstats_heap_sys_bytes'),
                    gc=dict(collections=metrics.get('go_gc_duration_seconds_count'),pause_wall_seconds=metrics.get('go_gc_duration_seconds_sum'),cpu_fraction=metrics.get('go_memstats_gc_cpu_fraction')),
                    maintenance='ownedDB SDK5s bounded revision compaction, retention1000; no concurrent automatic compactor; DB/revision raw in SDK artifacts')

    def memory(self):return cgroup_memory(self.target['cgroup'])

    def verify(self,expected_counts=None):
        stats=self.stats();memory=self.memory()
        if self.language=='go':digest=self.sdk('verify',self.records)['dataset_sha256']
        else:
            verified=rpc(self.url,'/stats?verify=1');digest=verified['dataset_sha256']
            require(verified['records']==self.records,'application retained object count differs')
        require(digest==dataset_digest(self.records),'actual application bytes differ from independent full dataset oracle')
        require(memory['oom_kills']==self.initial_memory['oom_kills'],'business OOM kill observed')
        # A cgroup charge failure is distinct from an OOM kill and is preserved.
        self.last_digest=digest
        proof=dict(stats=stats,memory=memory,initial_memory=self.initial_memory,dataset_sha256=digest,records=self.records)
        if self.language=='java':
            files=list(self.root.glob('gc.log*'));pauses=[]
            for path in files:
                for line in path.read_text().splitlines():
                    match=re.search(r'Pause.* ([0-9.]+)ms$',line)
                    if match:pauses.append(float(match[1]))
            proof['gc_log']=dict(pause_entries=len(pauses),pause_total_ms=sum(pauses),gc_cpu_seconds=None,scope='boundedHotSpotGC pause wall durations; MXBean collection walltime separate; CPU unsupported null',files={path.name:dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in files})
        if self.language=='python':
            require(stats['gc']['enabled'],'Python normal GC disabled')
            samples=stats.get('tracked_samples') or [stats.get('tracked',{})]
            require(samples and all(sample and all(sample.values()) for sample in samples),'Python real Record/nested graph not tracked')
        return proof

    def calibrate(self,percent):
        limit=self.a.memory_limit_mib<<20;count=1024;trace=[]
        for iteration in range(40):
            stats=self.fill(count);time.sleep(.5);memory=self.memory();usage=memory['current_bytes']
            trace.append(dict(iteration=iteration,records=count,memory=memory,stats=stats,epoch=time.time()))
            (self.owner.out/'calibration.json').write_text(json.dumps(trace,indent=2)+'\n')
            require(memory['oom_kills']==self.initial_memory['oom_kills'],'preload OOM kill observed')
            ratio=usage*100/limit
            if percent-self.a.pressure_tolerance<=ratio<=percent+self.a.pressure_tolerance:
                samples=[]
                for _ in range(5):time.sleep(.25);samples.append(self.memory()['current_bytes'])
                plan=freeze_plan(count,limit,percent,samples,self.a.pressure_tolerance)
                plan.update(fill_recipe=[dict(records=row['records'],settle_seconds=.5) for row in trace],plateau_samples=5,plateau_interval=.25,seed=self.a.seed,language=self.language,object_shape='real product graph; 90%1KiB/10%64KiB actual values')
                return plan
            require(ratio<percent+self.a.pressure_tolerance,'preload overshot pressure band; retain invalid calibration')
            gap=limit*percent/100-usage;estimate=max(8192,usage/count)
            count+=max(64,min(20000,int(gap/estimate*.55)))
            require(count<=1000000,'real key-count budget cannot reach pressure')
        raise RuntimeError('application pressure unreachable within bounded40step preload')


def read_cpu_scope(path):
    path=Path(path)
    def integer(name):
        try:return int((path/name).read_text().strip())
        except (OSError,ValueError):return None
    try:stat=dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())
    except OSError:stat={}
    usage=integer('cpuacct.usage');quota=integer('cpu.cfs_quota_us');period=integer('cpu.cfs_period_us')
    return dict(cpu_seconds=usage/1e9 if usage is not None else None,
                quota_cores=quota/period if quota is not None and quota>0 and period else None,
                periods=int(stat['nr_periods']) if 'nr_periods' in stat else None,
                throttled_periods=int(stat['nr_throttled']) if 'nr_throttled' in stat else None,
                throttled_seconds=int(stat['throttled_time'])/1e9 if 'throttled_time' in stat else None,
                scope=str(path),units='cgroupv1 cumulative CPU/throttled seconds; periods counts; unsupported null')


def cpu_scope_for_pid(pid):
    controllers=Path('/proc/%d/cgroup'%pid).read_text().splitlines()
    relative=next((line.split(':',2)[2] for line in controllers if 'cpu' in line.split(':')[1].split(',')),None)
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,right=line.split(' - ',1);fields=right.split()
        if relative is not None and fields[0]=='cgroup' and 'cpu' in fields[2].split(','):
            return read_cpu_scope(Path(left.split()[4])/relative.lstrip('/'))
    return dict(cpu_seconds=None,quota_cores=None,periods=None,throttled_periods=None,throttled_seconds=None,scope=None,units='CPU controller unavailable; unsupported null')


def finish_owned_database(directory,marker,output,success,digest):
    import shutil
    directory=Path(directory);output=Path(output)
    path=directory/'.huatuo-owned.json'
    if directory.is_symlink() or path.is_symlink() or not re.fullmatch('[a-f0-9]{32}',directory.name) or json.loads(path.read_text())!=marker or marker.get('token')!=directory.name or marker.get('output')!=str(output):
        raise ValueError('owned database marker/path changed; preserve without deletion')
    size=sum(entry.stat().st_size for entry in directory.rglob('*') if entry.is_file() and not entry.is_symlink())
    result=dict(directory=str(directory),retained=not success,bytes=size,last_successful_dataset_sha256=digest,
                lifecycle='ephemeral owned business state removed only after successful verification and container stop; failed campaign state retained; raw metrics/requests/proofs remain in evidence')
    if success:shutil.rmtree(directory)
    (output/'business-data-lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')
