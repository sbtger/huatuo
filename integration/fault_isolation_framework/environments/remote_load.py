# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Remote fixed-arrival control, clock bounds and verified raw transfer."""
import base64
import hashlib
import json
import math
import time
import urllib.request
from pathlib import Path


class RemoteLoad:
    def __init__(self,url,token_file,output,max_clock_error=.02):
        self.url=url.rstrip('/');self.token=Path(token_file).read_text().strip()
        self.output=Path(output);self.output.mkdir(parents=True,exist_ok=True)
        self.max_clock_error=max_clock_error;self.job=None;self.clock=None
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self,path,body=None):
        req=urllib.request.Request(self.url+path,data=json.dumps(body).encode() if body is not None else None,
                                   headers={'Authorization':'Bearer '+self.token})
        with self.opener.open(req,timeout=5) as response:
            return json.loads(response.read(1<<20))

    def calibrate(self):
        samples=[]
        for _ in range(5):
            before=time.monotonic();health=self.request('/health');after=time.monotonic()
            if not isinstance(health.get('monotonic'),(int,float)) or not math.isfinite(health['monotonic']):raise ValueError('invalid remote clock sample')
            samples.append(dict(rtt=after-before,offset=(before+after)/2-health['monotonic']))
        best=min(samples,key=lambda x:x['rtt'])
        if best['rtt']/2>self.max_clock_error:raise ValueError('remote clock uncertainty exceeds budget')
        required={'load_controller.py','workloads/performance_load.py','workloads/redis_protocol.py'}
        if set(health.get('driver_sha256',{}))!=required:raise ValueError('load-controller source proof incomplete')
        root=Path(__file__).resolve().parents[1]
        for name,expected in health['driver_sha256'].items():
            if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:raise ValueError('load-controller source mismatch: '+name)
        result=dict(best,samples=samples,health=health)
        if self.clock is None:self.clock=result
        return result

    def download(self,job,kind,path,expected):
        req=urllib.request.Request(self.url+'/jobs/'+job+'/'+kind,headers={'Authorization':'Bearer '+self.token})
        digest=hashlib.sha256();size=0
        with self.opener.open(req,timeout=10) as response, Path(path).open('xb') as stream:
            for block in iter(lambda:response.read(65536),b''):
                size+=len(block)
                if size>128<<20:raise ValueError('remote artifact exceeds transfer budget')
                digest.update(block);stream.write(block)
        if size!=expected['bytes'] or digest.hexdigest()!=expected['sha256']:raise ValueError('remote artifact integrity mismatch')

    def cancel(self):
        if self.job is not None:
            self.request('/jobs/'+self.job+'/cancel',{})
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                status=self.request('/jobs/'+self.job)
                if status['state']!='running':return
                time.sleep(.2)
            raise RuntimeError('remote load did not stop within cleanup budget')

    def run(self,targets,qps,duration,workers,pending,expected,start):
        if self.clock is None:self.calibrate()
        normalized=[]
        for target in targets:
            t=dict(target)
            if t.get('kind','http')=='http':t['expected_b64']=base64.b64encode(expected).decode()
            normalized.append(t)
        spec=dict(targets=normalized,qps=qps,duration=duration,workers=workers,pending=pending,
                  start_monotonic=start-self.clock['offset'])
        meta=dict(clock_before=self.clock,spec=spec)
        try:
            self.job=self.request('/jobs',spec)['id']
            deadline=start+duration+max(30,2*pending/workers+10)
            while True:
                status=self.request('/jobs/'+self.job)
                if status['state']!='running':break
                if time.monotonic()>deadline:raise TimeoutError('remote job deadline exceeded')
                time.sleep(.2)
            meta.update(status)
            for kind,name in [('requests','requests.jsonl'),('resources','load-resources.jsonl')]:
                self.download(self.job,kind,self.output/('remote-'+name),status['files'][name])
            clock_after=self.calibrate();meta['clock_after']=clock_after
            if abs(clock_after['offset']-self.clock['offset'])+clock_after['rtt']/2+self.clock['rtt']/2>self.max_clock_error:
                raise ValueError('remote clock drift/uncertainty exceeds budget')
            rows=[]
            with (self.output/'remote-requests.jsonl').open() as stream, (self.output/'requests.jsonl').open('x') as converted:
                for line in stream:
                    row=json.loads(line)
                    for key in ('scheduled','sent','ended'):
                        if row.get(key) is not None:
                            row['remote_'+key]=row[key];row[key]+=self.clock['offset']
                    converted.write(json.dumps(row)+'\n');rows.append(row)
            if status['state']!='finished':raise RuntimeError('remote job failed/cancelled: '+status.get('error',''))
            self.request('/jobs/'+self.job+'/ack',dict(files=status['files']))
            return rows
        finally:
            if self.job is not None:
                self.cancel()
            (self.output/'remote-load.json').write_text(json.dumps(meta,indent=2)+'\n')
