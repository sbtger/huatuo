#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Authenticated bounded load jobs on a separate VM; no arbitrary commands."""
import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import resource
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.workloads.performance_load import run_load


def sha256(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):digest.update(block)
    return digest.hexdigest()


def driver_hashes():
    root=Path(__file__).resolve().parent
    return {name:sha256(root/name) for name in ('load_controller.py','workloads/performance_load.py','workloads/redis_protocol.py')}


def usage():
    r=resource.getrusage(resource.RUSAGE_SELF)
    row=dict(time=time.monotonic(),epoch=time.time(),cpu_seconds=r.ru_utime+r.ru_stime,
             controller_lifetime_peak_rss_bytes=r.ru_maxrss*(1024 if sys.platform.startswith('linux') else 1))
    for name in ('stat','meminfo','pressure/cpu','pressure/memory'):
        path=Path('/proc')/name
        row[name]=path.read_text() if path.exists() else None
    return row


class JobManager:
    def __init__(self,root,target_host,ports,lease_seconds):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.target_host,self.ports,self.lease_seconds=target_host,set(ports),lease_seconds
        self.jobs={};self.lock=threading.Lock()

    def validate(self,spec):
        targets=spec.get('targets',[])
        if not isinstance(targets,list) or not 1<=len(targets)<=32:raise ValueError('expected 1..32 targets')
        ids=set()
        for t in targets:
            if set(t)-{'id','url','kind','expected_b64','keys','value_bytes'}:raise ValueError('unsupported target fields')
            if not isinstance(t.get('id'),str) or t['id'] in ids or len(t['id'])>100:raise ValueError('invalid target identity')
            ids.add(t['id'])
            u=urlsplit(t['url']);kind=t.get('kind','http')
            if kind not in ('http','redis') or u.scheme!=('redis' if kind=='redis' else 'http') or u.hostname!=self.target_host or u.port not in self.ports or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
                raise ValueError('destination is outside configured fixture routes')
            if kind=='http':
                wanted=base64.b64decode(t['expected_b64'],validate=True)
                if not 1<=len(wanted)<=4096:raise ValueError('HTTP checksum body missing/oversized')
            elif not 1<=t.get('keys',128)<=4096 or not 1<=t.get('value_bytes',65536)<=1<<20:
                raise ValueError('Redis fixture size outside budget')
        qps,duration,start=(spec[k] for k in ('qps','duration','start_monotonic'))
        if not all(isinstance(v,(int,float)) and not isinstance(v,bool) and math.isfinite(v) for v in (qps,duration,start)):
            raise ValueError('rate/duration/start must be finite numbers')
        if not 0<qps<=1000 or not 0<duration<=3600 or not time.monotonic()-.2<=start<=time.monotonic()+60:
            raise ValueError('rate/duration/start outside load budget')
        if math.ceil(qps*duration)*len(targets)>250000:raise ValueError('request count exceeds job budget')
        if not 1<=spec['workers']<=64 or not 1<=spec['pending']<=256:raise ValueError('queue/worker capacity outside budget')

    def start(self,spec):
        self.validate(spec)
        with self.lock:
            if any(not j.get('sealed') for j in self.jobs.values()):raise ValueError('another load job is active')
            if sum(not j.get('acked') for j in self.jobs.values())>=4:raise ValueError('unacknowledged artifacts require collection')
            ident=uuid.uuid4().hex;directory=self.root/ident;directory.mkdir()
            job=dict(id=ident,root=directory,stop=threading.Event(),done=threading.Event(),last_seen=time.monotonic(),
                     meta=dict(id=ident,state='running',recorded=0,error='',driver_sha256=driver_hashes(),
                               pid=os.getpid(),kernel=os.uname().release,cpu_count=os.cpu_count()))
            self.jobs[ident]=job
        (directory/'request.json').write_text(json.dumps(spec,indent=2)+'\n')
        threading.Thread(target=self.execute,args=(job,spec),daemon=True).start()
        return dict(id=ident)

    def execute(self,job,spec):
        directory=job['root'];stop=job['stop'];samples=[];lease_expired=threading.Event()
        stream=(directory/'load-resources.jsonl').open('x')
        def observe():
            next_sample=0
            while not job['done'].wait(.05):
                if time.monotonic()-job['last_seen']>self.lease_seconds:
                    lease_expired.set();stop.set()
                if time.monotonic()>=next_sample:
                    row=usage();samples.append(row);stream.write(json.dumps(row)+'\n');stream.flush()
                    next_sample=time.monotonic()+1
        watcher=threading.Thread(target=observe,daemon=True)
        before=usage();stream.write(json.dumps(before)+'\n');watcher.start()
        try:
            targets=[dict(t) for t in spec['targets']]
            for t in targets:
                if t.get('kind','http')=='http':t['_expected']=base64.b64decode(t['expected_b64'])
            rows=run_load(targets,directory/'requests.jsonl',spec['qps'],spec['duration'],spec['workers'],spec['pending'],
                          start_monotonic=spec['start_monotonic'],stop=stop)
            job['meta'].update(recorded=len(rows),state='cancelled' if stop.is_set() else 'finished')
            if lease_expired.is_set():job['meta']['error']='client lease expired'
        except Exception as exc:
            job['meta'].update(state='failed',error=repr(exc))
        finally:
            # Stop the observer before sealing raw artifacts.
            job['done'].set();watcher.join(3)
            after=usage();stream.write(json.dumps(after)+'\n');stream.close()
            job['meta'].update(cpu_seconds=after['cpu_seconds']-before['cpu_seconds'],
                               elapsed_seconds=after['time']-before['time'],
                               files={p.name:dict(sha256=sha256(p),bytes=p.stat().st_size) for p in (directory/'requests.jsonl',directory/'load-resources.jsonl') if p.exists()})
            (directory/'job.json').write_text(json.dumps(job['meta'],indent=2)+'\n')
            job['sealed']=True

    def get(self,ident):
        with self.lock:
            if ident not in self.jobs:raise KeyError('unknown job')
            job=self.jobs[ident];job['last_seen']=time.monotonic()
            meta=dict(job['meta'])
            if not job.get('sealed'):meta['state']='running'
            return job,meta


def create_server(address,root,token,target_host,ports,lease_seconds=10):
    manager=JobManager(root,target_host,ports,lease_seconds)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,status,body):
            data=json.dumps(body).encode();self.send_response(status)
            self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)))
            self.end_headers();self.wfile.write(data)
        def authorized(self):
            if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token):
                self.reply(401,dict(error='unauthorized'));return False
            return True
        def do_GET(self):
            if not self.authorized():return
            try:
                parts=urlsplit(self.path).path.strip('/').split('/')
                if parts==['health']:
                    return self.reply(200,dict(monotonic=time.monotonic(),epoch=time.time(),pid=os.getpid(),
                                               kernel=os.uname().release,cpu_count=os.cpu_count(),driver_sha256=driver_hashes()))
                if len(parts)<2 or parts[0]!='jobs':raise KeyError('unknown route')
                job,meta=manager.get(parts[1])
                if len(parts)==2:return self.reply(200,meta)
                names={'requests':'requests.jsonl','resources':'load-resources.jsonl'}
                if len(parts)!=3 or parts[2] not in names or not job.get('sealed'):raise KeyError('artifact unavailable')
                path=job['root']/names[parts[2]]
                self.send_response(200);self.send_header('Content-Length',str(path.stat().st_size));self.end_headers()
                with path.open('rb') as stream:
                    for block in iter(lambda:stream.read(65536),b''):self.wfile.write(block)
            except KeyError as exc:self.reply(404,dict(error=str(exc)))
            except (OSError,ValueError) as exc:self.reply(400,dict(error=str(exc)))
        def do_POST(self):
            if not self.authorized():return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=65536:raise ValueError('bounded JSON body required')
                body=json.loads(self.rfile.read(length));parts=urlsplit(self.path).path.strip('/').split('/')
                if parts==['jobs']:return self.reply(200,manager.start(body))
                if len(parts)!=3 or parts[0]!='jobs':raise KeyError('unknown route')
                job,meta=manager.get(parts[1])
                if parts[2]=='cancel':
                    job['stop'].set();return self.reply(200,dict(cancelled=True))
                if parts[2]=='ack':
                    if not job.get('sealed') or body.get('files')!=meta.get('files'):raise ValueError('artifact hashes must be acknowledged')
                    for name in meta['files']:(job['root']/name).unlink(missing_ok=True)
                    job['acked']=True;return self.reply(200,dict(acked=True))
                raise KeyError('unknown route')
            except KeyError as exc:self.reply(404,dict(error=str(exc)))
            except (OSError,TypeError,ValueError) as exc:self.reply(400,dict(error=str(exc)))
    server=ThreadingHTTPServer(address,Handler);server.manager=manager
    return server


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bind',default='0.0.0.0');p.add_argument('--port',type=int,default=19890)
    p.add_argument('--token-file',required=True);p.add_argument('--output',required=True)
    p.add_argument('--target-host',required=True);p.add_argument('--port-start',type=int,required=True);p.add_argument('--port-count',type=int,default=64)
    a=p.parse_args();token=Path(a.token_file).read_text().strip()
    if len(token)<32:p.error('use a random token of at least32 characters')
    server=create_server((a.bind,a.port),a.output,token,a.target_host,range(a.port_start,a.port_start+a.port_count))
    try:server.serve_forever()
    finally:
        for job in server.manager.jobs.values():job['stop'].set()
        server.server_close()


if __name__=='__main__':main()
