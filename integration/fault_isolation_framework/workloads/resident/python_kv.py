# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real tracked Record/nested-container KV; normal CPython GC stays enabled."""
import gc,hashlib,json,os,platform,sys,threading,time,urllib.parse
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer


gc_timing=dict(collections=0,pause_callback_wall_ns=0,collector_thread_cpu_ns=0,active={})

def gc_timing_callback(phase,info):
    generation=info['generation']
    if phase=='start':gc_timing['active'][generation]=(time.monotonic_ns(),time.thread_time_ns())
    elif phase=='stop':
        started=gc_timing['active'].pop(generation,None)
        if started:
            gc_timing['collections']+=1
            gc_timing['pause_callback_wall_ns']+=time.monotonic_ns()-started[0]
            gc_timing['collector_thread_cpu_ns']+=time.thread_time_ns()-started[1]

gc.callbacks.append(gc_timing_callback)


class Record:
    __slots__=('key','value','labels','children')
    def __init__(self,key):
        self.key=key;self.value=bytearray([97+key%26])*(65536 if key%10==0 else 1024)
        self.labels={'kind':key%10,'key':key,'tracked':[]}
        self.children=[[key,key+1],{'owner':key,'tracked':[]}]


records=[];churn=[Record(i) for i in range(64)]
counts=dict(GET=0,SET=0,DELETE=0);lock=threading.Lock();dataset_hash=hashlib.sha256()


def stats():
    sample=records[:32]
    return dict(records=len(records),churn_slots=len(churn),operations=dict(counts),runtime='CPython '+platform.python_version(),
                gc_timing={key:value for key,value in gc_timing.items() if key!='active'},gc_timing_scope='bounded gc.callbacks start/stop wall and collecting-thread CPU; includes callback overhead; cumulative process lifetime',python_allocated_blocks=sys.getallocatedblocks(),gc=dict(enabled=gc.isenabled(),counts=gc.get_count(),threshold=gc.get_threshold(),generations=gc.get_stats()),
                tracked_samples=[dict(record=gc.is_tracked(r),labels=gc.is_tracked(r.labels),children=gc.is_tracked(r.children),nested=gc.is_tracked(r.children[0])) for r in sample],
                small_bytes=1024,large_bytes=65536,large_every=10,dataset_sha256=dataset_hash.hexdigest())


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def answer(self,body):
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def do_POST(self):
        path=urllib.parse.urlsplit(self.path);query=urllib.parse.parse_qs(path.query)
        with lock:
            n=int(query.get('records',['-1'])[0])
            if path.path!='/fill' or not len(records)<=n<=1000000:self.send_error(400);return
            while len(records)<n:
                record=Record(len(records));dataset_hash.update(('%d:%d:%s\n'%(record.key,len(record.value),hashlib.sha256(record.value).hexdigest())).encode());records.append(record)
            self.answer(json.dumps(stats()).encode())
    def do_GET(self):
        path=urllib.parse.urlsplit(self.path);query=urllib.parse.parse_qs(path.query)
        with lock:
            if path.path=='/stats':self.answer(json.dumps(stats()).encode());return
            if path.path!='/op' or len(records)<1024:self.send_error(400);return
            ordinal=int(query['ordinal'][0]);seed=int(query['seed'][0]);mixed=((ordinal+seed)*1103515245+12345)&0x7fffffff
            kind='GET';key=mixed%min(len(records),1024);value=records[key]
            if mixed%10>=6:
                key=mixed%64;kind='SET'
                if mixed%10>=9:kind='DELETE';churn[key]=None
                churn[key]=Record(key);value=churn[key]
            counts[kind]+=1
            body=('%d|%s|%d|%s\n'%(ordinal,kind,key,hashlib.sha256(value.value).hexdigest())).encode();self.answer(body)


if __name__=='__main__':
    server=ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('HUATUO_TEST_PORT','30000'))),Handler)
    print(json.dumps(dict(pid=os.getpid(),url='http://127.0.0.1:%d'%server.server_port,language='python',runtime=platform.python_version())),flush=True)
    server.serve_forever()
