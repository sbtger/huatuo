# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Native product plugins; target data and queues supply observed memory."""
import base64
import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path
from ..core.util import require, run, wait_for, write_control
from ..environments.linux import identity, ManagedProcess
from ..environments.supervisor import own

BODY=b'huatuo-business-body\n'*64
VALUE=b'huatuo-kv-payload\n'*(1048576//18)


def http(url,body=None):
    request=urllib.request.Request(url,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=15) as response:return response.read()


def kv(url,path,body):return json.loads(http(url+'/v3/kv/'+path,body))
def b64(data):return base64.b64encode(data).decode()


class NativeProduct:
    language=''

    def __init__(self,owner,role,offset):
        self.owner=owner;self.a=owner.a;self.role=role;self.offset=offset
        self.root=owner.out/role;self.root.mkdir();self.origin=None
        self.port=self.a.service_port_base+offset;self.url='http://127.0.0.1:%d'%self.port
        self.log=self.root/'business.log'

    def launch(self,command):
        env=self.owner.environment
        args=['docker','run','-d','--rm','--network','host','--memory','%dm'%self.a.memory_limit_mib,'--memory-swap','%dm'%self.a.memory_limit_mib]
        for root in ('/usr','/lib','/lib64','/bin','/sbin','/etc'):
            args+=['-v',root+':'+root+':ro']
        for root in (str(self.root),self.a.native_root,str(Path(__file__).parent)):
            args+=['-v',root+':'+root+('' if root==str(self.root) else ':ro')]
        args+=['-e','JAVA_HOME='+self.a.java_home,'-e','KAFKA_HEAP_OPTS=-Xms64m -Xmx1024m',env.image]+command
        cid=run(*args,timeout=30).stdout.strip();env.containers.append(cid);own('container',cid)
        pid=int(run('docker','inspect','-f','{{.State.Pid}}',cid).stdout.strip())
        cg=next(line.split(':',2)[2] for line in Path('/proc/%d/cgroup'%pid).read_text().splitlines() if 'memory' in line.split(':')[1].split(','))
        self.target=dict(id=self.role+'-'+self.a.business,role=self.role,language=self.language,cid=cid,pid=pid,identity=identity(pid),cgroup=env.mount/cg.lstrip('/'),url=self.url)
        self.target['oom_before']=(self.target['cgroup']/'memory.failcnt').read_text().strip()
        return self.target

    def close(self):
        if hasattr(self,'target'):
            logs=run('docker','logs',self.target['cid'],check=False);self.log.write_text(logs.stdout+logs.stderr)
        if self.origin:self.origin.stop()

    def release(self):pass

    def proof(self):
        t=self.target
        require(identity(t['pid'])==t['identity'],'native business process changed')
        require((t['cgroup']/'memory.failcnt').read_text().strip()==t['oom_before'],'native business memory allocation hit limit')
        return dict(pid=t['pid'],identity=t['identity'],cgroup=str(t['cgroup']),memory_bytes=int((t['cgroup']/'memory.usage_in_bytes').read_text()))


class EtcdProduct(NativeProduct):
    language='go'

    def start(self):
        binary=str(Path(self.a.native_root)/'etcd/etcd')
        target=self.launch([binary,'--name','native','--data-dir',str(self.root/'data'),'--listen-client-urls','http://0.0.0.0:%d'%self.port,'--advertise-client-urls',self.url,'--listen-peer-urls','http://127.0.0.1:%d'%(self.port+10),'--initial-advertise-peer-urls','http://127.0.0.1:%d'%(self.port+10),'--initial-cluster','native=http://127.0.0.1:%d'%(self.port+10),'--quota-backend-bytes','2147483648','--snapshot-count','1000000'])
        wait_for('etcd health',lambda:json.loads(http(self.url+'/health')).get('health')=='true',timeout=45)
        self.put('/correctness/000000',VALUE)
        return target

    def put(self,key,value):return kv(self.url,'put',dict(key=b64(key.encode()),value=b64(value)))

    def pressure(self):
        for i in range(self.a.dataset_mib):self.put('/pressure/%06d'%i,VALUE)
        return dict(keys=self.a.dataset_mib,value_bytes=len(VALUE),payload_sha256=hashlib.sha256(VALUE).hexdigest())

    def verify(self):
        proof=self.proof();raw=kv(self.url,'range',dict(key=b64(b'/correctness/000000')))
        require(len(raw.get('kvs',[]))==1 and base64.b64decode(raw['kvs'][0]['value'])==VALUE,'etcd known-input readback mismatch')
        # The official PUT tool does not expose its crypto-random value. Retain
        # exact key cardinality and lengths; do not claim known-input coverage.
        if self.role=='neighbor':return proof
        requests=[dict(request_range=dict(key=b64(bytes([i*2])+bytes(15)))) for i in range(64)]
        responses=kv(self.url,'txn',dict(success=requests)).get('responses',[])
        rows=[r['response_range']['kvs'][0] for r in responses if len(r.get('response_range',{}).get('kvs',[]))==1]
        require(len(rows)==64,'etcd benchmark key cardinality mismatch')
        require(all(len(base64.b64decode(r.get('value','')))==256 for r in rows),'etcd benchmark value length mismatch')
        expected=getattr(self,'expected_puts',0)
        require(sum(int(r['version']) for r in rows)==expected,'etcd benchmark committed version count mismatch')
        proof.update(known_input_sha256=hashlib.sha256(VALUE).hexdigest(),benchmark_keys=len(rows),benchmark_committed_versions=expected,benchmark_value_lengths=[256],benchmark_payloads_known=False)
        return proof


class KafkaProduct(NativeProduct):
    language='java'

    def start(self):
        kafka=Path(self.a.native_root)/'kafka';config=self.root/'server.properties'
        external='%s:%d'%(self.a.load_target_host,self.a.load_target_base_port+self.offset)
        config.write_text('process.roles=broker,controller\nnode.id=1\ncontroller.quorum.voters=1@127.0.0.1:%d\nlisteners=EXTERNAL://0.0.0.0:%d,INTERNAL://127.0.0.1:%d,CONTROLLER://127.0.0.1:%d\nadvertised.listeners=EXTERNAL://%s,INTERNAL://127.0.0.1:%d\nlistener.security.protocol.map=EXTERNAL:PLAINTEXT,INTERNAL:PLAINTEXT,CONTROLLER:PLAINTEXT\ncontroller.listener.names=CONTROLLER\ninter.broker.listener.name=INTERNAL\nlog.dirs=%s\noffsets.topic.replication.factor=1\ntransaction.state.log.replication.factor=1\ntransaction.state.log.min.isr=1\ngroup.initial.rebalance.delay.ms=0\nnum.partitions=1\nmessage.max.bytes=2097152\nsocket.request.max.bytes=4194304\nqueued.max.requests=16\nlog.segment.bytes=67108864\n' %(self.port+20,self.port,self.port+10,self.port+20,external,self.port+10,self.root/'logs'))
        run(str(kafka/'bin/kafka-storage.sh'),'format','-t','MkU3OEVBNTcwNTJENDM2Qk','-c',str(config),timeout=45)
        target=self.launch([str(kafka/'bin/kafka-server-start.sh'),str(config)])
        self.internal='127.0.0.1:%d'%(self.port+10)
        wait_for('Kafka broker ready',lambda:run(str(kafka/'bin/kafka-broker-api-versions.sh'),'--bootstrap-server',self.internal,check=False,timeout=20).returncode==0,timeout=90)
        run(str(kafka/'bin/kafka-topics.sh'),'--bootstrap-server',self.internal,'--create','--topic','pressure','--partitions','1','--replication-factor','1',timeout=30)
        return target

    def pressure(self):
        kafka=Path(self.a.native_root)/'kafka'
        result=run(str(kafka/'bin/kafka-producer-perf-test.sh'),'--topic','pressure','--num-records',str(self.a.dataset_mib),'--record-size','1048576','--throughput','-1','--producer-props','bootstrap.servers='+self.internal,'acks=all','retries=0','enable.idempotence=false','max.request.size=2097152',timeout=90)
        (self.root/'pressure-producer.stdout').write_text(result.stdout);(self.root/'pressure-producer.stderr').write_text(result.stderr)
        return dict(records=self.a.dataset_mib,record_bytes=1048576,scope='real broker request processing and log/page cache; anonymous growth must be observed separately')

    def verify(self):return self.proof()


class ProxyProduct(NativeProduct):
    language='python'

    def start(self):
        self.control=self.root/'retained-flows';write_control(self.control,'0')
        scripts=Path(__file__).parent/'native';origin_port=self.port+10
        self.origin=ManagedProcess();self.origin.start([self.a.python,str(scripts/'proxy_origin.py'),'--port',str(origin_port)],self.root/'origin.log',dict(os.environ))
        binary=str(Path(self.a.native_root)/'mitmproxy/bin/mitmdump')
        target=self.launch([binary,'--mode','reverse:http://127.0.0.1:%d'%origin_port,'--listen-host','0.0.0.0','--listen-port',str(self.port),'-s',str(scripts/'proxy_retention.py'),'--set','business_control='+str(self.control),'--set','flow_detail=0','--set','termlog_verbosity=warn','--set','confdir='+str(self.root/'conf')])
        wait_for('mitmproxy reverse readiness',lambda:http(self.url)==BODY,timeout=45)
        return target

    def pressure(self):
        write_control(self.control,str(self.a.dataset_mib))
        digest=None
        for _ in range(self.a.dataset_mib):digest=hashlib.sha256(http(self.url+'/large')).hexdigest()
        return dict(real_completed_flows=self.a.dataset_mib,response_sha256=digest,scope='real buffered HTTP flows retained by bounded addon')

    def release(self):
        write_control(self.control,'0');http(self.url)

    def verify(self):
        proof=self.proof();require(http(self.url)==BODY,'reverse proxy body mismatch');return proof


PRODUCTS={'etcd':EtcdProduct,'kafka':KafkaProduct,'mitmproxy':ProxyProduct}
