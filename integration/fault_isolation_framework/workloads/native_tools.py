# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Fixed native tool recipes. Native histograms never become request rows."""
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit


def validate_native(spec,host,ports):
    allowed={'native','url','rate','duration','start_monotonic','records','connections'}
    if set(spec)-allowed:raise ValueError('unsupported native fields')
    if spec.get('native') not in ('etcd','kafka','mitmproxy'):raise ValueError('unsupported native recipe')
    u=urlsplit(spec['url'])
    if u.scheme!='http' or u.hostname!=host or u.port not in ports or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
        raise ValueError('destination is outside configured native routes')
    for name in ('rate','duration','start_monotonic','records','connections'):
        v=spec[name]
        if not isinstance(v,(int,float)) or isinstance(v,bool) or not math.isfinite(v):raise ValueError('native budget must be finite')
    if not 1<=spec['rate']<=50000 or not 20<=spec['duration']<=600 or not 1<=spec['records']<=1000000 or not 1<=spec['connections']<=128:
        raise ValueError('native rate/duration/record/connection budget exceeded')
    if int(spec['rate'])!=spec['rate'] or int(spec['records'])!=spec['records'] or int(spec['connections'])!=spec['connections']:
        raise ValueError('native counts must be integers')
    if not time.monotonic()-.2<=spec['start_monotonic']<=time.monotonic()+60:raise ValueError('native start outside budget')
    if spec['records']!=math.ceil(spec['rate']*spec['duration']):raise ValueError('native record budget must match rate and duration')


def bounded_process(command,root,name,stop,timeout):
    """wait4 reports child-tool CPU/RSS; killpg also stops script descendants."""
    root=Path(root);begin=time.monotonic()
    with (root/(name+'.stdout')).open('xb') as out,(root/(name+'.stderr')).open('xb') as err:
        process=subprocess.Popen(command,stdout=out,stderr=err,start_new_session=True)
        cancelled=False;timed_out=False;sent=None
        while True:
            pid,status,usage=os.wait4(process.pid,os.WNOHANG)
            if pid:break
            now=time.monotonic()
            if stop.is_set() or now-begin>timeout:
                cancelled=stop.is_set();timed_out=now-begin>timeout
                if sent is None:
                    os.killpg(process.pid,signal.SIGTERM);sent=now
                elif now-sent>2:
                    try:os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
            time.sleep(.03)
        process.returncode=os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
        # A launcher can exit while a descendant survives; a dedicated group is owned.
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    result=dict(command=command,pid=process.pid,begin=begin,end=time.monotonic(),
                returncode=process.returncode,cancelled=cancelled,timed_out=timed_out,
                cpu_seconds=usage.ru_utime+usage.ru_stime,peak_rss_bytes=usage.ru_maxrss*1024,
                resource_scope='wait4 child and reaped descendants; maxrss is maximum process, not simultaneous tree sum')
    (root/(name+'.process.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result


def parse_etcd(text):
    rate=re.search(r'Requests/sec:\s*([\d.eE+-]+)',text)
    tails={p:re.search(r'\b%s%% in\s+([\d.eE+-]+) secs'%p,text) for p in (95,99)}
    if not rate or not all(tails.values()) or float(rate[1])<=0:raise ValueError('missing etcd native histogram/rate')
    if 'Error distribution:' in text:raise ValueError('etcd benchmark reported request errors')
    return dict(ops_s=float(rate[1]),p95_ms=float(tails[95][1])*1000,p99_ms=float(tails[99][1])*1000,
                errors=0,measurement='native RPC aggregate')


def parse_kafka(text):
    pattern=r'(\d+) records sent, ([\d.]+) records/sec \(([\d.]+) MB/sec\), ([\d.]+) ms avg latency, ([\d.]+) ms max latency, ([\d.]+) ms 50th, ([\d.]+) ms 95th, ([\d.]+) ms 99th'
    matches=list(re.finditer(pattern,text))
    if not matches or int(matches[-1][1])<=0:raise ValueError('missing Kafka producer final summary')
    m=matches[-1]
    return dict(records=int(m[1]),records_s=float(m[2]),mb_s=float(m[3]),ack_p95_ms=float(m[7]),ack_p99_ms=float(m[8]),
                errors=0,measurement='native producer acknowledgement aggregate; tool samples tails')


def tested_capacity(trials,slo,repeats):
    if slo is None:return dict(status='NOT_EVALUATED',highest_tested_rate=None)
    rates=sorted({t['rate'] for t in trials});accepted=[]
    for rate in rates:
        chosen=[t for t in trials if t['rate']==rate]
        expected={(g,r) for g in ('B','D') for r in range(repeats)}
        if {(t['group'],t['repeat']) for t in chosen}!=expected:continue
        if all(t['valid'] and t['metrics'].get('p99_ms') is not None and t['metrics']['p99_ms']<=slo for t in chosen):accepted.append(rate)
    return dict(status='TESTED_RATES_ONLY',slo_p99_ms=slo,highest_tested_rate=max(accepted,default=None),tested_rates=rates)


WRK_SCRIPT='''local threads = {}
local counter = 0
function setup(thread)
  thread:set("bad", 0)
  thread:set("checked", 0)
  table.insert(threads, thread)
end
function response(status, headers, body)
  checked = checked + 1
  if status ~= 200 or body ~= string.rep("huatuo-business-body\\n", 64) then bad = bad + 1 end
end
function done(summary, latency, requests)
  local bad_total, checked_total = 0, 0
  for _, thread in ipairs(threads) do
    bad_total = bad_total + thread:get("bad")
    checked_total = checked_total + thread:get("checked")
  end
  io.write(string.format("NATIVE_JSON {\\"requests\\":%d,\\"checked\\":%d,\\"body_errors\\":%d,\\"p95_ms\\":%.6f,\\"p99_ms\\":%.6f,\\"duration_us\\":%d,\\"timeouts\\":%d,\\"socket_errors\\":%d,\\"status_errors\\":%d}\\n", summary.requests, checked_total, bad_total, latency:percentile(95)/1000, latency:percentile(99)/1000, summary.duration, summary.errors.timeout, summary.errors.connect+summary.errors.read+summary.errors.write, summary.errors.status))
end
'''


def run_native(spec,root,stop,tools):
    root=Path(root);kind=spec['native'];url=spec['url'];rate=int(spec['rate']);records=int(spec['records'])
    runs=[];result=dict(kind=kind,valid=False,errors=[],runs=runs)
    def invoke(name,command,timeout=None):
        row=bounded_process(command,root,name,stop,timeout or spec['duration']+45);runs.append(row)
        text=(root/(name+'.stdout')).read_text(errors='replace')
        if row['returncode'] or row['cancelled'] or row['timed_out']:raise RuntimeError(name+' exited/cancelled/timed out')
        return text
    try:
        if stop.wait(max(0,spec['start_monotonic']-time.monotonic())):raise RuntimeError('native job cancelled before start')
        if kind=='etcd':
            benchmark=tools['benchmark'];base=[benchmark,'--endpoints='+url,'--clients='+str(spec['connections']),'--conns=2','--precise']
            put=parse_etcd(invoke('etcd-put',base+['put','--total='+str(records),'--rate='+str(rate),'--key-size=16','--val-size=256','--key-space-size=64','--sequential-keys']))
            get=parse_etcd(invoke('etcd-get',base+['range','/correctness/000000','--total='+str(records),'--rate='+str(rate)]))
            result.update(metrics=dict(put_ops_s=put['ops_s'],get_ops_s=get['ops_s'],p95_ms=max(put['p95_ms'],get['p95_ms']),p99_ms=max(put['p99_ms'],get['p99_ms']),errors=0),put=put,get=get,
                          payload_scope='PUT crypto-random 256B values are unseeded; keyspace/size/rate/distribution matched. Known-input CRUD prefix checked independently; GET uses deterministic seeded 1MiB value')
        elif kind=='kafka':
            kafka=Path(tools['kafka']);endpoint=urlsplit(url).netloc;topic='native-'+root.name
            invoke('kafka-topic',[str(kafka/'bin/kafka-topics.sh'),'--bootstrap-server',endpoint,'--create','--topic',topic,'--partitions','1','--replication-factor','1'],30)
            producer=invoke('kafka-producer',[str(kafka/'bin/kafka-producer-perf-test.sh'),'--topic',topic,'--num-records',str(records),'--payload-monotonic','--throughput',str(rate),'--producer-props','bootstrap.servers='+endpoint,'acks=all','retries=0','enable.idempotence=false','max.block.ms=10000','delivery.timeout.ms=30000','request.timeout.ms=10000'])
            stats=parse_kafka(producer)
            if stats['records']!=records:raise ValueError('producer acknowledged record count mismatch')
            stderr=(root/'kafka-producer.stderr').read_text(errors='replace')
            if 'Exception' in stderr or 'ERROR' in stderr:raise ValueError('producer reported errors')
            consumer=invoke('kafka-consumer',[str(kafka/'bin/kafka-consumer-perf-test.sh'),'--bootstrap-server',endpoint,'--topic',topic,'--messages',str(records),'--group','perf-native','--timeout','15000'])
            consumer_lines=[line for line in consumer.splitlines() if re.match(r'\d{4}-',line)]
            if not consumer_lines:raise ValueError('Kafka consumer summary missing')
            fields=[v.strip() for v in consumer_lines[-1].split(',')]
            if len(fields)<6 or int(fields[4])!=records:raise ValueError('Kafka consumer count mismatch')
            consumer_metrics=dict(records=int(fields[4]),mb_s=float(fields[3]),records_s=float(fields[5]))
            # Fresh topic; independent full readback checks IDs, duplicates and order.
            lag=invoke('kafka-group-lag',[str(kafka/'bin/kafka-consumer-groups.sh'),'--bootstrap-server',endpoint,'--describe','--group','perf-native'],30)
            result['consumer_group_lag_raw']=lag
            lag_rows=[line.split() for line in lag.splitlines() if line.startswith('perf-native') and topic in line]
            if not lag_rows or any(not row[5].isdigit() for row in lag_rows):raise ValueError('Kafka consumer committed lag unavailable')
            lag_records=sum(int(row[5]) for row in lag_rows)
            result['consumer_group_lag_records']=lag_records
            if lag_records:raise ValueError('Kafka consumer group did not reach acknowledged end')
            raw=invoke('kafka-readback',[str(kafka/'bin/kafka-console-consumer.sh'),'--bootstrap-server',endpoint,'--topic',topic,'--from-beginning','--max-messages',str(records),'--timeout-ms','15000','--consumer-property','group.id=verify-native'],spec['duration']+45)
            ids=raw.splitlines()
            if ids!=[str(i) for i in range(records)]:raise ValueError('Kafka message ID/count/order mismatch')
            result.update(metrics=dict(records_s=stats['records_s'],mb_s=stats['mb_s'],p95_ms=stats['ack_p95_ms'],p99_ms=stats['ack_p99_ms'],consumer_records_s=consumer_metrics['records_s'],consumer_mb_s=consumer_metrics['mb_s'],errors=0),producer=stats,consumer=consumer_metrics,consumer_raw=consumer,
                          correctness=dict(records=records,ordered_unique_ids=True,sha256=hashlib.sha256(raw.encode()).hexdigest(),lag_records=0,lag_scope='readback reached acknowledged end; consumer performance group lag separately retained'))
        else:
            script=root/'verify.lua';script.write_text(WRK_SCRIPT)
            text=invoke('wrk2',[tools['wrk2'],'-t2','-c'+str(spec['connections']),'-d%ds'%spec['duration'],'-R'+str(rate),'--latency','-s',str(script),url])
            matches=re.findall(r'NATIVE_JSON (\{[^\n]+\})',text)
            if len(matches)!=1:raise ValueError('wrk2 verified body/histogram summary missing')
            stats=json.loads(matches[0]);errors=sum(stats[k] for k in ('timeouts','socket_errors','status_errors','body_errors'))
            if errors or stats['requests']<=0 or stats['checked']!=stats['requests']:raise ValueError('wrk2 request/body/timeout failure')
            result.update(metrics=dict(rps=stats['requests']/(stats['duration_us']/1e6),p95_ms=stats['p95_ms'],p99_ms=stats['p99_ms'],errors=errors),http=stats)
        result['valid']=True
    except Exception as exc:result['errors'].append(repr(exc))
    result.update(cpu_seconds=sum(r['cpu_seconds'] for r in runs),peak_process_rss_bytes=max((r['peak_rss_bytes'] for r in runs),default=0))
    (root/'native-result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
