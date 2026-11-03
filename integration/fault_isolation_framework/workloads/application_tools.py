# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Allowlisted real-application jobs and count-preserving histogram readers."""
import json
import math
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
from .native_tools import bounded_process,parse_etcd


def validate_application(spec,host,ports):
    allowed={'application','url','rate','duration','start_monotonic','records','seed',
             'connections','warmup','baseline','hold','trace_margin','diagnostic'}
    if set(spec)!=allowed or spec.get('application') not in ('cache','etcd-sdk','etcd-reference'):
        raise ValueError('application job requires the complete fixed schema')
    route=urlsplit(spec['url'])
    if route.scheme!='http' or route.hostname!=host or route.port not in ports or route.username or route.password or route.path not in ('','/') or route.query or route.fragment:
        raise ValueError('destination outside configured application routes')
    for key in allowed-{'application','url','diagnostic'}:
        value=spec[key]
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
            raise ValueError('application budgets must be finite numbers')
    for key in ('rate','records','seed','connections'):
        if int(spec[key])!=spec[key]:raise ValueError('application counts must be integers')
    if not isinstance(spec['diagnostic'],bool):raise ValueError('diagnostic must be explicit boolean')
    if not 1<=spec['rate']<=50000 or not 20<=spec['duration']<=600 or not 1024<=spec['records']<=1000000 or not 0<=spec['seed']<=1000000 or not 2<=spec['connections']<=128:
        raise ValueError('application count/duration budget exceeded')
    if not 0<=spec['warmup']<=120 or not 5<=spec['baseline']<=180 or not 5<=spec['hold']<=180 or spec['warmup']+spec['baseline']+spec['hold']>spec['duration'] or not 1<=spec['trace_margin']<=10:
        raise ValueError('application phase/trace budget exceeded')
    if not time.monotonic()-.2<=spec['start_monotonic']<=time.monotonic()+60:
        raise ValueError('application start outside bounded horizon')


def histogram_metrics(histogram):
    bins=sorted((int(value),int(count)) for value,count in histogram.items())
    if any(value<0 or count<0 for value,count in bins):raise ValueError('negative histogram bucket')
    count=sum(n for _,n in bins)
    def tail(p,minimum):
        if count<minimum:return None
        target=math.ceil(count*p/100);seen=0
        for value,n in bins:
            seen+=n
            if seen>=target:return value/1000
    return dict(count=count,p95_ms=tail(95,100),p99_ms=tail(99,1000),p999_ms=tail(99.9,10000),
                max_ms=bins[-1][0]/1000 if bins else None,
                quantile_scope='upper bucket bound; merged counts, never averaged quantiles')


def merge_wrk_histograms(paths):
    result=dict(histograms={},slots={},overflow=0)
    for path in paths:
        header=False
        for line in Path(path).read_text().splitlines():
            fields=line.split(',')
            if fields[0]=='H' and len(fields)==5:
                if fields[1:4]!=['1','60000000','3']:raise ValueError('unexpected HDR geometry')
                result['overflow']+=int(fields[4]);header=True
            elif fields[0]=='C' and len(fields)==4:
                slot=int(fields[1]);count=int(fields[2]);errors=int(fields[3])
                if not 0<=slot<12 or min(count,errors)<0 or errors>count:raise ValueError('invalid HDR slot')
                row=result['slots'].setdefault(str(slot),dict(count=0,errors=0));row['count']+=count;row['errors']+=errors
            elif fields[0]=='B' and len(fields)==4:
                index,value,count=map(int,fields[1:])
                if not 0<=index<292 or value<0 or count<1:raise ValueError('invalid HDR bucket')
                histogram=result['histograms'].setdefault(str(index),{})
                histogram[str(value)]=histogram.get(str(value),0)+count
            else:raise ValueError('malformed native histogram artifact')
        if not header:raise ValueError('missing native histogram header')
    return result


def run_application(spec,root,stop,tools):
    """No command/path input comes from a job; tools are controller configuration."""
    root=Path(root);result=dict(kind=spec['application'],valid=False,errors=[])
    before=dict(monotonic=time.monotonic(),epoch=time.time())
    start_epoch=before['epoch']+spec['start_monotonic']-before['monotonic']
    capture=spec['start_monotonic']+spec['warmup']+spec['baseline']+2
    trace_begin=capture-spec['trace_margin'];trace_end=capture+3+spec['trace_margin']
    try:
        if stop.wait(max(0,spec['start_monotonic']-time.monotonic())):raise RuntimeError('cancelled before application start')
        if spec['application']=='cache':
            threads=min(4,int(spec['connections']))
            args=[tools['wrk2_measured'],'-t'+str(threads),'-c'+str(int(spec['connections'])),'-d%ds'%math.ceil(spec['duration']),
                  '-R'+str(int(spec['rate'])),'--latency','-s',tools['cache_lua'],spec['url'],'--']
            args += [str(spec[key]) for key in ('records','seed')]+[str(threads)]
            args += [str(spec[key]) for key in ('warmup','baseline','hold')]
            args += [str(spec['duration']-spec['warmup']-spec['baseline']-spec['hold']),str(start_epoch),
                     str(before['epoch']+trace_begin-before['monotonic']),str(before['epoch']+trace_end-before['monotonic']),str(root),str(int(spec['diagnostic']))]
            process=bounded_process(args,root,'application',stop,spec['duration']+15)
            text=(root/'application.stdout').read_text(errors='replace')
            matches=re.findall(r'BENCH_JSON (\{[^\n]+\})',text)
            if len(matches)!=1:raise ValueError('native verified response summary missing')
            counters=json.loads(matches[0]);histograms=merge_wrk_histograms(sorted(root.glob('hist-*.csv')))
            if len(list(root.glob('hist-*.csv')))!=threads:raise ValueError('native worker histogram missing')
            if sum(row['count'] for row in histograms['slots'].values())!=counters['checked']:raise ValueError('HDR response coverage differs from oracle count')
            if counters['checked']!=counters['requests']:raise ValueError('not every HTTP response verified')
            result.update(generator_parallelism=threads,counters=counters,**histograms,clock_scope='wrk2 native gettimeofday expected arrival; epoch/monotonic anchors checked')
            if histograms['overflow'] or counters['trace_overflow']:raise ValueError('measurement histogram/trace budget overflow')
        elif spec['application']=='etcd-reference':
            runs=[];total=math.ceil(spec['rate']*spec['duration'])
            if total>1000000:raise ValueError('official reference request budget exceeded')
            base=[tools['benchmark'],'--endpoints='+spec['url'],'--clients=8','--conns=2','--precise']
            summaries={}
            for name,command in [('put',base+['put','--total='+str(total),'--rate='+str(int(spec['rate'])),'--key-size=16','--val-size=256','--key-space-size=64','--sequential-keys']),('get',base+['range','/application/00000000','--total='+str(total),'--rate='+str(int(spec['rate']))])]:
                process=bounded_process(command,root,'official-'+name,stop,spec['duration']+30);runs.append(process)
                if process['returncode'] or process['cancelled'] or process['timed_out']:raise ValueError('official benchmark witness '+name+' failed')
                summaries[name]=parse_etcd((root/('official-'+name+'.stdout')).read_text())
            process=dict(returncode=0,cancelled=False,timed_out=False,cpu_seconds=sum(row['cpu_seconds'] for row in runs),peak_rss_bytes=max(row['peak_rss_bytes'] for row in runs))
            result.update(reference=summaries,runs=runs,generator_parallelism=8,measurement='official tool native RPC aggregates only; PUT256B unseededcrypto payload/keyspace64, GETactual64KiBkey0; notmixedSDKcapacity and notperrequesthistogram')
        else:
            args=[tools['etcd_sdk'],'--endpoint='+spec['url'],'--mode=load','--output='+str(root)]
            args += ['--'+flag+'='+str(spec[key]) for flag,key in [('records','records'),('rate','rate'),('duration','duration'),('start','start_monotonic'),('workers','connections'),('seed','seed'),('warmup','warmup'),('baseline','baseline'),('hold','hold')]]
            args+=['--diagnostic='+str(spec['diagnostic']).lower()]
            args+=['--trace-start='+str(trace_begin),'--trace-end='+str(trace_end)]
            process=bounded_process(args,root,'application',stop,spec['duration']+15)
            result.update(json.loads((root/'sdk-result.json').read_text()));result['generator_parallelism']=4
            validate_sdk_result(result,math.ceil(spec['rate']*spec['duration']))
            if result['trace_overflow']:raise ValueError('SDK trace budget overflow')
        result['process']=process
        if process['returncode'] or process['timed_out'] or process['cancelled']:raise RuntimeError('application tool failed/cancelled/timed out')
        result['valid']=True
    except Exception as exc:result['errors'].append(repr(exc))
    after=dict(monotonic=time.monotonic(),epoch=time.time());result.update(clock_before=before,clock_after=after)
    result['trace_window_monotonic']=dict(begin=trace_begin,end=trace_end)
    result['epoch_clock_drift_seconds']=(after['epoch']-after['monotonic'])-(before['epoch']-before['monotonic'])
    if abs(result['epoch_clock_drift_seconds'])>.02:
        result['valid']=False;result['errors'].append('native epoch clock moved beyond20ms')
    result['measurement_protocol_valid']=result['valid']
    result['method']=('instrumented pinned wrk2 native HDR + full body oracle' if spec['application']=='cache' else ('official etcd benchmark aggregate reference' if spec['application']=='etcd-reference' else 'custom fixed-arrival official clientv3 SDK'))
    result['request_recipe']=('official independent PUT256B/keyspace64 and GETactualkey0/64KiB; aggregatesonly' if spec['application']=='etcd-reference' else ('GET70/SET20/DELETE_REPLACE10' if spec['application']=='cache' else 'native GET70/PUT30; one SDK invocation each, transparent transport retries possible/unmeasured; fullGETbytes/revisionACK; independent paginated readback outside timed windows'))+'; full keyspace80/20 hotspot; 90%1KiB/10%64KiB'
    (root/'application-result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def business_quality(native,windows,throughput_tolerance=.02):
    errors=[];counters=native.get('counters',{})
    for key in ('body_errors','timeouts','connect_errors','read_errors','write_errors','status_errors','queue_full','rpc_errors','protocol_errors','cancelled'):
        if counters.get(key,0):errors.append('%s=%d (whole native job)'%(key,counters[key]))
    maintenance_errors=sum(bool(row.get('error')) for row in native.get('maintenance',[]))
    if maintenance_errors:errors.append('MVCCmaintenance_errors=%d'%maintenance_errors)
    for name,window in windows.items():
        if window['response_errors']:errors.append('%s response_errors=%d'%(name,window['response_errors']))
        if not window['requests']:errors.append(name+' has no response samples')
        if abs(window['success_rps']/window['offered_rps']-1)>throughput_tolerance:
            errors.append(name+' actual success throughput differs from fixed offered rate')
    return dict(valid=not errors,errors=errors,scope='business quality, separate from measurement protocol/capture validity',
                throughput_tolerance=throughput_tolerance)


def validate_sdk_result(result,expected):
    counters=result.get('counters',{});required={'requests','timeouts','body_errors','queue_full','rpc_errors','protocol_errors','cancelled'}
    if not required.issubset(counters) or any(not isinstance(counters[key],int) or isinstance(counters[key],bool) or counters[key]<0 for key in required):
        raise ValueError('SDK error counters missing/invalid; unsupported is not zero')
    count=sum(row['count'] for key,row in result['metrics'].items() if not key.startswith('window:'))
    errors=sum(row['errors'] for key,row in result['metrics'].items() if not key.startswith('window:'))
    if result.get('cancelled') or count!=expected or counters['requests']!=expected or sum(counters[key] for key in required-{'requests'})!=errors:
        raise ValueError('SDK terminal-arrival/error coverage differs from fixed budget')
