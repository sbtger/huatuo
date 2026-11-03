# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real app B-only capacity/pressure calibration and one-round B/C costs."""
import gzip
import hashlib
import json
import math
import os
import random
import threading
import time
from pathlib import Path
from ...core.evidence import EvidenceStore
from ...core.performance import distribution
from ...core.util import require,write_control
from ...environments.performance import PerformanceSampler,resource_metrics
from ...environments.remote_load import RemoteLoad
from ...environments.linux import identity
from ...workloads.application_workloads import ApplicationWorkload,finish_owned_database
from ...workloads.application_tools import histogram_metrics,business_quality
from ...workloads.application_protocol import capacity_state,frozen_rates,bracket_capacity,validate_frozen_profile,capacity_probe_state
from ...workloads.resident_kv import freeze_plan,replay_fill,replay_candidate,canonical_fill_recipe
from .resident_performance import ScopedProcess,ResidentAdapter,helper_resources,memory_window,capture_rows,finalize_trial,validate_captures
from .discovery import parse_timestamp


class ApplicationAdapter(ResidentAdapter):
    workload_factory=ApplicationWorkload
    def cleanup(self):
        clean=False
        try:super().cleanup();clean=True
        finally:
            kv=getattr(self,'kv',None)
            if kv and hasattr(kv,'database'):
                finish_owned_database(kv.database,kv.database_marker,self.out,clean and kv.allow_db_cleanup,kv.last_digest)

    def prepare(self,group):
        super().prepare(group)
        path=self.out/'environment.json';value=json.loads(path.read_text())
        value.update(application=self.a.application,business_objects='actual etcd KV or Spring/FastAPI Record/map/list graph,1KiB/64KiB values; no filler',
                     pressure_scope='business cgroup usage, including actual service pagecache; runtime heap reported separately')
        path.write_text(json.dumps(value,indent=2)+'\n')


def merge_bins(histograms):
    result={}
    for histogram in histograms:
        for value,count in histogram.items():result[str(value)]=result.get(str(value),0)+int(count)
    return result


def load_windows(native,windows,rate):
    result={};wrk=native['kind']=='cache'
    operations=('GET','SET','DELETE_REPLACE') if wrk else ('GET','PUT')
    for phase,name,duration in windows:
        endpoints={};all_lat=[];all_lag=[]
        for index,operation in enumerate(operations):
            if wrk:
                slot=str(phase*3+index);counts=native['slots'].get(slot,dict(count=0,errors=0))
                latency=native['histograms'].get(str((phase*3+index)*3),{})
                lag=native['histograms'].get(str((phase*3+index)*3+2),{})
            else:
                counts=native['metrics'].get(str(phase)+':'+operation,dict(count=0,errors=0,latency_us={},lag_us={}))
                latency=counts['latency_us'];lag=counts['lag_us']
            all_lat.append(latency);all_lag.append(lag)
            endpoints[operation]=dict(requests=counts['count'],response_errors=counts['errors'],
                                     error_classes=counts.get('error_kinds') if not wrk else None,success_rps=(counts['count']-counts['errors'])/duration,
                                     scheduled_latency=histogram_metrics(latency),dispatch_lag=histogram_metrics(lag))
        result[name]=dict(endpoints=endpoints,requests=sum(row['requests'] for row in endpoints.values()),
                          response_errors=sum(row['response_errors'] for row in endpoints.values()),
                          success_rps=sum(row['success_rps'] for row in endpoints.values()),offered_rps=rate,
                          scheduled_latency=histogram_metrics(merge_bins(all_lat)),dispatch_lag=histogram_metrics(merge_bins(all_lag)))
    return result


def subwindow(native,start,end,kind):
    histograms=[]
    for index in range(math.ceil(start/5),math.floor(end/5)):
        if native['kind']=='cache':histograms.append(native['histograms'].get(str(36+index*2+(1 if kind=='lag' else 0)),{}))
        else:histograms.append(native['metrics'].get('window:'+str(index),{}).get('lag_us' if kind=='lag' else 'latency_us',{}))
    return histogram_metrics(merge_bins(histograms))


def read_timeline(directory,native,offset):
    rows=[];anchor=native['clock_before'];epoch_offset=anchor['monotonic']-anchor['epoch']+offset
    for path in sorted(Path(directory).glob('trace-*.jsonl.gz')):
        with gzip.open(path,'rt') as stream:
            for line in stream:
                if len(line)>16384:raise ValueError('oversized request timeline record')
                row=json.loads(line)
                for key in ('scheduled','sent','ended'):
                    epoch_key=key+'_epoch'
                    if epoch_key in row:
                        row['remote_'+epoch_key]=row[epoch_key];row[key]=row[epoch_key]+epoch_offset if row[epoch_key] is not None else None
                    elif row.get(key) is not None:
                        row['remote_'+key]=row[key];row[key]+=offset
                rows.append(row)
    return rows


def execute(args,directory,group,pressure,fill_plan,rate,probe=False,diagnostic=False,existing=None,memory_diagnostic=False):
    evidence=EvidenceStore(directory);owner=existing or ApplicationAdapter(args,evidence);trial_out=evidence.output;diagnostic_process=None;sampler=None;remote=None;observer=None;stop=threading.Event()
    outcome=dict(group=group,pressure_percent=pressure,rate=rate,probe=probe,diagnostic=diagnostic,valid=False,errors=[],captures=[],metrics={},pressure_samples=[],phase_stats={})
    warmup=args.warmup;baseline=args.baseline;hold=5 if probe else args.hold;recovery=0 if probe else args.recovery
    duration=warmup+baseline+hold+recovery;capturing=group=='C' and not probe
    try:
        available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))*1024
        if existing is None:require(available>(args.memory_limit_mib<<20)+(768<<20),'VM lacks bounded business/collector memory headroom')
        if existing is None:
            owner.prepare(group);replay_fill(fill_plan,owner.kv.fill);owner.kv.freeze();owner.start_agent();owner.start_helper()
        if memory_diagnostic:
            require(args.application_diagnostic and group=='B','resource increment only permitted in isolated DIAGNOSTIC owner')
            scope=owner.scope_directories[0]/'diagnostic';scope.mkdir();(scope/'memory.limit_in_bytes').write_text(str(128<<20))
            owner.scope_directories.append(scope);owner.memory_scopes['diagnostic']=scope
            diagnostic_process=ScopedProcess(scope)
        before=owner.kv.verify();target=owner.targets[0];outcome['before']=before
        sampler=PerformanceSampler(owner,trial_out/'resources.jsonl',args.sample_interval);sampler.start()
        remote=RemoteLoad(args.load_controller_url,args.load_token_file,trial_out,args.max_clock_error);remote.calibrate()
        start=time.monotonic()+3;anchor=dict(monotonic=time.monotonic(),epoch=time.time());outcome.update(start=start,clock_anchor=anchor,fill_plan=fill_plan)
        def observe():
            try:
                for offset,name in [(warmup,'baseline'),(warmup+baseline,'capture'),(warmup+baseline+hold,'recovery')]:
                    if stop.wait(max(0,start+offset-time.monotonic())):return
                    outcome['phase_stats'][name]=dict(time=time.monotonic(),stats=owner.kv.stats(),memory=owner.kv.memory())
                    if name=='capture':
                        for _ in range(5):
                            outcome['pressure_samples'].append(owner.kv.memory()['current_bytes'])
                            if stop.wait(.25):return
                        outcome['frozen_pressure']=freeze_plan(fill_plan['records'],fill_plan['limit_bytes'],pressure,outcome['pressure_samples'],args.pressure_tolerance)
                        if memory_diagnostic:
                            if stop.wait(max(0,start+offset+2-time.monotonic())):return
                            code='import time; b=bytearray(32<<20); b[::4096]=bytes([1])*(len(b)//4096); print("DIAGNOSTIC_READY",flush=True); time.sleep(3)'
                            diagnostic_process.start(['/usr/bin/python3','-c',code],trial_out/'memory-diagnostic.log',dict(os.environ))
                            if stop.wait(3.5):return
                            diagnostic_process.stop()
                        if capturing:
                            if stop.wait(max(0,start+offset+2-time.monotonic())):return
                            require(identity(target['pid'])==target['identity'],'snapshot target identity changed')
                            write_control(owner.snapshot_control,json.dumps(dict(id=1,pid=target['pid'],start_ticks=target['identity'][1])))
                            outcome['capture_command']=dict(monotonic=time.monotonic(),pid=target['pid'],start_ticks=target['identity'][1])
                            deadline=time.monotonic()+args.capture_timeout+15
                            while not any(row['id']==1 for row in capture_rows(owner)):
                                if stop.wait(.02):return
                                require(time.monotonic()<deadline,'snapshot response deadline exceeded')
            except Exception as exc:outcome['errors'].append('phase observer: '+repr(exc))
        observer=threading.Thread(target=observe,daemon=True);observer.start()
        spec=dict(application='etcd-sdk' if args.application=='etcd' else 'cache',url='http://%s:%d'%(args.load_target_host,args.load_target_base_port),rate=rate,duration=duration,start_monotonic=start,records=fill_plan['records'],seed=args.seed,connections=args.workers,warmup=warmup,baseline=baseline,hold=hold,trace_margin=4,diagnostic=diagnostic)
        native=remote.run_native(spec);outcome['native']=native
        observer.join(args.capture_timeout+20);require(not observer.is_alive(),'phase observer stuck')
        outcome['phase_stats']['end']=dict(time=time.monotonic(),stats=owner.kv.stats(),memory=owner.kv.memory())
        outcome['after']=owner.kv.verify();require(identity(target['pid'])==target['identity'],'business lifetime changed')
        windows=[(1,'baseline',baseline),(2,'capture',hold)]+([(3,'recovery',recovery)] if recovery else [])
        loads=load_windows(native,windows,rate);outcome['windows']={}
        begin=start+warmup
        for _,name,seconds in windows:
            end=begin+seconds;resources=resource_metrics(sampler.rows,begin,end);helper=helper_resources(sampler.rows,begin,end);memory=memory_window(sampler.rows,begin,end,target['id'])
            samples=[row['business_memory'][target['id']]['current_bytes'] for row in sampler.rows if begin<=row['time']<end]
            outcome['windows'][name]=dict(role='UNMEASURED_PROBE_PADDING' if probe and name!='baseline' else 'MEASURED_BUSINESS_PHASE',begin=begin,end=end,load=loads[name],resources=resources,helper_resources=helper,memory=memory,
                                         pressure=dict(min_percent=min(samples)*100/fill_plan['limit_bytes'],max_percent=max(samples)*100/fill_plan['limit_bytes']))
            prefix=name+'.';outcome['metrics'].update({prefix+'rps':loads[name]['success_rps'],prefix+'p99_ms':loads[name]['scheduled_latency']['p99_ms'],prefix+'p999_ms':loads[name]['scheduled_latency']['p999_ms'],prefix+'business_peak_bytes':memory['business']['sampled_peak_bytes'],prefix+'business_peak_above_baseline_bytes':memory['business']['peak_above_baseline_bytes'],prefix+'collector_peak_bytes':memory['collector_simultaneous_sampled_peak_bytes'],prefix+'collector_peak_above_baseline_bytes':memory['collector_peak_above_baseline_bytes'],prefix+'collector_cpu_seconds':helper['cpu_seconds'],prefix+'collector_total_cpu_seconds':helper['cpu_seconds']+resources['cpu_seconds'],prefix+'agent_cpu_seconds':resources['cpu_seconds']})
            for scope in ('agent','helper','worker-0','worker-1'):
                stats=memory['scopes'].get(scope)
                for key in ('sampled_peak_bytes','peak_above_baseline_bytes','lifetime_high_water_increase_bytes','oom_kills_delta','allocation_failures_delta'):
                    outcome['metrics'][prefix+scope+'.'+key]=stats.get(key) if stats else None
            for key in ('oom_kills_delta','allocation_failures_delta'):
                outcome['metrics'][prefix+'business.'+key]=memory['business'][key]
            require(not resources['errors'],'resource sample errors: '+repr(resources['errors']));begin=end
        width=baseline/3
        first=subwindow(native,warmup,warmup+width,'latency');last=subwindow(native,warmup+baseline-width,warmup+baseline,'latency')
        first_lag=subwindow(native,warmup,warmup+width,'lag');last_lag=subwindow(native,warmup+baseline-width,warmup+baseline,'lag')
        counters=native.get('counters',{});whole_job_errors=sum(counters.get(key,0) for key in ('timeouts','connect_errors','read_errors','write_errors','status_errors','body_errors','queue_full','rpc_errors','protocol_errors','cancelled'))
        client_meta=json.loads((trial_out/'remote-load.json').read_text())
        probe_summary=dict(offered_rps=rate,success_rps=loads['baseline']['success_rps'],errors=max(loads['baseline']['response_errors'],whole_job_errors)+sum(bool(row.get('error')) for row in native.get('maintenance',[])),timeouts=counters.get('timeouts',0),body_errors=counters.get('body_errors',0),trace_overflow=counters.get('trace_overflow',0),client_cpu_cores=(native['process']['cpu_seconds']+client_meta.get('cpu_seconds',0))/duration,client_cores=min(native['generator_parallelism'],client_meta['clock_before']['health']['cpu_count']),initial_p99_ms=first['p99_ms'],final_p99_ms=last['p99_ms'],initial_backlog_ms=first_lag['p99_ms'],final_backlog_ms=last_lag['p99_ms'])
        outcome['capacity_probe']=dict(probe_summary,decision=capacity_state(probe_summary),scope='baseline60s throughput/tails only; all-job errors gate, raw categories authoritative (HTTP events may overlap); clientCPU whole job inclnative child')
        rows=read_timeline(trial_out,native,remote.clock['offset']);outcome['timeline_scope']='complete records near planned capture±timeout margin plus every error; all-response HDR elsewhere'
        for name,window in outcome['windows'].items():
            window['load']['transport_error_events']={}
            for row in rows:
                if row.get('transport_error') and row.get('scheduled') is not None and window['begin']<=row['scheduled']<window['end']:
                    endpoint=row.get('operation','UNKNOWN');counts=window['load']['transport_error_events'].setdefault(endpoint,{})
                    counts[row['transport_error']]=counts.get(row['transport_error'],0)+1
            window['load']['transport_error_scope']='native events retained; repeated timeout callbacks may concern one request; unassigned connection events remain whole-job counters'
        uncertainty=client_meta['clock_before']['rtt']/2+client_meta['clock_after']['rtt']/2+abs(client_meta['clock_after']['offset']-client_meta['clock_before']['offset'])+abs(native['epoch_clock_drift_seconds'])
        outcome['active_capture_windows']=[];outcome['captures']=capture_rows(owner)
        for capture in outcome['captures']:
            begin=parse_timestamp(capture['started']).timestamp()-anchor['epoch']+anchor['monotonic'];end=parse_timestamp(capture['ended']).timestamp()-anchor['epoch']+anchor['monotonic']
            definite=[row for row in rows if row.get('scheduled') is not None and begin+uncertainty<=row['scheduled']<end-uncertainty]
            possible=[row for row in rows if row.get('sent') is not None and row['sent']-uncertainty<=end and row['ended']+uncertainty>=begin]
            active=dict(begin=begin,end=end,wall_ms=capture['wall_ms'],clock_uncertainty_ms=uncertainty*1000,resolution_limited=2*uncertainty>=end-begin,definite_scheduled_count=len(definite),latency_ms=distribution([(row['ended']-row['scheduled'])*1000 for row in definite if row['ok']]),possible_inflight_count=len(possible),errors=sum(not row['ok'] for row in possible))
            trace=native['trace_window_monotonic'];complete_trace=begin-uncertainty>=trace['begin']+remote.clock['offset'] and end+uncertainty<=trace['end']+remote.clock['offset']
            active['interval_trace_complete']=complete_trace
            if not complete_trace:
                active['observed_rows_in_incomplete_interval']=len(definite);active['definite_scheduled_count']=None;active['latency_ms']=None
                active['scope']='partial raw coverage; interval tails unavailable, no full active-window latency claim'
            outcome['active_capture_windows'].append(active)
            (trial_out/'active-capture-requests.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in possible))
        outcome['measurement_protocol_valid']=not outcome['errors']
        outcome['capture_quality_errors']=validate_captures(outcome['captures'],target,1 if capturing else 0)
        outcome['business_quality']=business_quality(native,loads,throughput_windows={'baseline'} if probe else None)
        outcome['errors']+=outcome['capture_quality_errors']+['business quality: '+error for error in outcome['business_quality']['errors']]
        outcome['valid']=not outcome['errors']
        if existing is None:owner.kv.allow_db_cleanup=outcome['valid']
    except Exception as exc:outcome['errors'].append(repr(exc))
    finally:
        stop.set()
        if remote:
            try:remote.cancel()
            except Exception as exc:outcome['errors'].append('remote cleanup: '+repr(exc))
        if observer and observer.is_alive():observer.join(args.capture_timeout+20)
        if diagnostic_process:
            try:diagnostic_process.stop()
            except Exception as exc:outcome['errors'].append('diagnostic cleanup: '+repr(exc))
        if sampler and not sampler.stream.closed:
            try:sampler.close()
            except Exception as exc:outcome['errors'].append('sampler cleanup: '+repr(exc))
        if existing is None:finalize_trial(owner,outcome,evidence)
        else:
            outcome['valid']=outcome['valid'] and not outcome['errors'];evidence.save(outcome)
    return outcome



def profile_identity(args):
    source=Path(__file__).resolve().parents[2];digest=hashlib.sha256()
    for path in sorted(source.rglob('*')):
        if path.is_file() and path.suffix in ('.py','.go','.java','.lua','.h','.xml','.mod','.sum') and '__pycache__' not in path.parts:
            digest.update(str(path.relative_to(source)).encode()+b'\0'+hashlib.sha256(path.read_bytes()).digest())
    toolroot=Path(args.application_tools)
    product={'etcd':toolroot/'etcd/etcd','spring':toolroot/'spring-cache/target/spring-cache-1.0.0.jar','fastapi':source/'workloads/applications/fastapi_cache.py'}[args.application]
    result={key:getattr(args,key) for key in ('application','seed','workers','business_cpus','memory_limit_mib','warmup','baseline','hold','recovery','capture_timeout','top_k','sample_interval','pressure_tolerance')}
    result.update(source_sha256=digest.hexdigest(),product_sha256=hashlib.sha256(product.read_bytes()).hexdigest(),snapshot_helper_sha256=hashlib.sha256(Path(args.snapshot_helper).read_bytes()).hexdigest(),agent_build=json.loads((Path(args.build)/'build.json').read_text()),java_heap_profile='fixed85percent-minus64MiB normalG1')
    return result

def calibrate(args,output,pressure):
    evidence=EvidenceStore(output);owner=ApplicationAdapter(args,evidence)
    try:
        owner.prepare('B')
        if args.application=='etcd':
            owner.kv.fill(1024)
            reference=RemoteLoad(args.load_controller_url,args.load_token_file,evidence.output/'official-reference',args.max_clock_error)
            try:
                reference.calibrate();reference.run_native(dict(application='etcd-reference',url='http://%s:%d'%(args.load_target_host,args.load_target_base_port),rate=100,duration=20,start_monotonic=time.monotonic()+3,records=1024,seed=args.seed,connections=8,warmup=0,baseline=5,hold=5,trace_margin=4,diagnostic=False))
            finally:reference.cancel()
        provisional=owner.kv.calibrate(pressure);proof=owner.kv.verify();owner.kv.allow_db_cleanup=True
    finally:owner.cleanup()
    (evidence.output/'provisional.json').write_text(json.dumps(dict(plan=provisional,proof=proof),indent=2)+'\n')
    candidate=dict(provisional,frozen=False);rounds=[]
    for round_index in range(3):
        candidate['fill_recipe']=canonical_fill_recipe(candidate['records'])
        replicas=[]
        for index in range(2):
            write_control(evidence.output.parent/'progress.json',json.dumps(dict(phase='pressure-%d-round-%d-replica-%d'%(pressure,round_index,index),started=time.monotonic())))
            replicas.append(execute(args,evidence.output/('pressure-round-%d-replica-%d'%(round_index,index)),'B',pressure,candidate,int(args.capacity_rates.split(',')[0]),probe=True))
        # Boundary pressure checks may be outside the band during calibration;
        # load validity and all real baseline samples decide bounded refinement.
        checked=[]
        for row in replicas:
            load=row.get('capacity_probe',{}).get('decision',{}).get('state')
            errors=[error for error in row['errors'] if 'outside pressure band' not in error]
            checked.append(dict(valid=load=='STABLE_TESTED_RATE' and not errors,pressure_samples=row['pressure_samples']))
        decision=replay_candidate(candidate['records'],candidate['limit_bytes'],pressure,args.pressure_tolerance,checked)
        rounds.append(dict(round=round_index,records=candidate['records'],replicas=[str(evidence.output/('pressure-round-%d-replica-%d'%(round_index,index))) for index in range(2)],decision=decision))
        (evidence.output/'pressure-preflights.json').write_text(json.dumps(rounds,indent=2)+'\n')
        if decision['status']=='FROZEN':candidate.update(frozen=True,preflight_observed_percent=decision['observed_percent']);break
        require(decision['status']=='REFINE','B-only pressure calibration '+decision['status']+': '+decision['reason']);candidate['records']=decision['records']
    require(candidate['frozen'],'B-only pressure unreachable after3predetermined rounds')
    probes=[];shared_evidence=EvidenceStore(evidence.output/'capacity-shared-business');shared=ApplicationAdapter(args,shared_evidence)
    try:
        shared.prepare('B');replay_fill(candidate,shared.kv.fill);shared.kv.freeze();shared.start_agent();shared.start_helper()
        def probe(rate):
            write_control(evidence.output.parent/'progress.json',json.dumps(dict(phase='capacity-%d-%d'%(pressure,rate),started=time.monotonic())))
            row=execute(args,evidence.output/('capacity-%d'%rate),'B',pressure,candidate,rate,probe=True,existing=shared)
            state=capacity_probe_state(row)
            recorded=dict(row.get('capacity_probe',{}),rate=rate,directory=str(evidence.output/('capacity-%d'%rate)),state=state)
            probes.append(recorded);(evidence.output/'capacity-probes.json').write_text(json.dumps(probes,indent=2)+'\n')
            return recorded
        bracket=bracket_capacity(list(map(int,args.capacity_rates.split(','))),probe)
        (evidence.output/'capacity-bracket.json').write_text(json.dumps(bracket,indent=2)+'\n')
        shared.kv.allow_db_cleanup=bracket['status']=='BRACKETED_TESTED_CAPACITY'
        require(bracket['status']=='BRACKETED_TESTED_CAPACITY','Bcapacity '+bracket['status']+': '+bracket.get('reason',''))
    finally:shared.cleanup()
    rates=frozen_rates([row for row in probes if row['state']=='STABLE_TESTED_RATE'])
    fresh=[]
    for label in ('normal','high'):
        write_control(evidence.output.parent/'progress.json',json.dumps(dict(phase='fresh-chosen-%d-%s'%(pressure,label),started=time.monotonic())))
        row=execute(args,evidence.output/('chosen-rate-fresh-'+label),'B',pressure,candidate,rates[label+'_rps'],probe=True)
        fresh.append(dict(load=label,directory=str(evidence.output/('chosen-rate-fresh-'+label)),valid=row['valid'],decision=row.get('capacity_probe',{}).get('decision')))
        (evidence.output/'chosen-rate-fresh.json').write_text(json.dumps(fresh,indent=2)+'\n')
        require(row['valid'] and row['capacity_probe']['decision']['state']=='STABLE_TESTED_RATE','chosen B-derived rate fresh preflight invalid; no guard relaxation')
    result=dict(profile_identity=profile_identity(args),pressure_percent=pressure,fill_plan=candidate,capacity=probes,capacity_bracket=bracket,rates=rates,source='B-only finite probes; no C input')
    (evidence.output/'frozen-plan.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def campaign(args,output):
    from ...application_performance import plan
    output=Path(output);schedule=plan(args);trials=[];calibrations={};error=''
    try:
        for pressure in sorted({row['pressure_percent'] for row in schedule['scenarios']}):
            name='calibration-'+str(pressure);write_control(output/'progress.json',json.dumps(dict(phase=name,started=time.monotonic())))
            if args.frozen_plan:
                frozen=json.loads(Path(args.frozen_plan).read_text());validate_frozen_profile(frozen,profile_identity(args));require(frozen['pressure_percent']==pressure,'reviewed plan pressure differs')
            else:frozen=calibrate(args,output/name,pressure)
            calibrations[str(pressure)]=frozen
            if args.calibration_only:continue
            if args.diagnostic_only:
                result=diagnostic_controls(args,output/'diagnostic-controls',frozen)
                write_control(output/'diagnostic-result.json',json.dumps(result,indent=2)+'\n')
                require(result['valid'],'DIAGNOSTIC sensitivity control not detected; do not claim no business effect')
                continue
            for scenario in [row for row in schedule['scenarios'] if row['pressure_percent']==pressure]:
                if scenario['load']=='high':require(frozen['capacity_bracket']['high_fraction_covered'],'high75..85%capacity NOT_COVERED by bounded B bracket')
                rate=frozen['rates'][scenario['load']+'_rps'];groups=['B','C'];random.Random(args.seed+pressure+(1 if scenario['load']=='high' else 0)).shuffle(groups)
                for group in groups:
                    name='%d-%s-%s'%(pressure,scenario['load'],group);write_control(output/'progress.json',json.dumps(dict(phase=name,started=time.monotonic())))
                    trial=execute(args,output/name,group,pressure,frozen['fill_plan'],rate);trial.update(directory=name,scenario=scenario['load']);trials.append(trial)
                    write_control(output/'results.json',json.dumps(dict(config=vars(args),trials=trials,calibrations=calibrations,error=error),indent=2)+'\n')
                require(all(row['valid'] for row in trials if row['pressure_percent']==pressure),'scenario invalid; preserve and stop before higher pressure')
    except Exception as exc:error=repr(exc)
    finally:write_control(output/'results.json',json.dumps(dict(config=vars(args),trials=trials,calibrations=calibrations,error=error),indent=2)+'\n')
    return trials


def report(output):
    output=Path(output)
    if not (output/'results.json').exists():result=dict(status='INVALID_OR_FAILED',reason='no completed source records')
    else:
        data=json.loads((output/'results.json').read_text());trials=data['trials'];comparisons=[]
        for pressure,scenario in sorted({(row['pressure_percent'],row['scenario']) for row in trials}):
            chosen={row['group']:row for row in trials if row['pressure_percent']==pressure and row['scenario']==scenario}
            complete=set(chosen)=={'B','C'} and all(row['valid'] for row in chosen.values())
            metrics={}
            if set(chosen)=={'B','C'}:
                for key,value in chosen['C']['metrics'].items():
                    baseline=chosen['B']['metrics'].get(key)
                    metrics[key]=value-baseline if value is not None and baseline is not None else None
            comparisons.append(dict(pressure_percent=pressure,scenario=scenario,state='DESCRIPTIVE_ONE_PAIR' if complete else 'INVALID_OR_QUALITY_FAILURE',B=chosen.get('B',{}).get('metrics'),C=chosen.get('C',{}).get('metrics'),C_minus_B=metrics,percent={key:(value/chosen['B']['metrics'][key]*100 if value is not None and chosen['B']['metrics'].get(key) not in (None,0) else None) for key,value in metrics.items()},
                                    interpretation='one pair cannot establish significance; signed deltas are observations, not improvement or SLOPASS'))
        expected=0 if data['config']['calibration_only'] or data['config'].get('diagnostic_only') else (6 if data['config']['scenario']=='all' else 2)
        result=dict(status='MEASUREMENT_COMPLETE' if not data['error'] and len(trials)==expected and all(row['valid'] for row in trials) else 'INVALID_OR_INCOMPLETE',error=data['error'],completed_trials=len(trials),comparisons=comparisons,
                    scope='one round; real apps, B-only tested capacity; no SLO supplied; actual capture/provider/partial/truncated remain in source summaries')
    (output/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    (output/'REPORT.md').write_text(markdown_report(result,data if (output/'results.json').exists() else None))
    return result


def diagnostic_controls(args,output,frozen):
    import copy
    control=copy.copy(args);control.application_diagnostic=True
    output=Path(output);output.mkdir();rows=[];rate=frozen['rates']['normal_rps'];pressure=frozen['pressure_percent']
    for name,delay,memory in [('baseline',False,False),('known-request-delay',True,False),('known-memory-increment',False,True)]:
        row=execute(control,output/name,'B',pressure,frozen['fill_plan'],rate,diagnostic=delay,memory_diagnostic=memory)
        rows.append(row)
    baseline,delay,memory=rows
    base_tail=baseline.get('windows',{}).get('capture',{}).get('load',{}).get('scheduled_latency',{}).get('p99_ms')
    delay_tail=delay.get('windows',{}).get('capture',{}).get('load',{}).get('scheduled_latency',{}).get('p99_ms')
    native=delay.get('native');actual_delays=[]
    if native:
        meta=json.loads((output/'known-request-delay/remote-load.json').read_text())
        raw=read_timeline(output/'known-request-delay',native,meta['clock_before']['offset'])
        actual_delays=[(row['ended']-row['sent'])*1000 for row in raw if row.get('diagnostic_delay_ms')==20 and row.get('sent') is not None and row['ok']]
    memory_stats=memory.get('windows',{}).get('capture',{}).get('memory',{}).get('scopes',{}).get('diagnostic',{})
    memory_peak=memory_stats.get('peak_above_baseline_bytes')
    delay_detected=base_tail is not None and delay_tail is not None and delay_tail-base_tail>=10 and actual_delays and min(actual_delays)>=19
    memory_detected=memory_peak is not None and memory_peak>=32<<20
    return dict(valid=all(row['valid'] for row in rows) and bool(delay_detected) and memory_detected,
                stage='DIAGNOSTIC ONLY, no production C snapshot or artificial snapshot cost',
                request_delay=dict(configured_ms=20,fraction=.05,scope='application serving wait forHTTP; actual client worker wait forSDK',baseline_p99_ms=base_tail,diagnostic_p99_ms=delay_tail,delta_ms=delay_tail-base_tail if delay_tail is not None and base_tail is not None else None,actual_traced_delay_samples=len(actual_delays),actual_min_ms=min(actual_delays) if actual_delays else None,detected=bool(delay_detected),criterion='>=10msP99increment and real delayed rawsample>=19ms; known20ms control only, notSLO'),
                memory_increment=dict(configured_bytes=32<<20,scope='separate test-only diagnostic cgroup, excluded from business/collector sums',sampled_peak_above_baseline_bytes=memory_peak,detected=memory_detected),
                directories=[str(output/name) for name in ('baseline','known-request-delay','known-memory-increment')])


def markdown_report(result,data):
    def number(value,scale=1):
        return 'null' if value is None else '%.4f'%(value/scale)
    lines=['# Real application snapshot B/C','',result['status'],'',
           'One descriptive pair per scenario. No significance, improvement, or SLO claim. '
           'Source trial summaries, native tool artifacts and request/resource timelines remain authoritative. '
           'The shared physical host also runs the VM2222 and VM2230 reliability soaks.','']
    for comparison in result.get('comparisons',[]):
        lines+=['## %s%% memory / %s'%(comparison['pressure_percent'],comparison['scenario']),'',comparison['state'],'']
        for phase in ('baseline','capture','recovery'):
            lines+=['### %s phase (distinct from actual snapshot interval)'%phase,'',
                    '| Metric | B | C | C−B | Change % |','|---|---:|---:|---:|---:|']
            fields=[('Success RPS','rps',1),('P99 ms','p99_ms',1),('P999 ms','p999_ms',1),
                    ('Business peak above phase baseline MiB','business_peak_above_baseline_bytes',1<<20),
                    ('Collector peak above phase baseline MiB','collector_peak_above_baseline_bytes',1<<20),
                    ('Agent+helper+reaped worker CPU s','collector_total_cpu_seconds',1),
                    ('Worker0 lifetime HWM increase MiB','worker-0.lifetime_high_water_increase_bytes',1<<20)]
            for label,key,scale in fields:
                name=phase+'.'+key;left=(comparison.get('B') or {}).get(name);right=(comparison.get('C') or {}).get(name)
                lines+=['| %s | %s | %s | %s | %s |'%(label,number(left,scale),number(right,scale),number(comparison['C_minus_B'].get(name),scale),number(comparison.get('percent',{}).get(name)))]
        chosen=[row for row in (data or {}).get('trials',[]) if row['pressure_percent']==comparison['pressure_percent'] and row['scenario']==comparison['scenario']]
        lines+=['','### Actual snapshot interval','',
                '| Group | Provider | Status | Entries | Provider ms | Full worker+serialization+fsync ms | Truncated | Reason |',
                '|---|---|---|---:|---:|---:|---|---|']
        for trial in chosen:
            if not trial.get('captures'):lines+=['| %s | idle / unavailable | null | null | null | null | null | %s |'%(trial['group'],'; '.join(trial.get('errors',[])).replace('|','/'))]
            for capture in trial.get('captures',[]):
                payload=capture.get('result') or {};snapshot=payload.get('Snapshot') or {}
                lines+=['| %s | %s | %s | %d | %s | %s | %s | %s |'%(trial['group'],payload.get('Language'),snapshot.get('status'),len(snapshot.get('entries') or []),number(snapshot.get('duration_ms')),number(capture.get('wall_ms')),snapshot.get('output_truncated'),str(snapshot.get('status_reason') or capture.get('error') or '').replace('|','/'))]
            for active in trial.get('active_capture_windows',[]):
                tails=active.get('latency_ms') or {};lines+=['',
                    '%s actual interval: %s arrivals; P99 %sms; P999 %sms; max %sms; clock uncertainty %sms; complete trace %s.'%(trial['group'],active.get('definite_scheduled_count'),number(tails.get('p99')),number(tails.get('p999')),number(tails.get('max')),number(active.get('clock_uncertainty_ms')),active.get('interval_trace_complete')),'']
    if result.get('error'):lines+=['Campaign error: '+result['error'],'']
    return '\n'.join(lines)+'\n'
