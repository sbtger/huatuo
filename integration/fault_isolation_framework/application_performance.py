#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""One-round real-application B/C snapshot measurements, B-only calibration."""
import argparse
import math
import json
import os
import signal
import subprocess
import sys
import tarfile
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.performance import parser as base_parser,seal,audit


def parser():
    defaults=vars(base_parser().parse_args(['--output','/unused']))
    p=argparse.ArgumentParser(description=__doc__);p.set_defaults(**defaults)
    for name in ('build','bpf_dir','snapshot_helper','load_controller_url','load_token_file','load_target_host','java_home','python'):
        p.add_argument('--'+name.replace('_','-'),default=defaults[name])
    p.add_argument('--output',required=True)
    for name in ('memory_limit_mib','workers','seed','top_k','capture_timeout','service_port_base','load_target_base_port','agent_port','repeats','snapshot_count'):
        p.add_argument('--'+name.replace('_','-'),type=int,default=defaults[name])
    for name in ('business_cpus','warmup','baseline','hold','recovery','sample_interval','max_clock_error','pressure_tolerance','phase_timeout','campaign_timeout'):
        p.add_argument('--'+name.replace('_','-'),type=float,default=defaults[name])
    p.add_argument('--plan',action='store_true');p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    p.add_argument('--application',required=True,choices=['etcd','spring','fastapi'])
    p.add_argument('--application-tools',default='')
    p.add_argument('--runtime-data-root',default='/data/huatuo-performance/application-owned-data-20261103')
    p.add_argument('--capacity-rates',default='100,300,1000,3000,10000,30000,50000')
    p.add_argument('--diagnostic-only',action='store_true')
    p.set_defaults(application_diagnostic=False)
    p.add_argument('--calibration-only',action='store_true')
    p.add_argument('--frozen-plan',help='reuse reviewed B-only frozen calibration JSON')
    p.add_argument('--scenario',choices=['all','normal60','normal90','high90'],default='all')
    p.set_defaults(business='application',module='memory_threshold_snapshot',repeats=1,snapshot_count=1,
                   memory_limit_mib=4096,business_cpus=4,workers=128,warmup=60,baseline=60,hold=60,recovery=60,
                   phase_timeout=1800,campaign_timeout=28800)
    return p


def plan(args):
    for name in ('business_cpus','warmup','baseline','hold','recovery','sample_interval','max_clock_error','pressure_tolerance','phase_timeout','campaign_timeout'):
        value=getattr(args,name)
        if not math.isfinite(value) or value<=0:raise ValueError(name+' must be finite and positive')
    if not 256<=args.memory_limit_mib<=4096 or not 0<args.business_cpus<=4:raise ValueError('business requires256..4096MiB and<=4CPU')
    if args.capture_timeout!=3:raise ValueError('approved capture/trace budget is exactly3seconds')
    if not 2<=args.workers<=128 or not 1<=args.top_k<=1000 or not 0<=args.seed<=1000000:raise ValueError('connection/top-k/seed budget outside bounds')
    if not .01<=args.sample_interval<=1 or not .001<=args.max_clock_error<=.1 or args.pressure_tolerance>2:raise ValueError('measurement precision/pressure budget outside bounds')
    if not 30000<=args.service_port_base<=30063 or not 40000<=args.load_target_base_port<=40063 or not 1024<=args.agent_port<=65535:raise ValueError('service/control route outside bounded ports')
    if args.phase_timeout>3600 or args.campaign_timeout>28800:raise ValueError('supervision budget outside bounds')
    if not Path(args.runtime_data_root).is_absolute() or Path(args.runtime_data_root) in (Path('/'),Path('/data')):raise ValueError('owned DB runtime root must be a dedicated absolute directory')
    if args.repeats!=1 or args.snapshot_count!=1:raise ValueError('only ONE round and ONE C capture are authorized')
    if min(args.warmup,args.baseline,args.hold,args.recovery)<60:raise ValueError('real application windows require >=60s including wrk2 calibration warmup')
    if args.memory_limit_mib>4096 or args.business_cpus>4:raise ValueError('one business target bounded by4CPU/4GiB')
    rates=[int(v) for v in args.capacity_rates.split(',')]
    if not rates or len(rates)>8 or sorted(set(rates))!=rates or not all(1<=v<=50000 for v in rates):raise ValueError('finite strictly increasing rate ladder1..50000 required')
    if args.warmup+args.baseline+args.hold+args.recovery>600:raise ValueError('bounded native job duration exceeds600s')
    scenarios=[dict(pressure_percent=60,load='normal'),dict(pressure_percent=90,load='normal'),dict(pressure_percent=90,load='high')]
    if args.diagnostic_only:scenarios=[dict(pressure_percent=60,load='normal')]
    elif args.scenario!='all':scenarios=[row for row in scenarios if args.scenario==row['load']+str(row['pressure_percent'])]
    return dict(application=args.application,groups=['DIAGNOSTIC_BASELINE','DIAGNOSTIC_DELAY','DIAGNOSTIC_MEMORY'] if args.diagnostic_only else ['B','C'],repeats=1,captures_per_C=0 if args.diagnostic_only else 1,scenarios=scenarios,
                capacity_rates=rates,phase_seconds={key:getattr(args,key) for key in ('warmup','baseline','hold','recovery')},
                normal_capacity_fraction=.55,high_capacity_fraction=.8,
                scope='DIAGNOSTIC ONLY; no production C' if args.diagnostic_only else 'measurement; no universal SLO supplied; no5round or95%run',
                lifecycle='Shipping Agent initializes manager in both groups; persistent test helper idle B, ONE production worker C')


def main():
    p=parser();args=p.parse_args()
    try:schedule=plan(args)
    except ValueError as exc:p.error(str(exc))
    if args.plan:print(json.dumps(schedule,indent=2));return 0
    for name in ('build','bpf_dir','snapshot_helper','load_controller_url','load_token_file','application_tools'):
        if not getattr(args,name):p.error('--'+name.replace('_','-')+' required')
    args.log_debug=False;args.resident_language={'etcd':'go','spring':'java','fastapi':'python'}[args.application]
    from fault_isolation_framework.adapters.huatuo.application_performance import campaign,report
    output=Path(args.output).resolve()
    if args.worker:
        signal.signal(signal.SIGTERM,lambda *_:(_ for _ in ()).throw(KeyboardInterrupt('campaign terminated')))
        campaign(args,output);return 0
    output.mkdir(parents=True,exist_ok=False)
    (output/'command.json').write_text(json.dumps(dict(argv=sys.argv,config=vars(args),schedule=schedule),indent=2)+'\n')
    with tarfile.open(output/'executed-framework.tar.gz','w:gz') as archive:
        source=Path(__file__).resolve().parent
        for path in sorted(source.rglob('*')):
            if path.is_file() and path.suffix in ('.py','.go','.java','.lua','.h','.xml','.mod','.sum') and '__pycache__' not in path.parts:archive.add(path,arcname=str(path.relative_to(source.parent)))
    reason=''
    with (output/'controller.log').open('x') as log:
        child=subprocess.Popen([sys.executable,str(Path(__file__).resolve())]+sys.argv[1:]+['--worker'],stdout=log,stderr=log,start_new_session=True,
                               env=dict(os.environ,HUATUO_TEST_OWNERSHIP=str(output/'ownership.jsonl')))
        try:
            deadline=time.monotonic()+args.campaign_timeout
            while child.poll() is None:
                if time.monotonic()>deadline:raise TimeoutError('application campaign deadline')
                checkpoint=output/'progress.json'
                if checkpoint.exists():
                    current=json.loads(checkpoint.read_text())
                    if time.monotonic()-current['started']>args.phase_timeout:raise TimeoutError('application trial deadline: '+current['phase'])
                time.sleep(.2)
        except (Exception,KeyboardInterrupt) as exc:
            reason=repr(exc);os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(15)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(10)
    from fault_isolation_framework.environments.supervisor import cleanup_owned
    cleanup=cleanup_owned(output)
    (output/'supervisor.json').write_text(json.dumps(dict(returncode=child.returncode,reason=reason,cleanup_errors=cleanup),indent=2)+'\n')
    result=report(output);seal(output);checked=audit(output)
    print(json.dumps(result,indent=2))
    return int(bool(reason or child.returncode or cleanup or checked['status']!='PASS' or result['status']!='MEASUREMENT_COMPLETE'))


if __name__=='__main__':raise SystemExit(main())
