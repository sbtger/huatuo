# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Independent full-working-set cache oracle and bounded B-only decisions."""
import math


def payload(key):return bytes([97+key%26])*(65536 if key%10==0 else 1024)


def cache_operation(ordinal,seed,records):
    if not 1024<=records<=1000000 or ordinal<0:raise ValueError('cache recipe outside bounded dataset')
    mixed=((ordinal+seed)*1103515245+12345)&0x7fffffff
    operation='GET' if mixed%100<70 else ('SET' if mixed%100<90 else 'DELETE')
    hot=max(1,min(records-1,math.ceil(records*.2)));draw=(mixed*48271)%2147483647
    key=draw%hot if (mixed//100)%100<80 else hot+draw%(records-hot)
    return operation,key


def capacity_state(probe,throughput_tolerance=.02,tail_growth=.2,backlog_growth_ms=5,client_fraction=.85):
    """Calibration stability controls are not production acceptance budgets."""
    errors=[]
    if probe['client_cpu_cores']>probe['client_cores']*client_fraction:
        return dict(state='CLIENT_LIMITED',reasons=['load host CPU headroom insufficient'])
    if any(probe.get(key,0) for key in ('errors','timeouts','body_errors','trace_overflow')):errors.append('request/response/trace errors')
    if abs(probe['success_rps']/probe['offered_rps']-1)>throughput_tolerance:errors.append('actual throughput differs from offered rate')
    if probe['final_p99_ms'] is None or probe['initial_p99_ms'] is None:errors.append('insufficient capacity-window tail samples')
    elif probe['final_p99_ms']>probe['initial_p99_ms']*(1+tail_growth)+1:errors.append('tail latency grows across baseline')
    if probe['final_backlog_ms'] is None or probe['initial_backlog_ms'] is None:errors.append('insufficient backlog samples')
    elif probe['final_backlog_ms']>probe['initial_backlog_ms']+backlog_growth_ms:errors.append('scheduled-arrival backlog grows across baseline')
    return dict(state='APPLICATION_UNSTABLE' if errors else 'STABLE_TESTED_RATE',reasons=errors,
                controls=dict(throughput_tolerance=throughput_tolerance,tail_growth=tail_growth,backlog_growth_ms=backlog_growth_ms,client_cpu_fraction=client_fraction))


def frozen_rates(probes):
    stable=[p['offered_rps'] for p in probes if capacity_state(p)['state']=='STABLE_TESTED_RATE']
    if not stable:raise ValueError('no stable tested B throughput; do not choose a lower untested rate')
    highest=max(stable)
    return dict(highest_tested_stable_rps=highest,normal_rps=max(1,int(highest*.55)),high_rps=max(1,int(highest*.8)),
                claim='fractions of highest stable tested B rate; not interpolated maximum capacity')


def dataset_digest(records):
    import hashlib
    digest=hashlib.sha256()
    # Cache oracle bytes by shape; the ordered manifest still names every key.
    values={}
    for key in range(records):
        shape=(key%26,key%10==0)
        if shape not in values:
            body=payload(key);values[shape]=(len(body),hashlib.sha256(body).hexdigest())
        size,sha=values[shape]
        digest.update(('%d:%d:%s\n'%(key,size,sha)).encode())
    return digest.hexdigest()


def bracket_capacity(ladder,probe,max_refinements=6,relative_width=.06):
    tested=[];stable=None;unstable=None
    def measure(rate):
        row=dict(probe(rate),offered_rps=rate);tested.append(row);return row['state']
    for rate in ladder:
        state=measure(rate)
        if state=='STABLE_TESTED_RATE':stable=rate
        elif state=='APPLICATION_UNSTABLE':unstable=rate;break
        else:return dict(status='CAPACITY_NOT_BRACKETED',reason=state,tested=tested,highest_tested_stable_rps=stable)
    if stable is None or unstable is None:return dict(status='CAPACITY_NOT_BRACKETED',reason='no stable/unstable application bracket',tested=tested,highest_tested_stable_rps=stable)
    refinements=0
    while (unstable-stable)/stable>relative_width and refinements<max_refinements:
        rate=(stable+unstable)//2
        if rate in (stable,unstable):break
        state=measure(rate);refinements+=1
        if state=='STABLE_TESTED_RATE':stable=rate
        elif state=='APPLICATION_UNSTABLE':unstable=rate
        else:return dict(status='CAPACITY_NOT_BRACKETED',reason=state,tested=tested,highest_tested_stable_rps=stable)
    return dict(status='BRACKETED_TESTED_CAPACITY',tested=tested,highest_tested_stable_rps=stable,
                first_tested_unstable_rps=unstable,relative_bracket_width=(unstable-stable)/stable,
                refinements=refinements,estimated_capacity_fraction_interval=dict(normal=[.55*stable/unstable,.55],high=[.8*stable/unstable,.8]),
                estimate_assumption='single-round monotonic stability between tested rates; first unstable may be transient; not formal capacity acceptance',
                high_fraction_covered=.8*stable/unstable>=.75,
                claim='actual B probes only; bracket bounds are measured, no interpolated maximum')


def validate_frozen_profile(plan,expected):
    if plan.get('profile_identity')!=expected:raise ValueError('B calibration profile/source differs; no cross-app/runtime/rate-plan reuse')


def capacity_probe_state(row):
    errors=[error for error in row.get('errors',[]) if not error.startswith('business quality: ')]
    if not row.get('measurement_protocol_valid') or not row.get('frozen_pressure') or row.get('capture_quality_errors') or errors:return 'INVALID_PREFLIGHT'
    return row.get('capacity_probe',{}).get('decision',{}).get('state','INVALID_PREFLIGHT')
