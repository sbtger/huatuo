# Copyright 2026 Huatuo Authors
# Licensed under the Apache License, Version 2.0.
"""Single-process resident object cache. DELETE means atomic eviction/rebuild.

Runtime: CPython 3.12, fastapi==0.115.12, uvicorn==0.34.2.
Start: python fastapi_cache.py (one worker; no preload).
"""
import asyncio
import gc
import hashlib
import os
import platform
import time
from collections import Counter

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response

app = FastAPI()
store = {}
locks = [asyncio.Lock() for _ in range(256)]
frozen = False
cache_seed = None
value_bytes = 0
counts = Counter({'GET': 0, 'SET': 0, 'DELETE': 0})
inflight = 0
max_inflight = 0
gc_totals = {'collections': 0, 'wall_ns': 0, 'collecting_thread_cpu_ns': 0}
gc_start = None

def gc_callback(phase, info):
    global gc_start
    if phase == 'start':
        gc_start = (time.perf_counter_ns(), time.thread_time_ns())
    elif gc_start is not None:
        gc_totals['collections'] += 1
        gc_totals['wall_ns'] += time.perf_counter_ns() - gc_start[0]
        gc_totals['collecting_thread_cpu_ns'] += time.thread_time_ns() - gc_start[1]
        gc_start = None

gc.callbacks.append(gc_callback)

class Record:
    def __init__(self, key):
        self.key = key
        self.value = bytearray([97 + key % 26]) * (65536 if key % 10 == 0 else 1024)
        self.labels = {'key': str(key), 'tags': ['resident', key]}
        self.children = [{'items': [key, {'active': True}]}]

def integer(value, name, maximum=2147483647):
    if value is None or not value.isascii() or not value.isdecimal():
        raise HTTPException(400, 'invalid ' + name)
    result = int(value) if len(value) <= 10 else maximum + 1
    if result > maximum:
        raise HTTPException(400, 'invalid ' + name)
    return result

@app.post('/fill')
async def fill(request: Request):
    global cache_seed, value_bytes
    if frozen:
        raise HTTPException(409, 'cache is frozen')
    records = integer(request.query_params.get('records'), 'records', 1000000)
    seed = integer(request.query_params.get('seed'), 'seed')
    if records < 1024 or records < len(store) or (cache_seed is not None and seed != cache_seed):
        raise HTTPException(400, 'fill requires grow-only count >=1024 and unchanged seed')
    cache_seed = seed
    for key in range(len(store), records):
        record = Record(key)
        store[key] = record
        value_bytes += len(record.value)
    return {'live_count': len(store), 'value_bytes': value_bytes}

@app.post('/freeze')
async def freeze():
    global frozen
    frozen = True
    return {'frozen': True}

@app.get('/stats')
async def stats(request: Request):
    sample = store.get(0)
    result = {'records': len(store), 'live_count': len(store), 'value_bytes': value_bytes, 'operations': dict(counts),
              'inflight': inflight, 'max_inflight': max_inflight, 'frozen': frozen,
              'runtime': {'python': platform.python_version(), 'workers': 1, 'pid': os.getpid()},
              'gc': dict(gc_totals, enabled=gc.isenabled()),
              'tracked': {} if sample is None else {name: gc.is_tracked(obj) for name, obj in
                  [('record', sample), ('labels', sample.labels), ('tags', sample.labels['tags']), ('children', sample.children)]}}
    if request.query_params.get('verify') == '1':
        digest = hashlib.sha256()
        for key in range(len(store)):
            value = store[key].value
            digest.update(('%d:%d:%s\n' % (key, len(value), hashlib.sha256(value).hexdigest())).encode())
        result['dataset_sha256'] = digest.hexdigest()
    return result

@app.api_route('/cache/{key}', methods=['GET', 'PUT', 'DELETE'])
async def cache(key: str, request: Request):
    global inflight, max_inflight
    key = integer(key, 'key', 999999)
    ordinal = integer(request.query_params.get('ordinal'), 'ordinal')
    seed = integer(request.query_params.get('seed'), 'seed')
    delay = integer(request.query_params.get('delay_ms', '0'), 'delay_ms', 100)
    if delay and ordinal % 20 != 0:
        raise HTTPException(400, 'delay requires ordinal divisible by 20')
    if delay and os.environ.get('APP_DIAGNOSTIC', '0') != '1':
        raise HTTPException(400, 'diagnostic delay disabled')
    if cache_seed is not None and seed != cache_seed:
        raise HTTPException(400, 'seed differs from fill')
    if key not in store:
        raise HTTPException(404, 'key not found')
    inflight += 1
    max_inflight = max(max_inflight, inflight)
    try:
        if delay:
            await asyncio.sleep(delay / 1000)
        body = bytearray()
        if request.method == 'PUT':
            expected = 65536 if key % 10 == 0 else 1024
            async for chunk in request.stream():
                if len(body) + len(chunk) > expected:
                    raise HTTPException(400, 'payload too large')
                body.extend(chunk)
            if body != bytearray([97 + key % 26]) * expected:
                raise HTTPException(400, 'payload differs from oracle')
        async with locks[key % len(locks)]:
            record = store[key]
            if request.method == 'PUT':
                record = Record(key)
                store[key] = record
            elif request.method == 'DELETE':
                record = store.pop(key)
                store[key] = Record(key)
            data = bytes(record.value)
            operation = 'SET' if request.method == 'PUT' else request.method
            counts[operation] += 1
        return Response(data, media_type='application/octet-stream', headers={
            'X-Bench-Ordinal': str(ordinal), 'X-Bench-Operation': operation, 'X-Bench-Key': str(key)})
    finally:
        inflight -= 1

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=int(os.environ.get('HUATUO_TEST_PORT', '30000')), workers=1, access_log=False)
