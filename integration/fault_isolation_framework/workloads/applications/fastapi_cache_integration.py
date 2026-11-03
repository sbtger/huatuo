# Copyright 2026 Huatuo Authors
# Licensed under the Apache License, Version 2.0.
"""External HTTP contract test; run with the application's pinned virtualenv."""
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

def run(diagnostic):
    port = 30062
    env = dict(os.environ, HUATUO_TEST_PORT=str(port), APP_DIAGNOSTIC=str(diagnostic))
    process = subprocess.Popen([sys.executable, 'fastapi_cache.py'], env=env)
    def request(path, method='GET', body=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), data=body, method=method)
        with urllib.request.urlopen(req) as response:
            return response.read(), response.headers
    try:
        for _ in range(100):
            try:
                request('/stats'); break
            except Exception:
                time.sleep(.1)
        request('/fill?records=1024&seed=7', 'POST')
        request('/freeze', 'POST')
        try:
            request('/fill?records=1025&seed=7', 'POST'); assert False
        except urllib.error.HTTPError as error:
            assert error.code == 409
        def operation(i):
            key = i % 1024
            payload = bytes([97 + key % 26]) * (65536 if key % 10 == 0 else 1024)
            method = ('GET', 'PUT', 'DELETE')[i % 3]
            data, headers = request('/cache/%d?ordinal=%d&seed=7' % (key, i), method, payload if method == 'PUT' else None)
            assert data == payload
            assert headers['X-Bench-Ordinal'] == str(i)
            assert headers['X-Bench-Operation'] == ('SET' if method == 'PUT' else method)
        with concurrent.futures.ThreadPoolExecutor(16) as pool:
            list(pool.map(operation, range(256)))
        stats = json.loads(request('/stats?verify=1')[0])
        digest = hashlib.sha256()
        for key in range(1024):
            payload = bytes([97 + key % 26]) * (65536 if key % 10 == 0 else 1024)
            digest.update(('%d:%d:%s\n' % (key, len(payload), hashlib.sha256(payload).hexdigest())).encode())
        assert stats['records'] == 1024
        assert stats['operations'] == {'GET': 86, 'SET': 85, 'DELETE': 85}
        assert stats['dataset_sha256'] == digest.hexdigest() and stats['live_count'] == 1024
        for body in (b'bad', b'x' * 65537):
            try:
                request('/cache/1?ordinal=299&seed=7', 'PUT', body); assert False
            except urllib.error.HTTPError as error:
                assert error.code == 400
        start = time.monotonic()
        try:
            request('/cache/1?ordinal=300&seed=7&delay_ms=20')
            assert diagnostic and time.monotonic() - start >= .019
        except urllib.error.HTTPError as error:
            assert not diagnostic and error.code == 400
        if diagnostic:
            # Eight independent waits must overlap; a global serving lock would
            # turn this into at least 0.8 seconds of serialized waiting.
            def delayed(i):
                data, _ = request('/cache/%d?ordinal=%d&seed=7&delay_ms=100' % (i, 400+i*20))
                assert data == bytes([97+i%26]) * (65536 if i%10 == 0 else 1024)
            start = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(8) as pool:
                list(pool.map(delayed, range(8)))
            assert time.monotonic() - start < .6, 'diagnostic waits were serialized'
            assert json.loads(request('/stats')[0])['max_inflight'] >= 2
    finally:
        process.terminate(); process.wait(timeout=10)

if __name__ == '__main__':
    run(0); run(1); print('FastAPI external integration PASS')
