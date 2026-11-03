# Copyright 2026. Licensed under the Apache License, Version 2.0.
"""External contract check. Start packaged application before running this script."""
import concurrent.futures, hashlib, json, os, urllib.request, urllib.error
import subprocess, socket, time, atexit
process = None
if os.environ.get('SPRING_JAR'):
    with socket.socket() as sock:
        assert sock.connect_ex(('127.0.0.1',30061)) != 0, 'test port occupied'
    env = dict(os.environ, HUATUO_TEST_PORT='30061', APP_DIAGNOSTIC='0')
    process = subprocess.Popen([os.environ.get('JAVA','java'), '-jar', os.environ['SPRING_JAR']], env=env, stdout=open('/tmp/spring-contract.log','w'), stderr=subprocess.STDOUT)
    def cleanup():
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill(); process.wait()
    atexit.register(cleanup)
    for _ in range(120):
        try:
            urllib.request.urlopen('http://127.0.0.1:30061/stats'); break
        except (OSError, urllib.error.URLError): time.sleep(.25)
    os.environ['BASE_URL']='http://127.0.0.1:30061'
BASE = os.environ.get('BASE_URL', 'http://127.0.0.1:30000')
def request(path, method='GET', body=None, status=200):
    req = urllib.request.Request(BASE + path, data=body, method=method, headers={'Content-Type':'application/octet-stream'} if method == 'PUT' else {})
    try:
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as exc:
        assert exc.code == status, (method, path, exc.code, status)
        return b'', {}
    assert response.status == status
    return response.read(), response.headers
request('/fill?records=1024&seed=1', 'POST')
request('/freeze', 'POST')
request('/fill?records=1025&seed=1', 'POST', status=400)
def payload(key):
    return bytes([97 + key % 26]) * (65536 if key % 10 == 0 else 1024)
def operation(item):
    key, method = item
    data, headers = request(f'/cache/{key}?ordinal={key+1}&seed=1', method, payload(key) if method == 'PUT' else None)
    assert data == payload(key)
    assert headers['X-Bench-Key'] == str(key)
    assert headers['X-Bench-Operation'] == ('SET' if method == 'PUT' else method)
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    list(pool.map(operation, [(key, method) for key in range(32) for method in ('GET','PUT','DELETE')]))
request('/cache/0?ordinal=1&seed=1', 'PUT', b'wrong', 400)
request('/cache/99999?ordinal=1&seed=1', status=404)
request('/cache/0?ordinal=0&seed=1')
request('/cache/0?ordinal=-1&seed=1', status=400)
request('/cache/0?ordinal=1&seed=2', status=400)
request('/cache/0?ordinal=1&seed=1&delay_ms=20', status=400)
stats = json.loads(request('/stats?verify=1')[0])
manifest = ''.join(f'{key}:{len(payload(key))}:{hashlib.sha256(payload(key)).hexdigest()}\n' for key in range(1024))
assert stats['dataset_sha256'] == hashlib.sha256(manifest.encode()).hexdigest()
assert stats['records'] == stats['live_count'] == 1024
assert stats['operations'] == {'GET':33,'SET':32,'DELETE':32}
assert stats['inflight'] == 0
print('Spring external contract passed')

assert isinstance(stats['runtime'], dict)
assert stats['gc']['cpu_ms'] is None
assert 'dataset_sha256' not in json.loads(request('/stats')[0])
if process is not None:
    cleanup()
    env['APP_DIAGNOSTIC'] = '1'
    process = subprocess.Popen([os.environ.get('JAVA','java'), '-jar', os.environ['SPRING_JAR']], env=env, stdout=open('/tmp/spring-contract-diagnostic.log','w'), stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            urllib.request.urlopen(BASE + '/stats'); break
        except (OSError, urllib.error.URLError): time.sleep(.25)
    request('/fill?records=1024&seed=0', 'POST')
    request('/freeze','POST')
    start = time.monotonic()
    data, _ = request('/cache/0?ordinal=0&seed=0&delay_ms=20')
    assert time.monotonic() - start >= .018
    assert data == payload(0)
    cleanup()
print('Spring schema, seed, and diagnostic checks passed')
