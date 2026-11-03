# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Test-only readiness then exec the real Redis server, retaining its PID."""
import json,os,subprocess,sys
binary,bind,port=sys.argv[1:4]
version=subprocess.check_output([binary,'--version'],universal_newlines=True).strip()
print(json.dumps(dict(url='redis://127.0.0.1:'+port,pid=os.getpid(),language='redis',runtime=version)),flush=True)
os.execv(binary,[binary,'--bind',bind,'--port',port,'--protected-mode','no',
                '--save','','--appendonly','no','--dir','/data','--dbfilename','dump.rdb',
                '--rdbcompression','no','--maxmemory','64mb','--maxmemory-policy','noeviction'])
