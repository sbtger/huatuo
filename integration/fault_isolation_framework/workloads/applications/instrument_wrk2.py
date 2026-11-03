#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Reproducible measurement-only hooks; refuse unknown upstream source anchors."""
import argparse,hashlib,json,shutil
from pathlib import Path

PIN='44a94c17d8e6a0bac8559b53da76848e430cb7a7'


def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('wrk2 source anchor changed: '+old[:90])
    return text.replace(old,new,1)


def instrument(source,output):
    source=Path(source);output=Path(output);shutil.copytree(source,output)
    original={name:hashlib.sha256((source/'src'/name).read_bytes()).hexdigest() for name in ('wrk.c','script.c','script.h')}
    path=output/'src/script.c';text=path.read_text()
    text=replace(text,'#include "zmalloc.h"','#include "zmalloc.h"\n#include "bench_metrics.h"')
    text=replace(text,'{ "time_us", LUA_TFUNCTION, script_wrk_time_us },','{ "time_us", LUA_TFUNCTION, script_wrk_time_us },\n        { "bench_record", LUA_TFUNCTION, script_wrk_bench_record },\n        { "bench_dump", LUA_TFUNCTION, script_wrk_bench_dump },')
    text=replace(text,'void script_response(lua_State *L, int status, buffer *headers, buffer *body) {','void script_response(lua_State *L, int status, buffer *headers, buffer *body, uint64_t planned, uint64_t sent, uint64_t ended, const char *request, size_t request_length) {')
    text=replace(text,'    lua_call(L, 3, 0);\n\n    buffer_reset(headers);','    lua_pushnumber(L, planned);lua_pushnumber(L, sent);lua_pushnumber(L, ended);\n    lua_pushlstring(L,request,request_length<512?request_length:512);\n    lua_call(L, 7, 0);\n\n    buffer_reset(headers);')
    # Export finish/failure hooks used by wrk.c; histogram helpers stay local.
    text=text.replace('#include "bench_metrics.h"','#define BENCH_SCRIPT_IMPLEMENTATION\n#include "bench_metrics.h"')
    path.write_text(text)
    path=output/'src/script.h';text=path.read_text().replace('void script_response(lua_State *, int, buffer *, buffer *);','void script_response(lua_State *, int, buffer *, buffer *, uint64_t, uint64_t, uint64_t, const char *, size_t);\nvoid script_bench_finish(lua_State *);\nvoid script_bench_failure(lua_State *,const char *,connection *,uint64_t);');path.write_text(text)
    path=output/'src/wrk.c';text=path.read_text()
    text=replace(text,'    aeMain(loop);','    aeMain(loop);\n    script_bench_finish(thread->L);')
    text=replace(text,'script_response(thread->L, status, &c->headers, &c->body);','script_response(thread->L, status, &c->headers, &c->body, c->thread_start+(c->complete_at_last_batch_start/c->throughput), c->actual_latency_start, now, c->request, c->length);')
    text=replace(text,'            thread->errors.timeout++;','            thread->errors.timeout++;\n            if(c->has_pending)script_bench_failure(thread->L,"timeout",c,now);')
    text=text.replace('    thread->errors.write++;','    script_bench_failure(thread->L,"write",c,time_us());\n    thread->errors.write++;')
    text=text.replace('    thread->errors.read++;','    script_bench_failure(thread->L,"read",c,time_us());\n    thread->errors.read++;')
    text=text.replace('    thread->errors.connect++;','    script_bench_failure(thread->L,"connect",c,time_us());\n    thread->errors.connect++;')
    path.write_text(text)
    header=Path(__file__).with_name('bench_metrics.h').read_text().replace('static void script_bench_finish','void script_bench_finish').replace('static void script_bench_failure','void script_bench_failure')
    (output/'src/bench_metrics.h').write_text(header)
    proof=dict(upstream_commit=PIN,claim='measurement hooks only; native pacing/expected-latency formula unchanged',upstream_source_sha256=original,
               patch_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),hook_sha256=hashlib.sha256(header.encode()).hexdigest(),instrumented_sha256={n:hashlib.sha256((output/'src'/n).read_bytes()).hexdigest() for n in ('wrk.c','script.c','script.h','bench_metrics.h')})
    (output/'measurement-build-proof.json').write_text(json.dumps(proof,indent=2)+'\n');return proof


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--output',required=True);a=p.parse_args();instrument(a.source,a.output)
