# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Bounded RESP2 client for the real Redis benchmark fixture."""
import socket
from urllib.parse import urlsplit

MAX_BULK = 2 << 20


def encode_command(*parts):
    values=[p if isinstance(p,bytes) else str(p).encode() for p in parts]
    return b"*%d\r\n"%len(values)+b"".join(b"$%d\r\n"%len(p)+p+b"\r\n" for p in values)


def read_reply(stream, depth=0):
    if depth>8:
        raise ValueError("RESP nesting exceeds fixture budget")
    line=stream.readline(65537)
    if not line or not line.endswith(b"\r\n") or len(line)>65536:
        raise EOFError("truncated or oversized RESP header")
    kind,body=line[:1],line[1:-2]
    if kind==b"+":return body
    if kind==b"-":raise ValueError("Redis error: "+body.decode(errors="replace"))
    if kind==b":":return int(body)
    if kind in (b"$",b"*"):
        size=int(body)
        if size==-1:return None
        if size<0 or size>(MAX_BULK if kind==b"$" else 1024):
            raise ValueError("RESP payload exceeds fixture budget")
        if kind==b"*":return [read_reply(stream,depth+1) for _ in range(size)]
        data=stream.read(size+2)
        if len(data)!=size+2 or data[-2:]!=b"\r\n":raise EOFError("truncated RESP bulk")
        return data[:-2]
    raise ValueError("unsupported RESP type")


def pipeline(url, commands, timeout=2):
    target=urlsplit(url)
    if target.scheme!="redis" or not target.hostname or not target.port:
        raise ValueError("expected redis://host:port")
    with socket.create_connection((target.hostname,target.port),timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(b"".join(encode_command(*c) for c in commands))
        with connection.makefile("rb") as stream:
            return [read_reply(stream) for _ in commands]


def command(url,*parts):return pipeline(url,[parts])[0]


def payload(size):
    return (bytes(range(251))*((size+250)//251))[:size]


def load_request(target,ordinal,timeout=2):
    body=target.get("_payload")
    if body is None:body=payload(target.get("value_bytes",65536))
    key="huatuo:perf:key:%d"%(ordinal%target.get("keys",128))
    answer=pipeline(target["url"],[("SET",key,body),("GET",key),("INCR","huatuo:perf:work-count")],timeout)
    if answer[0]!=b"OK" or answer[1]!=body or not isinstance(answer[2],int) or answer[2]<1:
        raise ValueError("Redis SET/GET/counter mismatch")
    return answer[2]


def info(url,section="all"):
    body=command(url,"INFO",section)
    if not isinstance(body,bytes):raise ValueError("Redis INFO was not bulk data")
    return {k:v for k,v in (line.split(":",1) for line in body.decode().splitlines() if line and not line.startswith("#") and ":" in line)}
