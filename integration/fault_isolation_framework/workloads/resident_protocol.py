# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Seeded resident-KV operations with an independently known response body."""
import hashlib


def size(key):return 65536 if key%10==0 else 1024

def payload(key):return bytes([97+key%26])*size(key)

def operation(ordinal,seed,count):
    mixed=((ordinal+seed)*1103515245+12345)&0x7fffffff
    kind='GET' if mixed%10<6 else ('SET' if mixed%10<9 else 'DELETE')
    key=mixed%min(count,1024) if kind=='GET' else mixed%64
    return kind,key


def expected(ordinal,seed,count):
    kind,key=operation(ordinal,seed,count)
    return ('%d|%s|%d|%s\n'%(ordinal,kind,key,hashlib.sha256(payload(key)).hexdigest())).encode()


def dataset_digest(count):
    cache={};digest=hashlib.sha256()
    for key in range(count):
        shape=(key%26,size(key))
        if shape not in cache:cache[shape]=hashlib.sha256(payload(key)).hexdigest()
        digest.update(('%d:%d:%s\n'%(key,size(key),cache[shape])).encode())
    return digest.hexdigest()
