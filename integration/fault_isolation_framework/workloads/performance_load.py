#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Bounded fixed-arrival validation driver, usable on a separate load host.

Intended-arrival latency includes client queueing. This stdlib driver requires
calibration before higher-rate measurements; it is not a replacement for wrk2.
"""
import argparse
import concurrent.futures
import json
import math
import threading
import sys
import time
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fault_isolation_framework.workloads.redis_protocol import load_request as redis_load, payload as redis_payload


def run_load(targets, output, qps, duration, workers=16, pending=64,
             expected=None, start_at=None, timeout=2, start_monotonic=None, stop=None):
    if qps <= 0 or duration <= 0 or workers < 1 or pending < 1 or not targets:
        raise ValueError("load requires positive rate/duration/capacity and targets")
    # Each target owns capacity, so a slow target cannot starve its neighbor.
    for t in targets:
        if t.get("kind") == "redis":
            t["_payload"] = redis_payload(t.get("value_bytes", 65536))
    gates = {t["id"]: threading.BoundedSemaphore(pending) for t in targets}
    rows, lock = [], threading.Lock()
    start = start_monotonic if start_monotonic is not None else time.monotonic() + max(0, (start_at or time.time())-time.time())
    pools = {t["id"]: concurrent.futures.ThreadPoolExecutor(max_workers=workers) for t in targets}
    with Path(output).open("x") as stream:
        def record(row):
            with lock:
                rows.append(row)
                stream.write(json.dumps(row)+"\n")
                stream.flush()

        def work(target, row):
            try:
                if stop is not None and stop.is_set():
                    row.update(error="load cancelled before send", load_invalid=True)
                    return
                row["sent"] = time.monotonic()
                if target.get("kind") == "redis":
                    row["redis_counter"] = redis_load(target, row["ordinal"], timeout)
                else:
                    with urllib.request.urlopen(target["url"]+"/work", timeout=timeout) as response:
                        body = response.read(4097)
                        wanted = target.get("_expected", expected)
                        if response.status != 200 or (wanted is not None and body != wanted):
                            raise ValueError("HTTP status/body mismatch")
                row["ok"] = True
            except Exception as exc:
                row.update(ok=False, error=repr(exc))
            finally:
                row["ended"] = time.monotonic()
                record(row)
                gates[target["id"]].release()

        try:
            for ordinal in range(math.ceil(duration*qps)):
                due = start + ordinal/qps
                delay=max(0, due-time.monotonic())
                if stop is not None:
                    if stop.wait(delay):break
                else:
                    time.sleep(delay)
                for target in targets:
                    if stop is not None and stop.is_set():
                        break
                    now = time.monotonic()
                    row = dict(target=target["id"], ordinal=ordinal, scheduled=due,
                               epoch_scheduled=time.time()+(due-now), dispatch_lag=now-due,
                               sent=None, ok=False)
                    if not gates[target["id"]].acquire(blocking=False):
                        row.update(ended=now, error="load queue full", load_invalid=True)
                        record(row)
                    else:
                        pools[target["id"]].submit(work, target, row)
        finally:
            for pool in pools.values():
                pool.shutdown(wait=True)
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--targets", required=True, help="JSON list of {id,url}")
    p.add_argument("--output", required=True)
    p.add_argument("--qps", type=float, required=True)
    p.add_argument("--duration", type=float, required=True)
    p.add_argument("--start-at", type=float)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--pending", type=int, default=64)
    a = p.parse_args()
    run_load(json.loads(Path(a.targets).read_text()), a.output, a.qps, a.duration,
             a.workers, a.pending, start_at=a.start_at)


if __name__ == "__main__":
    main()
