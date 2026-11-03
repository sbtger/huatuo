# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Read-only Linux measurements; parent and waited-child CPU plus sampled live-worker resources."""
import json
import os
import threading
import time
from pathlib import Path


def parse_stat(text, ticks):
    prefix, tail = text.rsplit(") ", 1)
    fields = tail.split()
    if fields[0] in ("Z", "X"):
        raise ProcessLookupError("process exited")
    return dict(identity=[int(prefix.split(" ", 1)[0]), int(fields[19])],
                cpu_seconds=(int(fields[11])+int(fields[12]))/ticks,
                waited_children_cpu_seconds=(int(fields[13])+int(fields[14]))/ticks,
                minor_faults=int(fields[7]), major_faults=int(fields[9]))


def process_sample(pid):
    root = Path("/proc")/str(pid)
    row = parse_stat((root/"stat").read_text(), os.sysconf("SC_CLK_TCK"))
    status = dict(line.split(":", 1) for line in (root/"status").read_text().splitlines() if ":" in line)
    if "VmRSS" not in status:
        raise ProcessLookupError("RSS unavailable during process exit")
    row.update(rss_bytes=int(status["VmRSS"].split()[0])*1024,
               threads=int(status["Threads"]), fds=len(list((root/"fd").iterdir())),
               voluntary_switches=int(status.get("voluntary_ctxt_switches", 0)),
               involuntary_switches=int(status.get("nonvoluntary_ctxt_switches", 0)))
    row["io"] = dict((key, int(value)) for key, value in
                     (line.split(":", 1) for line in (root/"io").read_text().splitlines()))
    if parse_stat((root/"stat").read_text(), os.sysconf("SC_CLK_TCK"))["identity"] != row["identity"]:
        raise ProcessLookupError("PID reused during observation")
    return row


def descendants(pid):
    found, todo = set(), [pid]
    while todo:
        parent = todo.pop()
        try:
            tasks = list((Path("/proc")/str(parent)/"task").iterdir())
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                children = map(int, (task/"children").read_text().split())
                for child in children:
                    if child not in found:
                        found.add(child)
                        todo.append(child)
            except FileNotFoundError:
                continue
    return sorted(found)


def read_optional(path):
    try:
        return Path(path).read_text().strip()
    except FileNotFoundError:
        return None


class PerformanceSampler:
    def __init__(self, owner, path, interval=.1):
        self.owner, self.path, self.interval = owner, Path(path), interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.rows = []
        self.stream = self.path.open("x")

    def record(self):
        row = dict(time=time.monotonic(), epoch=time.time(), processes={}, cgroups={}, errors=[])
        for target in getattr(self.owner, "measurement_targets", self.owner.targets):
            key = target["id"]
            try:
                proc = process_sample(target["pid"])
                if proc["identity"] != target["identity"]:
                    raise ProcessLookupError("target identity changed")
                row["processes"][key] = proc
                cg = target["cgroup"]
                row["cgroups"][key] = {name: read_optional(cg/name) for name in (
                    "memory.usage_in_bytes", "memory.max_usage_in_bytes", "memory.failcnt", "memory.stat")}
            except (OSError, ValueError, KeyError) as exc:
                row["errors"].append(key+": "+repr(exc))
        helper=getattr(self.owner,'snapshot_helper',None)
        if helper is not None:
            try:
                if helper.poll() is not None:raise ProcessLookupError('snapshot helper exited')
                row['processes']['snapshot-helper']=process_sample(helper.pid)
                for pid in descendants(helper.pid):
                    try:row['processes']['snapshot-child-%d'%pid]=process_sample(pid)
                    except (FileNotFoundError,ProcessLookupError):continue
            except (OSError,ValueError,KeyError) as exc:row['errors'].append('snapshot helper: '+repr(exc))
        if self.owner.agent is not None:
            try:
                if self.owner.agent.poll() is not None:
                    raise ProcessLookupError("Agent exited")
                row["processes"]["agent"] = process_sample(self.owner.agent.pid)
                for pid in descendants(self.owner.agent.pid):
                    try:
                        row["processes"]["child-%d" % pid] = process_sample(pid)
                    except (FileNotFoundError, ProcessLookupError):
                        # Short-lived children are expected; never invent lifetime CPU.
                        continue
            except (OSError, ValueError, KeyError) as exc:
                row["errors"].append("agent: "+repr(exc))
        row["business_memory"] = {target["id"]:cgroup_memory(target["cgroup"]) for target in getattr(self.owner,"measurement_targets",self.owner.targets)}
        row["memory_scopes"] = {name:cgroup_memory(path) for name,path in getattr(self.owner,"memory_scopes",{}).items()}
        row["host"] = {name: read_optional("/proc/"+name) for name in (
            "stat", "meminfo", "vmstat", "pressure/cpu", "pressure/memory", "pressure/io")}
        self.rows.append(row)
        self.stream.write(json.dumps(row)+"\n")
        self.stream.flush()

    def loop(self):
        while not self.stop.wait(self.interval):
            try:
                self.record()
            except Exception as exc:
                row = dict(time=time.monotonic(), errors=[repr(exc)], processes={})
                self.rows.append(row)
                self.stream.write(json.dumps(row)+"\n")
                self.stream.flush()

    def start(self):
        self.record()
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(10)
        if self.thread.is_alive():
            raise RuntimeError("performance sampler did not stop")
        self.record()
        self.stream.close()


def resource_metrics(rows, start, end):
    window = [r for r in rows if start <= r["time"] <= end]
    result = dict(samples=len(window), errors=sum(len(r["errors"]) for r in window))
    peaks, cpu, previous = [], 0, {}
    parent_cpu, waited_cpu, previous_parent = 0, 0, {}
    for row in window:
        rss = 0
        for key, proc in row["processes"].items():
            if key != "agent" and not key.startswith("child-"):
                continue
            rss += proc["rss_bytes"]
            ident = tuple(proc["identity"])
            if ident in previous:
                cpu += max(0, proc["cpu_seconds"]-previous[ident])
            # Unknown first-seen child lifetime before first sample is omitted.
            previous[ident] = proc["cpu_seconds"]
        parent = row["processes"].get("agent")
        if parent:
            ident = tuple(parent["identity"])
            current = (parent["cpu_seconds"], parent.get("waited_children_cpu_seconds", 0))
            if ident in previous_parent:
                before = previous_parent[ident]
                parent_cpu += max(0, current[0]-before[0])
                waited_cpu += max(0, current[1]-before[1])
            previous_parent[ident] = current
        peaks.append(rss)
    result.update(cpu_seconds=parent_cpu+waited_cpu, cpu_average_cores=(parent_cpu+waited_cpu)/(end-start),
                  agent_self_cpu_seconds=parent_cpu, waited_children_cpu_seconds=waited_cpu,
                  sampled_tree_cpu_seconds=cpu, sampled_agent_tree_rss_peak_bytes=max(peaks, default=0),
                  agent_fd_peak=max((r["processes"].get("agent", {}).get("fds", 0) for r in window), default=0),
                  agent_thread_peak=max((r["processes"].get("agent", {}).get("threads", 0) for r in window), default=0),
                  cpu_accounting="Agent self plus waited-child delta; child CPU attributed at reap, live/unreaped children excluded; sampled tree reported separately, never added")
    result["business"] = {}
    keys = {key for row in window for key in row["processes"] if key != "agent" and not key.startswith("child-")}
    for key in sorted(keys):
        samples = [row["processes"][key] for row in window if key in row["processes"]]
        counter_delta = {}
        for field in ("cpu_seconds", "waited_children_cpu_seconds", "minor_faults", "major_faults", "voluntary_switches", "involuntary_switches"):
            if field in samples[0] and samples[0]["identity"] == samples[-1]["identity"]:
                counter_delta[field] = max(0, samples[-1][field]-samples[0][field])
        counter_delta["total_cpu_seconds"] = counter_delta.get("cpu_seconds", 0)+counter_delta.get("waited_children_cpu_seconds", 0)
        counter_delta["rss_peak_bytes"] = max(p["rss_bytes"] for p in samples)
        result["business"][key] = counter_delta
    return result


def cgroup_memory(path):
    path=Path(path);v2=(path/'memory.current').exists()
    names=('memory.current','memory.max','memory.peak','memory.events','memory.stat','memory.pressure','cpu.stat','io.stat') if v2 else ('memory.usage_in_bytes','memory.limit_in_bytes','memory.max_usage_in_bytes','memory.failcnt','memory.oom_control','memory.stat')
    raw={name:(path/name).read_text().strip() if (path/name).exists() else None for name in names}
    current=raw['memory.current' if v2 else 'memory.usage_in_bytes'];limit=raw['memory.max' if v2 else 'memory.limit_in_bytes']
    events={}
    for line in (raw['memory.events' if v2 else 'memory.oom_control'] or '').splitlines():
        words=line.split()
        if len(words)==2 and words[1].isdigit():events[words[0]]=int(words[1])
    return dict(version=2 if v2 else 1,current_bytes=int(current) if current else None,limit_bytes=int(limit) if limit and limit!='max' else None,
                lifetime_peak_bytes=int(raw['memory.peak' if v2 else 'memory.max_usage_in_bytes']) if raw.get('memory.peak' if v2 else 'memory.max_usage_in_bytes') else None,
                oom_kills=events.get('oom_kill'),allocation_failures=None if v2 else int(raw['memory.failcnt']) if raw.get('memory.failcnt') is not None else None,
                psi_scope='business cgroup' if v2 and raw.get('memory.pressure') else 'unavailable at cgroup scope',raw=raw)
