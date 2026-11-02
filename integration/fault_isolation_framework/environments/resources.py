# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Continuous Agent/resource observation independent of scenario operations."""
import json
import threading
import time
from pathlib import Path
from .linux import identity


def inotify_watch_count(fdinfo):
    count = 0
    for path in Path(fdinfo).iterdir():
        try:
            count += sum(
                line.startswith("inotify ") for line in path.read_text().splitlines()
            )
        except FileNotFoundError:
            # A live Agent may close a descriptor between listing and reading it.
            continue
    return count


def sample_process(pid):
    root = Path("/proc/%d" % pid)
    ident = identity(pid)
    status = dict(
        line.split(":", 1)
        for line in (root / "status").read_text().splitlines()
        if ":" in line
    )
    return dict(
        agent=ident,
        rss_bytes=int(status["VmRSS"].split()[0]) * 1024,
        fds=len(list((root / "fd").iterdir())),
        threads=int(status["Threads"]),
        inotify_watches=inotify_watch_count(root / "fdinfo"),
        settled=False,
    )


class ResourceMonitor:
    def __init__(self, owner, interval=2):
        self.owner = owner
        self.interval = interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.rows = []
        self.lock = threading.Lock()
        self.path = owner.out / "resources.jsonl"
        self.stream = self.path.open("w")
        owner.evidence.register(self.path.name, "resource_samples", format="jsonl")

    def record(self, settled=False, baseline=False):
        row = dict(time=time.monotonic(), phase=self.owner.case_name, agent=None)
        try:
            agent = self.owner.agent
            if (
                agent is not None
                and agent.poll() is not None
                and not self.owner.agent_transition
            ):
                raise RuntimeError("Agent exited outside a declared replacement")
            if agent is not None and agent.poll() is None:
                row.update(sample_process(agent.pid))
                row["settled"] = settled
                row["baseline"] = baseline
            for process in getattr(self.owner, "extra_processes", []):
                if process.process is None or process.process.poll() is not None:
                    raise RuntimeError(
                        "ranking helper exited; process-scale load disappeared"
                    )
            for probe in self.owner.probes:
                if any(not t.is_alive() for t in probe.threads):
                    raise RuntimeError(
                        "business observer thread stopped: " + probe.target_id
                    )
        except (OSError, ValueError, RuntimeError, KeyError) as exc:
            if not self.owner.agent_transition:
                row["error"] = repr(exc)
        with self.lock:
            self.rows.append(row)
            self.stream.write(json.dumps(row) + "\n")
            self.stream.flush()
        return row

    def loop(self):
        last = time.monotonic()
        while not self.stop.wait(self.interval):
            now = time.monotonic()
            if now - last > max(10, self.interval * 4):
                with self.lock:
                    row = dict(
                        time=now, error="resource observer sampling gap", agent=None
                    )
                    self.rows.append(row)
                    self.stream.write(json.dumps(row) + "\n")
            self.record()
            last = now

    def start(self):
        self.record()
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise RuntimeError("resource observer did not stop")
        self.stream.close()
