# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Example workload contract; the core has no HTTP or state-formula knowledge."""
import concurrent.futures, json, threading, time, urllib.request
from pathlib import Path
from ..core.util import require, wait_for
from ..environments.linux import identity

EXPECTED = b"feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d\n"


def request_http(url, path, post=False):
    req = urllib.request.Request(url + path, data=b"" if post else None)
    with urllib.request.urlopen(req, timeout=1) as response:
        require(response.status == 200, "HTTP status %d" % response.status)
        return response.read()


def validate_phase(p):
    errors = []
    checks = [
        (p["samples"] > 0, "empty observation phase"),
        (not p["errors"], "business request errors"),
        (p["identity_before"] == p["identity_after"], "process identity changed"),
        (p["tick_after"] > p["tick_before"], "background task stalled"),
        (p["seq_after"] > p["seq_before"], "transactions stalled"),
        (
            p["total"] == 13 * p["seq_after"] * (p["seq_after"] + 1) // 2,
            "business state mismatch",
        ),
        (not p["fault_expected"] or p["fault_hits"] > 0, "fault was not reached"),
        (p["scheduled"] == p["completed"], "scheduled requests were lost"),
        (
            p["largest_success_gap"] <= p["max_gap"],
            "service progress gap exceeded bound",
        ),
    ]
    for ok, message in checks:
        if not ok:
            errors.append(message)
    return errors


class Traffic:
    def __init__(self, target, out, qps):
        self.t = target
        self.target_id = target["language"]
        self.qps = qps
        self.phase = "warmup"
        self.seq = 0
        self.lock = threading.Lock()
        self.txnlock = threading.Lock()
        self.rows = []
        self.pending = {}
        self.scheduled = {}
        self.last_tick = -1
        self.tick_advanced = time.monotonic()
        self.stop = threading.Event()
        self.expected_identity = identity(target["pid"])
        self.file = (out / (target["language"] + "-requests.jsonl")).open("w")
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self.threads = [
            threading.Thread(target=self.workload, daemon=True),
            threading.Thread(target=self.transactions, daemon=True),
        ]

    def start(self):
        for t in self.threads:
            t.start()

    def record(self, phase, kind, ok, detail="", at=None):
        row = dict(
            phase=phase,
            kind=kind,
            ok=ok,
            detail=detail,
            time=time.monotonic() if at is None else at,
        )
        with self.lock:
            self.rows.append(row)
            self.file.write(json.dumps(row) + "\n")
            self.file.flush()

    def work(self, phase):
        ok = True
        err = ""
        try:
            require(
                request_http(self.t["url"], "/work") == EXPECTED, "wrong work checksum"
            )
        except Exception as e:
            ok = False
            err = str(e)
        self.record(phase, "work", ok, err)
        with self.lock:
            self.pending[phase] -= 1

    def workload(self):
        deadline = time.monotonic()
        while not self.stop.is_set():
            self.stop.wait(max(0, deadline - time.monotonic()))
            if self.stop.is_set():
                break
            phase = self.phase
            lag = time.monotonic() - deadline
            if lag > 0.5:
                self.record(
                    phase,
                    "scheduler",
                    False,
                    "open-loop scheduler missed deadline by %.3fs" % lag,
                )
            with self.lock:
                self.pending[phase] = self.pending.get(phase, 0) + 1
                self.scheduled[phase] = self.scheduled.get(phase, 0) + 1
            self.pool.submit(self.work, phase)
            deadline += 1 / self.qps

    def transactions(self):
        while not self.stop.is_set():
            phase = self.phase
            try:
                with self.txnlock:
                    n = self.seq + 1
                    ack = json.loads(
                        request_http(self.t["url"], "/txn?seq=%d" % n, True)
                    )
                    require(
                        ack["seq"] == n and ack["total"] == 13 * n * (n + 1) // 2,
                        "transaction acknowledgment mismatch",
                    )
                    self.seq = n
                    state = json.loads(request_http(self.t["url"], "/state"))
                    require(
                        state["seq"] == n and state["total"] == ack["total"],
                        "committed state was lost or corrupted",
                    )
                    if state["ticks"] > self.last_tick:
                        self.last_tick = state["ticks"]
                        self.tick_advanced = time.monotonic()
                    require(
                        time.monotonic() - self.tick_advanced < 2,
                        "background task made no progress for 2 seconds",
                    )
                    require(
                        identity(self.t["pid"]) == self.expected_identity,
                        "business PID/start time changed",
                    )
                self.record(phase, "transaction", True)
            except Exception as e:
                self.record(phase, "transaction", False, str(e))
            self.stop.wait(0.2)

    def state(self):
        with self.txnlock:
            state = json.loads(request_http(self.t["url"], "/state"))
            require(state["seq"] == self.seq, "unexpected business state sequence")
            return state

    def begin(self, name):
        before = self.state()
        started = time.monotonic()
        self.phase = name
        return before, started

    def finish(self, name, before, started, hits, expected):
        self.phase = "between"
        wait_for(
            "outstanding business requests",
            lambda: self.pending.get(name, 0) == 0,
            timeout=3,
            period=0.02,
        )
        after = self.state()
        ended = time.monotonic()
        with self.lock:
            rows = [r for r in self.rows if r["phase"] == name]
        work = [r for r in rows if r["kind"] == "work"]
        times = [started] + [r["time"] for r in work if r["ok"]] + [ended]
        times.sort()
        p = dict(
            samples=len(work),
            errors=[r for r in rows if not r["ok"]],
            identity_before=self.expected_identity,
            identity_after=identity(self.t["pid"]),
            tick_before=before["ticks"],
            tick_after=after["ticks"],
            seq_before=before["seq"],
            seq_after=after["seq"],
            total=after["total"],
            fault_expected=expected,
            fault_hits=hits,
            scheduled=self.scheduled.get(name, 0),
            completed=len(work),
            largest_success_gap=max(b - a for a, b in zip(times, times[1:])),
            max_gap=2.0,
            seconds=ended - started,
        )
        p["assertion_errors"] = validate_phase(p)
        return p

    def close(self):
        if self.file.closed:
            return
        self.stop.set()
        for t in self.threads:
            t.join(3)
        self.pool.shutdown(wait=True)
        self.file.close()
        require(
            not any(t.is_alive() for t in self.threads),
            "business observer did not stop",
        )
        require(
            sum(self.scheduled.values()) == sum(r["kind"] == "work" for r in self.rows),
            "aggregate scheduled business requests were lost",
        )

    def totals(self):
        return dict(
            requests=sum(r["kind"] == "work" for r in self.rows), transactions=self.seq
        )

    def records(self):
        return self.rows
