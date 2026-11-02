# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Out-of-process Linux/Docker supervision and test-owned resource cleanup."""
import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path


def own(kind, value):
    journal = os.environ.get("HUATUO_TEST_OWNERSHIP")
    if journal:
        with open(journal, "a") as stream:
            stream.write(json.dumps(dict(kind=kind, value=value)) + "\n")
            stream.flush()


def cleanup_owned(output):
    from .linux import identity

    errors = []
    journal = Path(output) / "ownership.jsonl"
    if not journal.exists():
        return errors
    records = [json.loads(line) for line in journal.read_text().splitlines()]
    records.sort(key=lambda row: row["kind"] != "process")
    for row in records:
        try:
            value = row["value"]
            if row["kind"] == "process":
                try:
                    current = identity(value[0])
                except (OSError, RuntimeError):
                    continue
                if current != value:
                    errors.append("owned PID was reused; no signal sent")
                    continue
                os.killpg(value[0], signal.SIGKILL)
            elif row["kind"] == "config":
                config = Path(value["path"])
                if config.exists():
                    if (
                        hashlib.sha256(config.read_bytes()).hexdigest()
                        != value["sha256"]
                    ):
                        errors.append("owned kubelet config changed; not removed")
                    else:
                        config.unlink()
            elif row["kind"] == "cgroup":
                scope = Path(value)
                if scope.exists():
                    scope.rmdir()
            elif row["kind"] in ("container", "image"):
                kind = row["kind"]
                inspect = subprocess.run(
                    ["docker", kind, "inspect", value], capture_output=True, timeout=15
                )
                if inspect.returncode == 0:
                    cmd = (
                        ["docker", "rm", "-f", value]
                        if kind == "container"
                        else ["docker", "rmi", value]
                    )
                    done = subprocess.run(cmd, capture_output=True, timeout=30)
                    if done.returncode:
                        errors.append("supervisor cleanup failed: " + value)
                elif b"no such" not in inspect.stderr.lower():
                    errors.append("cannot verify cleanup of owned resource: " + value)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            errors.append(repr(exc))
    return errors


def supervise(command, output, timeout, phase_timeout, observer_timeout=10):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    reason = ""
    observed_state = None
    last_observation = started
    with (output / "controller.log").open("w") as stream:
        child = subprocess.Popen(
            command, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True
        )
        while child.poll() is None:
            now = time.monotonic()
            if now - started > timeout:
                reason = "campaign timeout"
            progress = output / "progress.json"
            finalizing = False
            if progress.exists():
                try:
                    point = json.loads(progress.read_text())
                    finalizing = point.get("phase") == "finalizing"
                    budget = max(phase_timeout, point.get("idle_budget", 0))
                    if now - point["started"] > budget:
                        reason = "phase timeout: " + point["phase"]
                except (ValueError, KeyError):
                    reason = "invalid supervisor progress checkpoint"
            elif now - started > phase_timeout:
                reason = "startup timeout"
            resource_file = output / "evidence/resources.jsonl"
            if resource_file.exists() and not finalizing:
                stat = resource_file.stat()
                current = (stat.st_mtime_ns, stat.st_size)
                if current != observed_state:
                    observed_state, last_observation = current, now
                elif now - last_observation > observer_timeout:
                    reason = "resource observer heartbeat timeout"
            if reason:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
                break
            time.sleep(0.1)
    summary_path = output / "evidence/summary.json"
    audit_path = output / "evidence/audit.json"
    evidence_passed = False
    if summary_path.exists() and audit_path.exists():
        try:
            evidence_passed = all(
                json.loads(p.read_text())["status"] == "PASS"
                for p in (summary_path, audit_path)
            )
        except (ValueError, KeyError):
            pass
    errors = (
        cleanup_owned(output)
        if reason or child.returncode or not evidence_passed
        else []
    )
    result = dict(
        status="PASS"
        if not reason and child.returncode == 0 and not errors and evidence_passed
        else "FAIL",
        reason=reason,
        returncode=child.returncode,
        cleanup_errors=errors,
        elapsed_seconds=time.monotonic() - started,
    )
    (output / "supervisor.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
