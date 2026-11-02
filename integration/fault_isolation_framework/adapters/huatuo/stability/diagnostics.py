# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Read-only failure evidence before the runner tears down owned processes."""
import json
import time
from pathlib import Path


def capture_failure(owner, error):
    def read(path):
        try:
            return Path(path).read_text()
        except OSError as exc:
            return repr(exc)

    data = dict(
        error=repr(error),
        phase=owner.case_name,
        wall=time.time(),
        monotonic=time.monotonic(),
        last_capture=owner.last_capture,
        targets=[],
    )
    for target in owner.targets:
        row = dict(
            language=target["language"],
            pid=target["pid"],
            cgroup=str(target["cgroup"]),
            requested_mb=read(target["ctl"] / "target_mb"),
        )
        for name in (
            "memory.usage_in_bytes",
            "memory.limit_in_bytes",
            "memory.stat",
            "memory.failcnt",
        ):
            row[name] = read(target["cgroup"] / name)
        row["proc_status"] = read("/proc/%d/status" % target["pid"])
        data["targets"].append(row)
    if owner.agent:
        data["agent_pid"] = owner.agent.pid
        data["agent_returncode"] = owner.agent.poll()
        root = Path("/proc/%d/fdinfo" % owner.agent.pid)
        try:
            data["fdinfo"] = {p.name: read(p) for p in root.iterdir()}
        except OSError as exc:
            data["fdinfo_error"] = repr(exc)
    name = "diagnostic-" + owner.case_name.replace("/", "_") + ".json"
    owner.evidence.register(name, "capture_diagnostics", format="json")
    (owner.out / name).write_text(json.dumps(data, indent=2) + "\n")
    return name
