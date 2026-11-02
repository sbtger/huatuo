# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import re, time
from pathlib import Path
from ....core.util import write_control, require, wait_for
from ....environments.linux import identity
from ....core.documents import read_documents
from ..discovery import parse_timestamp
from .worker import capture_metadata_errors


def event_after_request(document, not_before):
    return not_before is None or parse_timestamp(document["started_timestamp"]).timestamp() >= not_before


class SnapshotTrigger:
    def __init__(self, owner):
        self.owner = owner

    def oom(self, t):
        return (t["cgroup"] / "memory.failcnt").read_text().strip()

    def usage(self, t):
        return int((t["cgroup"] / "memory.usage_in_bytes").read_text())

    def release(self, t):
        write_control(t["ctl"] / "target_mb", "0")
        wait_for(
            "pressure release", lambda: self.usage(t) < 400 * 1024 * 1024, timeout=20
        )

    def watch_ready(self, t):
        inode = format((t["cgroup"] / "memory.limit_in_bytes").stat().st_ino, "x")
        return any(
            re.search(r"^inotify wd:.*ino:" + inode + r" ", p.read_text(), re.M)
            for p in Path("/proc/%d/fdinfo" % self.owner.agent.pid).iterdir()
        )

    def capture(self, t, normal=False, not_before=None):
        self.release(t)
        # Threshold edges during Agent's node-wide cooldown are intentionally discarded.
        time.sleep(
            max(
                0,
                getattr(self.owner.a, "cooldown", 1)
                + 0.2
                - (time.monotonic() - self.owner.last_capture),
            )
        )
        before = len(read_documents(self.owner.event_path))
        write_control(t["ctl"] / "target_mb", "500")
        document = wait_for(
            "real Agent persisted " + t["language"] + " capture",
            lambda: next(
                (
                    d
                    for d in read_documents(self.owner.event_path)[before:]
                    if d.get("container_id") == t["cid"] and event_after_request(d, not_before)
                ),
                None,
            ),
            timeout=45,
        )
        self.owner.last_capture = time.monotonic()
        self.owner.evidence.expect_document(
            str(self.owner.event_path.relative_to(self.owner.out))
        )
        data = document["tracer_data"]
        snapshot = data["snapshot"]
        require(data["victim_pid"] == t["pid"], "Agent selected a different process")
        require(not capture_metadata_errors(data, t["language"]), "runtime or memory metadata invalid")
        result = dict(
            status=snapshot["status"],
            reason=snapshot.get("status_reason", ""),
            entries=len(snapshot.get("entries", [])),
            event_file=str(self.owner.event_path),
            agent_pid=self.owner.agent.pid,
            target_pid=t["pid"],
            event_index=read_documents(self.owner.event_path).index(document),
        )
        if not_before is not None:
            result["not_before_epoch"] = not_before
        if normal:
            attempts = [dict(result)]
            # A live CPython census can encounter changing GC metadata. Preserve each
            # failed event and require eventual nonempty recovery, without disabling GC.
            for _ in range(2):
                if (
                    t["language"] != "python"
                    or result["status"] != "failed"
                    or result["reason"]
                    != "CPython interpreter GC generations are invalid"
                ):
                    break
                result = self.capture(t, normal=False, not_before=not_before)
                attempts.append(dict(result))
            require(
                result["status"]
                in (
                    ("complete",) if t["language"] == "go" else ("complete", "partial")
                ),
                "normal runtime snapshot unavailable after bounded attempts: "
                + str(attempts),
            )
            require(result["entries"] > 0, "empty normal snapshot")
            require(
                identity(t["pid"]) == t["identity"],
                "business identity changed during snapshot",
            )
            result["normal_attempts"] = attempts
        return result
