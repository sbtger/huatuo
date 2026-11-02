# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real host anonymous-memory edges and cgroup edges; no procfs substitution."""
import time
import math
from pathlib import Path
import os
from ....core.documents import read_documents
from ....core.util import write_control, require, wait_for
from ....environments.linux import identity
from ..memsnapshot.trigger import SnapshotTrigger, event_after_request
from ..memsnapshot.worker import capture_metadata_errors


def burst_anon_floor(total_kib, baseline_kib):
    percent = math.ceil((baseline_kib + 256 * 1024) * 100 / total_kib)
    require(
        0 <= percent <= 100 and total_kib * percent / 100 < baseline_kib + 500 * 1024,
        "VM memory scale cannot express a safe 500MiB anonymous-pressure floor",
    )
    return percent


class StabilityTrigger(SnapshotTrigger):
    def release_all(self):
        for target in self.owner.targets:
            self.release(target)

    def pressure(self, target):
        if self.owner.tracer_name == "memburst":
            self.release_all()
            self.release(target)
            # Fill the two-sample baseline with real low anonymous-memory use.
            time.sleep(2.2)
            driver = (
                target
                if target["language"] == "go"
                else next(t for t in self.owner.targets if t["language"] == "go")
            )
            if target["language"] != "go":
                write_control(target["ctl"] / "target_mb", "500")
                wait_for(
                    "non-Go target resident before anonymous trigger",
                    lambda: int(
                        Path("/proc/%d/statm" % target["pid"]).read_text().split()[1]
                    )
                    * os.sysconf("SC_PAGE_SIZE")
                    > 450 * 1024 * 1024,
                    timeout=25,
                )
            write_control(driver["ctl"] / "target_mb", "500")
        else:
            write_control(target["ctl"] / "target_mb", "500")

    def capture(self, target, normal=False, not_before=None):
        if self.owner.tracer_name != "memburst":
            return super().capture(target, normal, not_before=not_before)
        self.release_all()
        self.release(target)
        time.sleep(
            max(
                0,
                self.owner.a.cooldown
                + 0.5
                - (time.monotonic() - self.owner.last_capture),
            )
        )
        before = len(read_documents(self.owner.event_path))
        self.pressure(target)

        def find():
            for index, doc in enumerate(
                read_documents(self.owner.event_path)[before:], before
            ):
                if not event_after_request(doc, not_before):
                    continue
                records = doc.get("tracer_data", {}).get("process_snapshots", [])
                record = next((r for r in records if r["pid"] == target["pid"]), None)
                if record:
                    return index, doc, record
            return None

        index, doc, record = wait_for(
            "real memburst ranked target capture", find, timeout=40
        )
        self.owner.last_capture = time.monotonic()
        self.owner.evidence.expect_document(
            str(self.owner.event_path.relative_to(self.owner.out))
        )
        ranking = doc["tracer_data"]["top_memory_usage"]
        snapshots = doc["tracer_data"]["process_snapshots"]
        require(
            [r["MemSize"] for r in ranking]
            == sorted((r["MemSize"] for r in ranking), reverse=True),
            "memburst ranking is not in RSS order",
        )
        require(
            len(snapshots) <= 3
            and all(r["pid"] == ranking[i]["PID"] for i, r in enumerate(snapshots)),
            "memburst snapshots differ from the first three ranked processes",
        )
        require(not capture_metadata_errors(record, target["language"]), "memburst runtime or memory metadata invalid")
        require(
            identity(target["pid"]) == target["identity"], "target identity changed"
        )
        snapshot = record["snapshot"]
        result = dict(
            status=snapshot["status"],
            reason=snapshot.get("status_reason", ""),
            entries=len(snapshot.get("entries", [])),
            event_file=str(self.owner.event_path),
            event_index=index,
            target_pid=target["pid"],
            agent_pid=self.owner.agent.pid,
        )
        if not_before is not None:
            result["not_before_epoch"] = not_before
        if normal:
            attempts = [dict(result)]
            for _ in range(2):
                if (
                    target["language"] != "python"
                    or result["status"] != "failed"
                    or result["reason"]
                    != "CPython interpreter GC generations are invalid"
                ):
                    break
                result = self.capture(target, not_before=not_before)
                attempts.append(dict(result))
            require(
                result["status"]
                in (
                    ("complete",)
                    if target["language"] == "go"
                    else ("complete", "partial")
                )
                and result["entries"] > 0,
                "normal memburst capture unavailable: " + str(attempts),
            )
            result["normal_attempts"] = attempts
        return result
