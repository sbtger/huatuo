# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Reconcile phase claims with raw HuaTuo fault markers, snapshots and logs."""
import json
import re
from pathlib import Path
from ....core.documents import read_documents
from .assertions import validate_fault
from .log_policy import unexpected_logs


def audit_artifacts(output, summary, manifest):
    rejected = {}
    allowed = {}
    errors = []
    log_texts = {}
    for artifact in manifest["artifacts"]:
        if artifact["role"] != "agent_log":
            continue
        name = artifact["path"]
        text = (output / name).read_text()
        log_texts[name] = text
        config = name.replace("agent-", "bamai-").replace(".log", ".conf")
        invalid = "ThresholdPercent = 101" in (output / config).read_text()
        full = "action=mark" in text and re.search(r"id=\S+/storage_full ", text)
        bad = unexpected_logs(text, storage_full=bool(full), invalid_config=invalid)
        if bad:
            rejected[name] = bad
        allowed[name] = sum(
            bool(re.search(r'level="(?:warn|warning|error|panic|fatal)"', line))
            for line in text.splitlines()
        ) - len(bad)
    targets = {
        target["language"]: target
        for target in json.loads((output / "environment.json").read_text())["targets"]
    }
    for case in summary["cases"]:
        target = targets[case["target_id"]]
        mode = case["name"].split("/", 1)[1]
        detail = case["detail"]
        logs = [name for name in case["evidence"] if name in log_texts]
        text = "\n".join(log_texts[name] for name in logs)
        if case["expect_fault"]:
            prefix = "MEMSNAP_FAULT id=" + case["name"] + " "
            markers = re.findall(
                re.escape(prefix) + r"action=(\S+) pid=(\d+) stage=(\S+)", text
            )
            action = "mark" if mode == "permission" else mode
            stage = "provider" if mode in ("panic", "cancel") else "read"
            valid = [m for m in markers if m == (action, str(target["pid"]), stage)]
            if not valid or len(valid) != case["fault_hits"]:
                errors.append("raw fault marker attribution mismatch: " + case["name"])
        attempts = detail.get("normal_attempts") or (
            [detail] if detail.get("event_file") else []
        )
        for attempt in attempts:
            original = Path(attempt["event_file"])
            relative = str(Path(original.parent.name) / original.name)
            if relative not in case["evidence"]:
                errors.append("snapshot not referenced by phase: " + case["name"])
                continue
            documents = read_documents(output / relative)
            matching = []
            for document in documents:
                data = document["tracer_data"]
                snapshot = data["snapshot"]
                actual = dict(
                    status=snapshot["status"],
                    reason=snapshot.get("status_reason", ""),
                    entries=len(snapshot.get("entries", [])),
                )
                if (
                    document["container_id"] == target["cid"]
                    and data["victim_pid"] == target["pid"]
                    and data["language"] == case["target_id"]
                    and data["process_memory"]["rss_bytes"] > 0
                    and all(actual[k] == attempt[k] for k in actual)
                ):
                    matching.append(actual)
            if not matching:
                errors.append("raw snapshot disagrees with phase: " + case["name"])
            elif case["expect_fault"] and mode in (
                "permission",
                "efault",
                "short",
                "panic",
                "cancel",
                "delay",
            ):
                errors.extend(
                    case["name"] + ": " + issue
                    for issue in validate_fault(mode, matching[-1])
                )
        if detail.get("normal_attempts"):
            acceptable = (
                ("complete",) if case["target_id"] == "go" else ("complete", "partial")
            )
            if (
                len(attempts) > 3
                or attempts[-1]["status"] not in acceptable
                or attempts[-1]["entries"] <= 0
            ):
                errors.append("normal recovery is unavailable: " + case["name"])
            for attempt in attempts[:-1]:
                if (
                    case["target_id"] != "python"
                    or attempt["status"] != "failed"
                    or attempt["reason"]
                    != "CPython interpreter GC generations are invalid"
                ):
                    errors.append("unsupported normal capture retry: " + case["name"])
        if mode in ("block", "kill_after_read"):
            if detail.get("exit_signal") != "SIGKILL" or not detail.get(
                "agent_http_responsive"
            ):
                errors.append(
                    "blocked-reader containment not witnessed: " + case["name"]
                )
            if (
                mode == "kill_after_read"
                and "MEMSNAP_READ_COMPLETED id=" + case["name"] + " " not in text
            ):
                errors.append("completed read was not witnessed: " + case["name"])
            for name in logs:
                number = Path(name).stem[len("agent-") :]
                event = output / ("events-" + number) / "memory_threshold_snapshot"
                if event.exists():
                    if (
                        output.resolve() not in event.resolve().parents
                        or read_documents(event)
                    ):
                        errors.append(
                            "blocked capture unexpectedly persisted: " + case["name"]
                        )
        if mode == "storage_full" and "no space left on device" not in text:
            errors.append("storage failure not witnessed: " + case["name"])
        if (
            mode == "invalid_config"
            and "threshold percent must be in [1, 100]" not in text
        ):
            errors.append("configuration rejection not witnessed: " + case["name"])
    return dict(
        errors=errors, unexpected_agent_logs=rejected, expected_fault_log_counts=allowed
    )
