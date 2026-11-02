# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Bind repeated phase claims to exact raw event indices and fault markers."""
import json
import datetime as dt
import re
from pathlib import Path
from ....core.documents import read_documents
from ....core.stability import coverage_errors, resource_errors
from .reliability import audit_check, selected_check_errors
from ..memsnapshot.trigger import event_after_request
from ..memsnapshot.assertions import validate_fault
from ..memsnapshot.log_policy import unexpected_logs


def captures(detail):
    if isinstance(detail, list):
        for item in detail:
            yield from captures(item)
    elif isinstance(detail, dict):
        if detail.get("event_file"):
            if detail.get("normal_attempts"):
                for attempt in detail["normal_attempts"]:
                    yield {**attempt, "target_language": detail.get("target_language")}
            else:
                yield detail
        else:
            for value in detail.values():
                if isinstance(value, (dict, list)):
                    yield from captures(value)


def normal_results(detail):
    if isinstance(detail, list):
        for item in detail:
            yield from normal_results(item)
    elif isinstance(detail, dict):
        if detail.get("event_file") and detail.get("normal_attempts"):
            yield detail
        else:
            for value in detail.values():
                if isinstance(value, (dict, list)):
                    yield from normal_results(value)


def normal_capture_errors(result, language):
    attempts = result.get("normal_attempts", [])
    acceptable = ("complete",) if language == "go" else ("complete", "partial")
    if (
        not attempts
        or len(attempts) > 3
        or attempts[-1]["status"] not in acceptable
        or attempts[-1]["entries"] <= 0
    ):
        return ["normal recovery is unavailable or exceeds retry budget"]
    if any(
        language != "python"
        or item["status"] != "failed"
        or item["reason"] != "CPython interpreter GC generations are invalid"
        for item in attempts[:-1]
    ):
        return ["unsupported normal capture retry"]
    return []


def phase_counts(cases):
    return dict(
        captures=sum(1 for c in cases for _ in normal_results(c["detail"])),
        cgroup_replacements=sum(
            len(c["detail"].get("replacements", [])) for c in cases
        ),
        limit_changes=sum(
            len(c["detail"].get("captures", []))
            for c in cases
            if c["name"].endswith("/limit-change")
        ),
        observed_pid_reuse=sum(
            bool(r.get("observed_pid_reuse"))
            for c in cases
            for r in c["detail"].get("replacements", [])
        ),
    )


def audit_artifacts(output, summary, manifest):
    output = Path(output)
    errors, rejected, allowed = [], {}, {}
    campaign = json.loads((output / "campaign.json").read_text())
    environment = json.loads((output / "environment.json").read_text())
    errors += selected_check_errors(
        environment.get("command_line", []), summary["cases"]
    )
    cycles = [
        json.loads(line) for line in (output / "cycles.jsonl").read_text().splitlines()
    ]
    resources = [
        json.loads(line)
        for line in (output / "resources.jsonl").read_text().splitlines()
    ]
    errors += coverage_errors(
        campaign["planned_cycles"],
        campaign["minimum_seconds"],
        cycles,
        campaign["elapsed_seconds"],
    )
    if campaign["status"] != "PASS":
        errors.append("campaign final checks failed")
    if (
        resources
        and resources[-1]["time"] - resources[0]["time"] + 2
        < campaign["minimum_seconds"]
    ):
        errors.append("raw resource observation does not cover minimum duration")
    actual_counts = phase_counts(summary["cases"])
    actual_counts["agent_replacements"] = max(
        0, sum(a["role"] == "agent_config" for a in manifest["artifacts"]) - 1
    )
    if actual_counts != campaign["counts"]:
        errors.append("campaign coverage counters disagree with raw phase operations")
    if not any(row.get("baseline") for row in resources):
        errors.append("no fully warmed Agent growth baseline")
    limits = campaign["resource_limits"]
    errors += resource_errors(resources, **limits)
    if cycles and cycles[-1]["counts"] != campaign["counts"]:
        errors.append("raw cycle counters differ from campaign totals")
    full_logs = {
        name
        for c in summary["cases"]
        if c["name"].endswith("/storage-full")
        and c["detail"].get("storage_failure") == "ENOSPC"
        for name in c["evidence"]
        if name.endswith(".log")
    }
    lifecycle_windows = [
        r for c in summary["cases"] for r in c["detail"].get("replacements", [])
    ]
    lifecycle_windows += [
        c["detail"]["exit_window"]
        for c in summary["cases"]
        if c["detail"].get("exit_window")
    ]
    fd_logs = {
        name
        for c in summary["cases"]
        if c["detail"].get("resource_fault") == "agent-fd"
        for name in c["evidence"]
        if name.endswith(".log")
    }
    for artifact in manifest["artifacts"]:
        if artifact["role"] != "agent_log":
            continue
        name = artifact["path"]
        text = (output / name).read_text()
        # Generalize only the writer's tracer name; no generic warning suppression.
        checked = text.replace("memburst", "memory_threshold_snapshot")
        bad = unexpected_logs(checked, storage_full=name in full_logs)
        kept = []
        for line in bad:
            stamp = re.search(r'time="([^"]+)"', line)
            when = dt.datetime.fromisoformat(stamp.group(1)).timestamp() if stamp else 0
            transient = any(
                r["cid"] in line and r["window_started"] <= when <= r["window_finished"]
                for r in lifecycle_windows
            )
            expected_refresh = (
                'msg="refresh container view"' in line
                or 'msg="memory snapshot waiting for a complete container view"' in line
                or 'msg="memory watch target unavailable; skipping cgroup instance"'
                in line
            )
            if not (
                transient
                and expected_refresh
                and (
                    "creation is not yet reflected by kubelet" in line
                    or (
                        "memory watch target unavailable; skipping cgroup instance"
                        in line
                        and 'error="<nil>"' in line
                    )
                )
            ):
                kept.append(line)
        bad = kept
        if name in fd_logs:
            bad = [line for line in bad if "too many open files" not in line.lower()]
        if bad:
            rejected[name] = bad
        allowed[name] = len(
            re.findall(r'level="?(?:warn|warning|error|panic|fatal)', text)
        ) - len(bad)
    used_events = set()
    for case in summary["cases"]:
        detail = case["detail"]
        errors += audit_check(output, case)
        mode = detail.get("fault_mode", detail.get("action"))
        for result in normal_results(detail):
            errors += normal_capture_errors(
                result, result.get("target_language", case["target_id"])
            )
        if detail.get("resource_fault"):
            witness = json.loads((output / detail["witness"]).read_text())
            if witness != {
                k: v for k, v in detail.items() if k not in ("witness", "module")
            }:
                errors.append("raw resource fault witness differs from phase")
            if detail["resource_fault"] == "agent-oom" and not (
                witness["oom_kill_after"] > witness["oom_kill_before"]
                and witness["exitcode"] == -9
            ):
                errors.append("kernel OOM witness missing")
        logs = "\n".join(
            (output / name).read_text()
            for name in case["evidence"]
            if name.endswith(".log")
        )
        if case["expect_fault"]:
            stage = "provider" if mode in ("panic", "cancel") else "read"
            marker = "MEMSNAP_FAULT id=%s action=%s pid=%d stage=%s" % (
                case["name"],
                detail["action"],
                detail["target_pid"],
                stage,
            )
            if not mode or logs.count(marker) != case["fault_hits"]:
                errors.append("fault witness attribution mismatch: " + case["name"])
        if mode in ("block", "kill_after_read"):
            witness = detail.get("witness")
            if (
                not witness
                or witness not in case["evidence"]
                or ('tracing="' + detail["module"] + '"')
                not in (output / witness).read_text()
            ):
                errors.append("blocked Agent HTTP has no registered raw witness")
            for name in case["evidence"]:
                if name.startswith("agent-") and name.endswith(".log"):
                    number = Path(name).stem[len("agent-") :]
                    event = output / ("events-" + number) / detail["module"]
                    if event.exists() and (
                        output.resolve() not in event.resolve().parents
                        or read_documents(event)
                    ):
                        errors.append("blocked capture unexpectedly persisted")
            if detail.get("exit_signal") != "SIGKILL" or not detail.get(
                "agent_http_responsive"
            ):
                errors.append("blocked Agent containment was not witnessed")
            if (
                mode == "kill_after_read"
                and "MEMSNAP_READ_COMPLETED id=" + case["name"] not in logs
            ):
                errors.append("completed read marker missing")
        if (
            detail.get("resource_fault") == "agent-fd"
            and "too many open files" not in logs.lower()
        ):
            errors.append("raw EMFILE witness missing")
        if (
            case["name"].endswith("/storage-full")
            and "no space left on device" not in logs
        ):
            errors.append("storage fault not reached: " + case["name"])
        for attempt in captures(detail):
            original = Path(attempt["event_file"])
            relative = str(Path(original.parent.name) / original.name)
            records = read_documents(output / relative)
            index = attempt["event_index"]
            if index < 0 or index >= len(records):
                errors.append("raw event index missing: " + case["name"])
                continue
            key = (relative, index, attempt["target_pid"])
            if key in used_events:
                errors.append(
                    "raw event reused by multiple phase claims: " + case["name"]
                )
            used_events.add(key)
            if not event_after_request(records[index], attempt.get("not_before_epoch")):
                errors.append(
                    "stale asynchronous event predates healthy capture request"
                )
            data = records[index]["tracer_data"]
            if detail["module"] == "memburst":
                record = next(
                    (
                        r
                        for r in data["process_snapshots"]
                        if r["pid"] == attempt["target_pid"]
                    ),
                    None,
                )
            else:
                record = data if data["victim_pid"] == attempt["target_pid"] else None
            if detail["module"] == "memburst":
                ranked = data["top_memory_usage"]
                scanned = data["process_snapshots"]
                if (
                    len(scanned) > 3
                    or any(
                        item["pid"] != ranked[i]["PID"]
                        for i, item in enumerate(scanned)
                    )
                    or [r["MemSize"] for r in ranked]
                    != sorted((r["MemSize"] for r in ranked), reverse=True)
                ):
                    errors.append(
                        "raw memburst ranking/snapshot association is invalid"
                    )
            if record and (
                record.get("language")
                != (attempt.get("target_language") or case["target_id"])
                or record.get("process_memory", {}).get("rss_bytes", 0) <= 0
            ):
                errors.append("raw runtime or process RSS differs from expected target")
            if not record:
                errors.append("raw target identity mismatch: " + case["name"])
                continue
            snapshot = record["snapshot"]
            if (
                snapshot["status"] != attempt["status"]
                or snapshot.get("status_reason", "") != attempt["reason"]
                or len(snapshot.get("entries", [])) != attempt["entries"]
            ):
                errors.append("raw snapshot differs from phase claim: " + case["name"])
            if case["expect_fault"] and mode not in ("block", "kill_after_read"):
                errors += validate_fault(mode, attempt)
    return dict(
        errors=errors, unexpected_agent_logs=rejected, expected_fault_log_counts=allowed
    )
