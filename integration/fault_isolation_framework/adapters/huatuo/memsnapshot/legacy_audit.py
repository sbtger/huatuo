# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Audit raw evidence and its accounting without rerunning the workloads."""
import argparse
import json
import re
from collections import Counter
from pathlib import Path
from .log_policy import unexpected_logs


def legacy_inventory(cases, languages):
    """Pre-inventory runs used sequential Agent/config IDs for each start."""
    recovery_restarts = {
        "permission-recovery",
        "block-recovery",
        "kill_after_read-recovery",
        "storage_full-recovery",
        "invalid_config-recovery",
    }
    starts = 0
    for case in cases:
        mode = case["name"].split("/", 1)[1]
        if mode == "agent-off":
            continue
        if mode.endswith("-recovery") and mode not in recovery_restarts:
            continue
        starts += 2 if mode == "restart" else 1
    return {
        "agent_logs": ["agent-%d.log" % n for n in range(1, starts + 1)],
        "configs": ["bamai-%d.conf" % n for n in range(1, starts + 1)],
        "request_streams": [language + "-requests.jsonl" for language in languages],
    }


def audit(output):
    output = Path(output)
    evidence_errors = []
    rejected, allowed, total_requests, errors = {}, {}, {}, {}

    def read(name):
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("evidence path must stay inside the output: " + name)
        return (output / path).read_text()

    summary = {}
    try:
        summary = json.loads(read("summary.json"))
        environment = json.loads(read("environment.json"))
        cases = summary["cases"]
        languages = [t["language"] for t in environment["targets"]]
        if not languages or len(set(languages)) != len(languages):
            raise ValueError("missing or duplicate business languages")
        if not cases or summary["case_count"] != len(cases):
            raise ValueError("case_count does not match nonempty cases")
        if any(c["status"] != "PASS" for c in cases):
            evidence_errors.append("one or more phases did not pass")
        inventory = summary.get("evidence_files") or legacy_inventory(cases, languages)
        # Derive expected names from the phase lifecycle, not surviving files.
        if inventory != legacy_inventory(cases, languages):
            raise ValueError("evidence inventory does not match the phase lifecycle")
        for kind in ("agent_logs", "configs", "request_streams"):
            for name in inventory[kind]:
                if not read(name):
                    evidence_errors.append("empty evidence file: " + name)

        for name in inventory["agent_logs"]:
            text = read(name)
            full = "action=mark" in text and re.search(r"id=\S+/storage_full ", text)
            config = name.replace("agent-", "bamai-").replace(".log", ".conf")
            invalid = "ThresholdPercent = 101" in read(config)
            bad = unexpected_logs(text, storage_full=bool(full), invalid_config=invalid)
            if bad:
                rejected[name] = bad
            allowed[name] = sum(
                bool(re.search(r'level="(?:warn|warning|error|panic|fatal)"', line))
                for line in text.splitlines()
            ) - len(bad)

        for field in ("total_business_requests", "total_business_transactions"):
            if set(summary[field]) != set(languages):
                raise ValueError(field + " languages do not match environment")
        for language in languages:
            name = language + "-requests.jsonl"
            rows = [json.loads(line) for line in read(name).splitlines()]
            if not rows:
                raise ValueError("empty request stream: " + name)
            if any(r["kind"] not in ("work", "transaction") for r in rows):
                raise ValueError("unknown request record kind in " + name)
            work = [r for r in rows if r["kind"] == "work"]
            total_requests[name] = len(work)
            transactions = sum(
                r["kind"] == "transaction" and r["ok"] is True for r in rows
            )
            if len(work) != summary["total_business_requests"][language]:
                evidence_errors.append("work request count mismatch: " + name)
            if transactions != summary["total_business_transactions"][language]:
                evidence_errors.append("transaction count mismatch: " + name)
            failed = [r for r in rows if r["ok"] is not True]
            if failed:
                errors[name] = failed
            counts = Counter(r["phase"] for r in work)
            for case in cases:
                phase = case["business"][language]
                if phase["samples"] <= 0 or counts[case["name"]] != phase["samples"]:
                    evidence_errors.append(
                        "phase sample count mismatch: " + case["name"] + "/" + language
                    )
                if phase["assertion_errors"]:
                    evidence_errors.append(
                        "phase business assertions failed: " + case["name"]
                    )

        # Rebase persisted event references so copied evidence remains portable.
        event_counts = Counter()
        for case in cases:
            detail = case["detail"]
            if detail.get("event_file"):
                path = Path(detail["event_file"])
                name = str(Path(path.parent.name) / path.name)
                event_counts[name] += max(1, len(detail.get("normal_attempts", [])))
        decoder = json.JSONDecoder()
        for name, minimum in event_counts.items():
            text = read(name).strip()
            count = 0
            while text:
                _, end = decoder.raw_decode(text)
                count += 1
                text = text[end:].lstrip()
            if count < minimum:
                evidence_errors.append("snapshot record count mismatch: " + name)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        evidence_errors.append(str(error))

    result = dict(
        status="PASS"
        if summary.get("status") == "PASS"
        and not rejected
        and not errors
        and not evidence_errors
        else "FAIL",
        evidence_errors=evidence_errors,
        unexpected_agent_logs=rejected,
        expected_fault_log_counts=allowed,
        business_errors=errors,
        total_work_requests=total_requests,
        case_count=summary.get("case_count", 0),
        performance_evaluated=False,
    )
    (output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
