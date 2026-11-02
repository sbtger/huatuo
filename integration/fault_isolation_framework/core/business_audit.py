# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Verify the observed business interval independently of feature completion."""
import hashlib
import json
from collections import Counter
from pathlib import Path


def audit_business(output, summary, manifest):
    output = Path(output).resolve()
    issues, errors, counts, streams = [], {}, {}, {}
    status = "UNVERIFIED"
    try:
        journal = [
            json.loads(line)
            for line in (output / "registrations.jsonl").read_text().splitlines()
        ]
        registered = {a["path"]: a for a in journal}
        artifacts = {a["path"]: a for a in manifest["artifacts"]}
        if (
            len(registered) != len(journal)
            or len(artifacts) != len(manifest["artifacts"])
            or set(registered) != set(artifacts)
        ):
            raise ValueError("business audit has inconsistent registration history")
        for name, artifact in artifacts.items():
            if artifact["role"] != "requests":
                continue
            registration = registered[name]
            if (
                any(
                    artifact[k] != registration[k]
                    for k in ("path", "role", "target_id", "format")
                )
                or artifact["minimum_documents"] < registration["minimum_documents"]
            ):
                raise ValueError("business stream registration changed: " + name)
            target = artifact["target_id"]
            relative = Path(name)
            path = output / relative
            if (
                target in streams
                or artifact["format"] != "jsonl"
                or relative.is_absolute()
                or ".." in relative.parts
                or output not in path.resolve().parents
            ):
                raise ValueError(
                    "duplicate, invalid or external business stream: " + name
                )
            aggregate = dict(work=0, transactions=0, bad=[], by_phase=Counter())
            digest, documents = hashlib.sha256(), 0
            with path.open("rb") as source:
                for line in source:
                    digest.update(line)
                    row = json.loads(line)
                    documents += 1
                    if row["kind"] not in ("work", "transaction", "scheduler"):
                        raise ValueError("unknown business record kind: " + target)
                    if row["ok"] is not True and len(aggregate["bad"]) < 100:
                        aggregate["bad"].append(row)
                    if row["kind"] == "work":
                        aggregate["work"] += 1
                        aggregate["by_phase"][row["phase"]] += 1
                    if row["kind"] == "transaction" and row["ok"] is True:
                        aggregate["transactions"] += 1
            if (
                not documents
                or documents < artifact["minimum_documents"]
                or digest.hexdigest() != artifact.get("sha256")
            ):
                raise ValueError("empty, changed or unhashed business stream: " + name)
            streams[target] = aggregate
        targets = set(summary["total_business_requests"])
        if (
            not targets
            or set(streams) != targets
            or set(summary["total_business_transactions"]) != targets
        ):
            raise ValueError("business stream targets do not match summary")
        for target, rows in streams.items():
            counts[target] = rows["work"]
            if rows["bad"]:
                errors[target] = rows["bad"]
            if (
                rows["work"] != summary["total_business_requests"][target]
                or rows["transactions"]
                != summary["total_business_transactions"][target]
            ):
                issues.append("business accounting mismatch: " + target)
            for case in summary["cases"]:
                observation = case["business"][target]
                if (
                    observation["samples"] <= 0
                    or observation["samples"] != rows["by_phase"][case["name"]]
                ):
                    issues.append(
                        "phase sample count mismatch: " + case["name"] + "/" + target
                    )
                if observation["assertion_errors"] or observation.get("errors"):
                    issues.append(
                        "business assertion failed: " + case["name"] + "/" + target
                    )
        status = "FAIL" if issues or errors else "PASS"
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        issues.append("business audit unavailable: " + str(error))
    return dict(
        status=status, issues=issues, business_errors=errors, total_work_requests=counts
    )
