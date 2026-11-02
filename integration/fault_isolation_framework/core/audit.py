# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Feature-neutral evidence integrity, phase coverage and request accounting."""
import hashlib
import json
from pathlib import Path
from .business_audit import audit_business


def audit(output, policy=None):
    output = Path(output).resolve()
    summary = {}
    issues = []
    business_errors = {}
    counts = {}
    policy_result = {}
    business_status = "UNVERIFIED"
    adapter_audit_completed = False
    try:
        summary = json.loads((output / "summary.json").read_text())
        manifest = json.loads((output / "manifest.json").read_text())
        if summary["schema_version"] != 2 or manifest["schema_version"] != 2:
            raise ValueError("unsupported evidence schema")
        business = audit_business(output, summary, manifest)
        business_status = business["status"]
        business_errors = business["business_errors"]
        counts = business["total_work_requests"]
        issues.extend(business["issues"])
        if summary.get("adapter_policy_required") and policy is None:
            raise ValueError("adapter audit policy is required")
        cases = summary["cases"]
        plan = summary["planned_cases"]
        if (
            not plan
            or len(set(plan)) != len(plan)
            or [c["name"] for c in cases] != plan
            or len(cases) != summary["case_count"]
        ):
            raise ValueError("executed cases do not match the complete plan")
        if any(c["status"] != "PASS" for c in cases):
            issues.append("one or more phases did not pass")
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
            raise ValueError("manifest does not match artifact registration history")
        for name, artifact in artifacts.items():
            registration = registered[name]
            for field in ("path", "role", "target_id", "format"):
                if artifact[field] != registration[field]:
                    raise ValueError("changed artifact registration: " + name)
            if artifact["minimum_documents"] < registration["minimum_documents"]:
                raise ValueError("weakened evidence requirement: " + name)
            relative = Path(name)
            path = output / relative
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or output not in path.resolve().parents
            ):
                raise ValueError("evidence outside output: " + name)
            if artifact["role"] == "requests":
                # The independent business pass already verified and streamed it.
                continue
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            if not path.stat().st_size or digest.hexdigest() != artifact.get("sha256"):
                raise ValueError("empty, changed or unhashed evidence: " + name)
            text = path.read_text()
            if artifact["format"] == "jsonl":
                documents = [json.loads(line) for line in text.splitlines()]
            elif artifact["format"] == "json_documents":
                decoder = json.JSONDecoder()
                documents = []
                text = text.strip()
                while text:
                    document, end = decoder.raw_decode(text)
                    documents.append(document)
                    text = text[end:].lstrip()
            elif artifact["format"] == "json":
                documents = [json.loads(text)]
            elif artifact["format"] == "text":
                documents = [text]
            else:
                raise ValueError("unknown evidence format: " + name)
            if len(documents) < artifact["minimum_documents"]:
                raise ValueError("evidence record count mismatch: " + name)
        for case in cases:
            if case["expect_fault"] and (
                case["fault_hits"] <= 0 or not case["evidence"]
            ):
                issues.append("fault has no reached witness/evidence: " + case["name"])
            if any(name not in artifacts for name in case["evidence"]):
                issues.append("unregistered phase evidence: " + case["name"])
        if policy is not None:
            try:
                policy_result = policy(output, summary, manifest)
                adapter_audit_completed = True
            except Exception as error:
                issues.append("adapter policy failed: " + repr(error))
                policy_result = {}
            issues.extend(policy_result.get("errors", []))
            if policy_result.get("unexpected_agent_logs"):
                issues.append("unexpected feature logs")
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        issues.append(str(error))
    result = dict(
        status="PASS"
        if summary.get("status") == "PASS"
        and business_status == "PASS"
        and not issues
        and not business_errors
        else "FAIL",
        evidence_errors=issues,
        business_errors=business_errors,
        business_audit_status=business_status,
        adapter_audit_completed=adapter_audit_completed,
        total_work_requests=counts,
        unexpected_agent_logs=policy_result.get("unexpected_agent_logs", {}),
        expected_fault_log_counts=policy_result.get("expected_fault_log_counts", {}),
        case_count=summary.get("case_count", 0),
        performance_evaluated=False,
    )
    (output / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
