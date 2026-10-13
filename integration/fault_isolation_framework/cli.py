# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Registry and backwards-compatible CLI for maintained feature adapters."""
import argparse, json
from pathlib import Path
from .core.evidence import EvidenceStore
from .core.runner import Runner
from .core.util import require
from .adapters.huatuo.memsnapshot.adapter import MemsnapshotAdapter, FAULTS
from .adapters.huatuo.memsnapshot.policy import audit_artifacts
from .adapters.huatuo.memsnapshot.legacy_audit import audit as legacy_audit
from .core.audit import audit as core_audit


def audit_output(output):
    try:
        summary = json.loads((Path(output) / "summary.json").read_text())
        if summary.get("schema_version") == 2:
            if summary.get("adapter_id") != "huatuo.memsnapshot":
                raise ValueError(
                    "unsupported adapter in evidence: " + str(summary.get("adapter_id"))
                )
            return core_audit(output, audit_artifacts)
        if summary.get("schema_version") not in (None, 1):
            raise ValueError(
                "unsupported evidence schema: " + str(summary.get("schema_version"))
            )
        return legacy_audit(output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = dict(
            status="FAIL", evidence_errors=[str(error)], performance_evaluated=False
        )
        (Path(output) / "audit.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--adapter", default="huatuo.memsnapshot", choices=["huatuo.memsnapshot"]
    )
    p.add_argument("--build", required=True)
    p.add_argument("--bpf-dir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--languages", default="go,java,python")
    p.add_argument("--faults", default=",".join(FAULTS))
    p.add_argument("--java-home", default="/usr/lib/jvm/java-17-openjdk-amd64")
    p.add_argument("--python", default="/usr/bin/python3")
    p.add_argument("--agent-port", type=int, default=19704)
    p.add_argument("--qps", type=int, default=10)
    a = p.parse_args()
    require(a.qps > 0, "qps must be positive")
    require(
        set(a.languages.split(",")) <= set(["go", "java", "python"]), "unknown language"
    )
    require(set(a.faults.split(",")) <= set(FAULTS), "unknown fault")
    require(a.adapter == "huatuo.memsnapshot", "unsupported adapter")
    evidence = EvidenceStore(a.output)
    adapter = MemsnapshotAdapter(a, evidence)
    result = Runner(evidence).execute(adapter)
    raise SystemExit(result["status"] != "PASS")
