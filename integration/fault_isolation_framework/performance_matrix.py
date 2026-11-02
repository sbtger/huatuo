#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Run explicit performance matrix cells sequentially and summarize rate sweeps."""
import argparse
import hashlib
import json
import math
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.core.performance import highest_tested_rate


def capacity_summary(cases, slo_p99_ms, max_error_rate):
    series = {}
    for case in cases:
        data = json.loads((Path(case["output"])/"results.json").read_text())
        exclusion_reasons = []
        if case.get("returncode") != 0:
            exclusion_reasons.append("campaign process failed or was interrupted")
        try:
            from fault_isolation_framework.performance import audit
            from fault_isolation_framework.adapters.huatuo.performance import report
            if audit(Path(case["output"]))["status"] != "PASS":
                exclusion_reasons.append("raw artifact integrity failed")
            elif report(Path(case["output"]))["status"] != "VALIDATION_PASS":
                exclusion_reasons.append("incomplete or failed campaign")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            exclusion_reasons.append("invalid campaign evidence: "+repr(exc))
        config = {k:v for k,v in data["config"].items() if k not in ("qps", "output", "worker")}
        signature = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()[:16]
        for group in sorted(set(t["group"] for t in data["trials"])):
            trials = [t for t in data["trials"] if t["group"] == group]
            targets = {key for t in trials for key in t.get("load", {})}
            for target in sorted(targets):
                observations = [t["load"][target] for t in trials if target in t.get("load", {})]
                p99 = [o["latency_ms"]["p99"] for o in observations]
                valid = not exclusion_reasons and len(trials) == data["config"]["repeats"] and all(t["valid"] for t in trials) and len(observations) == len(trials)
                key = signature+"/"+group+"/"+target
                series.setdefault(key, dict(config=config, group=group, target=target, observations=[]))["observations"].append(dict(
                    case=case["name"], exclusion_reasons=exclusion_reasons, qps=data["config"]["qps"], valid=valid,
                    p99_ms=max(p99) if p99 and all(p is not None for p in p99) else None,
                    error_rate=max((o["errors"]/o["scheduled"] for o in observations if o["scheduled"]), default=1)))
    for value in series.values():
        value["highest_tested_slo_rate"] = highest_tested_rate(value["observations"], slo_p99_ms, max_error_rate)
    return dict(slo_p99_ms=slo_p99_ms, max_error_rate=max_error_rate, series=series,
                interpretation="highest tested rate satisfying every valid repeat; not an interpolated or proven maximum capacity")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--matrix", required=True, help="JSON list of {name,options}; option names use hyphens")
    p.add_argument("--build", required=True)
    p.add_argument("--bpf-dir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--plan", action="store_true")
    p.add_argument("--slo-p99-ms", type=float)
    p.add_argument("--max-error-rate", type=float, default=0)
    a = p.parse_args()
    if a.slo_p99_ms is not None and (not math.isfinite(a.slo_p99_ms) or a.slo_p99_ms <= 0):
        p.error("slo-p99-ms must be finite and positive")
    if not 0 <= a.max_error_rate <= 1:
        p.error("max-error-rate must be in [0,1]")
    cases = json.loads(Path(a.matrix).read_text())
    if not isinstance(cases, list) or not cases:
        p.error("matrix must be a nonempty list")
    names = set()
    planned = []
    root = Path(a.output).resolve()
    script = Path(__file__).with_name("performance.py")
    for case in cases:
        name, options = case["name"], case["options"]
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in name) or name in names:
            p.error("matrix cell names must be unique safe directory names")
        names.add(name)
        command = [sys.executable, str(script), "--build", str(Path(a.build).resolve()),
                   "--bpf-dir", str(Path(a.bpf_dir).resolve()), "--output", str(root/name)]
        for key, value in options.items():
            if key in ("output", "build", "bpf-dir", "worker", "report", "plan") or not isinstance(value, (str, int, float)) or (isinstance(value, bool) and key != "load-all"):
                p.error("invalid matrix option: "+key)
            if key == "load-all":
                if value:
                    command += ["--load-all"]
            else:
                command += ["--"+key, str(value)]
        # Let the real parser validate every cell before creating any output.
        checked = subprocess.run(command+["--plan"], capture_output=True, text=True)
        if checked.returncode:
            p.error("invalid cell %s: %s" % (name, checked.stderr[-1000:]))
        planned.append(dict(name=name, command=command, output=str(root/name)))
    if a.plan:
        print(json.dumps(planned, indent=2))
        return 0
    root.mkdir(parents=True, exist_ok=False)
    (root/"matrix.json").write_text(json.dumps(cases, indent=2)+"\n")
    completed = []
    for case in planned:
        with (root/(case["name"]+".log")).open("x") as log:
            done = subprocess.run(case["command"], stdout=log, stderr=subprocess.STDOUT)
        case["returncode"] = done.returncode
        completed.append(case)
        (root/"matrix-results.json").write_text(json.dumps(completed, indent=2)+"\n")
    if a.slo_p99_ms is not None:
        usable = [c for c in completed if (Path(c["output"])/"results.json").exists()]
        result = capacity_summary(usable, a.slo_p99_ms, a.max_error_rate)
        (root/"capacity.json").write_text(json.dumps(result, indent=2)+"\n")
    return int(any(c["returncode"] for c in completed))


if __name__ == "__main__":
    raise SystemExit(main())
