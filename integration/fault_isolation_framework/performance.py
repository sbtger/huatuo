#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Opt-in paired plain-Agent performance experiments in a dedicated Linux VM."""
import argparse
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.core.performance import experiment_groups


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1<<20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal(output):
    # Derived reports can be regenerated; raw data and trial summaries cannot.
    excluded = {"integrity.json", "analysis.json", "REPORT.md", "audit.json"}
    hashes = {str(p.relative_to(output)):file_hash(p) for p in output.rglob("*")
              if p.is_file() and str(p.relative_to(output)) not in excluded}
    (output/"integrity.json").write_text(json.dumps(hashes, indent=2)+"\n")


def audit(output):
    hashes = json.loads((output/"integrity.json").read_text())
    errors = []
    for name, expected in hashes.items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts:
            errors.append("invalid artifact path: "+name)
        elif not (output/path).is_file() or file_hash(output/path) != expected:
            errors.append("missing/changed artifact: "+name)
    if not hashes or "results.json" not in hashes or "supervisor.json" not in hashes:
        errors.append("missing campaign records")
    result = dict(status="PASS" if not errors else "FAIL", files=len(hashes), errors=errors)
    (output/"audit.json").write_text(json.dumps(result, indent=2)+"\n")
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--module", choices=["memburst", "memory_threshold_snapshot"])
    p.add_argument("--experiment", choices=["idle", "pulse"], default="idle")
    p.add_argument("--build")
    p.add_argument("--bpf-dir")
    p.add_argument("--output", required=True)
    p.add_argument("--report", action="store_true", help="verify raw hashes and regenerate derived report")
    p.add_argument("--plan", action="store_true", help="print schedule without running or creating output")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--seed", type=int, default=923)
    p.add_argument("--languages", default="go,java,python")
    p.add_argument("--pressure-languages", default="go")
    p.add_argument("--copies", type=int, default=1, help="registered containers per runtime")
    p.add_argument("--pressure-targets", type=int, default=1)
    p.add_argument("--load-all", action="store_true", help="load every registered container; default loads first copy, pressure targets and neighbor")
    p.add_argument("--pressure-mib", type=int, default=500)
    p.add_argument("--memory-limit-mib", type=int, default=768)
    p.add_argument("--extra-processes", type=int, default=0)
    p.add_argument("--warmup", type=float, default=60)
    p.add_argument("--baseline", type=float, default=30)
    p.add_argument("--hold", type=float, default=30)
    p.add_argument("--recovery", type=float, default=30)
    p.add_argument("--qps", type=float, default=20, help="per target and neighbor")
    p.add_argument("--workers", type=int, default=16, help="load threads per business")
    p.add_argument("--pending", type=int, default=64, help="maximum outstanding requests per business")
    p.add_argument("--max-dispatch-lag", type=float, default=.1)
    p.add_argument("--sample-interval", type=float, default=.1)
    p.add_argument("--poll-interval", type=int, default=1)
    p.add_argument("--threshold-percent", type=int, default=60)
    p.add_argument("--top-k", type=int, default=7)
    p.add_argument("--capture-timeout", type=int, default=3)
    p.add_argument("--cooldown", type=int, default=8)
    p.add_argument("--agent-port", type=int, default=19704)
    p.add_argument("--java-home", default="/usr/lib/jvm/java-17-openjdk-amd64")
    p.add_argument("--python", default="/usr/bin/python3")
    p.add_argument("--phase-timeout", type=float, default=900)
    p.add_argument("--campaign-timeout", type=float, default=18000)
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return p


def main():
    p = parser()
    a = p.parse_args()
    a.log_debug = False
    output = Path(a.output).resolve()
    if a.report:
        from fault_isolation_framework.adapters.huatuo.performance import report
        checked = audit(output)
        print(json.dumps(checked, indent=2))
        if checked["status"] != "PASS":
            return 1
        result = report(output)
        print(json.dumps(result, indent=2))
        return int(result["status"] != "VALIDATION_PASS")
    positive = (a.qps, a.warmup, a.baseline, a.hold, a.recovery, a.sample_interval,
                a.max_dispatch_lag, a.phase_timeout, a.campaign_timeout)
    if not all(math.isfinite(v) and v > 0 for v in positive):
        p.error("rates, durations and observation intervals must be finite and positive")
    if not a.module or not a.build or not a.bpf_dir:
        p.error("--module, --build and --bpf-dir are required")
    if min(a.repeats, a.copies, a.pressure_targets, a.workers, a.pending, a.poll_interval, a.capture_timeout, a.cooldown) < 1 or a.extra_processes < 0:
        p.error("counts must be positive; extra-processes may be zero")
    languages, pressure_languages = a.languages.split(","), a.pressure_languages.split(",")
    if len(set(languages)) != len(languages) or not set(languages) <= {"go", "java", "python"} or "go" not in languages:
        p.error("unique --languages must contain go; supported: go,java,python")
    if not set(pressure_languages) <= set(languages) or a.pressure_targets > len(set(pressure_languages))*a.copies:
        p.error("pressure targets exceed selected registered containers")
    if not 1 <= a.threshold_percent <= 100 or not 1 <= a.top_k <= 100:
        p.error("threshold-percent and top-k must be in [1,100]")
    if not 1 <= a.pressure_mib <= 600 or a.memory_limit_mib < a.pressure_mib+64:
        p.error("fixture pressure must be 1..600 MiB with >=64 MiB container headroom")
    if a.hold <= a.poll_interval*2 and a.module == "memburst":
        p.error("memburst hold must exceed two sampling intervals")
    if a.plan:
        import random
        rng = random.Random(a.seed)
        schedule = []
        for repeat in range(a.repeats):
            groups = experiment_groups(a.experiment)
            rng.shuffle(groups)
            schedule.append(dict(repeat=repeat, groups=groups))
        print(json.dumps(dict(config=vars(a), schedule=schedule), indent=2))
        return 0
    from fault_isolation_framework.adapters.huatuo.performance import campaign, report
    if a.worker:
        def interrupted(signum, frame):
            raise KeyboardInterrupt("performance worker interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        campaign(a, output)
        return 0
    output.mkdir(parents=True, exist_ok=False)
    (output/"command.json").write_text(json.dumps(dict(argv=sys.argv, config=vars(a)), indent=2)+"\n")
    # Preserve the exact executed source without interpreter caches.
    import tarfile
    with tarfile.open(output/"executed-framework.tar.gz", "w:gz") as archive:
        root = Path(__file__).resolve().parent
        for source in sorted(root.rglob("*")):
            if source.is_file() and source.suffix in (".py", ".go", ".java", ".c") and "__pycache__" not in source.parts:
                archive.add(source, arcname=str(source.relative_to(root.parent)))
    env = dict(os.environ, HUATUO_TEST_OWNERSHIP=str(output/"ownership.jsonl"))
    reason = ""
    with (output/"controller.log").open("w") as log:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve())]+sys.argv[1:]+["--worker"],
                                 stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        deadline = time.monotonic()+a.campaign_timeout
        try:
            while child.poll() is None:
                if time.monotonic() > deadline:
                    raise TimeoutError("performance campaign deadline exceeded")
                checkpoint = output/"progress.json"
                if checkpoint.exists():
                    point = json.loads(checkpoint.read_text())
                    if time.monotonic()-point["started"] > a.phase_timeout:
                        raise TimeoutError("trial deadline exceeded: "+point["phase"])
                time.sleep(.2)
        except (Exception, KeyboardInterrupt) as exc:
            reason = repr(exc)
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(10)
    from fault_isolation_framework.environments.supervisor import cleanup_owned
    cleanup_errors = cleanup_owned(output)
    supervisor = dict(returncode=child.returncode, reason=reason, cleanup_errors=cleanup_errors)
    (output/"supervisor.json").write_text(json.dumps(supervisor, indent=2)+"\n")
    if (output/"results.json").exists():
        result = report(output)
    else:
        result = dict(status="INVALID_OR_FAILED", errors=["no completed trials"])
        (output/"analysis.json").write_text(json.dumps(result, indent=2)+"\n")
    seal(output)
    checked = audit(output)
    print(json.dumps(result, indent=2))
    return int(bool(reason or child.returncode or cleanup_errors or checked["status"] != "PASS" or result["status"] != "VALIDATION_PASS"))


if __name__ == "__main__":
    raise SystemExit(main())
