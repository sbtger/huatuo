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
    p.add_argument("--business",choices=["fixture","etcd","kafka","mitmproxy","resident"],default="fixture")
    p.add_argument("--native-root",default="")
    p.add_argument("--snapshot-helper",default="")
    p.add_argument("--snapshot-count",type=int,default=1)
    p.add_argument("--snapshot-interval",type=float,default=5)
    p.add_argument("--dataset-mib",type=int,default=32)
    p.add_argument("--resident-language",choices=["go","java","python"],default="go")
    p.add_argument("--resident-go",default="")
    p.add_argument("--pressure-levels",default="60,80,90")
    p.add_argument("--pressure-tolerance",type=float,default=2)
    p.add_argument("--business-cpus",type=float,default=4)
    p.add_argument("--allow-95",action="store_true")
    p.add_argument("--rates",default="100,200")
    p.add_argument("--slo-p99-ms",type=float)
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
    p.add_argument("--burst-max-targets", type=int, default=3)
    p.add_argument("--driver-pressure-mib", type=int, default=320)
    p.add_argument("--redis", action="store_true")
    p.add_argument("--redis-server", default="/usr/bin/redis-server")
    p.add_argument("--redis-keys", type=int, default=128)
    p.add_argument("--redis-value-bytes", type=int, default=65536)
    p.add_argument("--redis-fork-interval", type=float, default=0)
    p.add_argument("--load-controller-url", default="")
    p.add_argument("--load-token-file", default="")
    p.add_argument("--service-port-base", type=int, default=30000)
    p.add_argument("--load-target-host", default="10.0.2.2")
    p.add_argument("--load-target-base-port", type=int, default=40000)
    p.add_argument("--max-clock-error", type=float, default=.02)
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
        config=json.loads((output/"results.json").read_text())["config"]
        if config.get("business")=="resident":
            from fault_isolation_framework.adapters.huatuo.resident_performance import report
        elif config.get("business","fixture")!="fixture":
            from fault_isolation_framework.adapters.huatuo.real_business import report
        else:
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
    if a.business=="fixture" and (not 1 <= a.pressure_mib <= 600 or a.memory_limit_mib < a.pressure_mib+64):
        p.error("fixture pressure must be 1..600 MiB with >=64 MiB container headroom")
    if a.hold <= a.poll_interval*2 and a.module == "memburst":
        p.error("memburst hold must exceed two sampling intervals")
    if not 1 <= a.burst_max_targets <= 3 or not 256 <= a.driver_pressure_mib <= 600:
        p.error("burst-max-targets must be1..3 and driver-pressure-mib256..600")
    if a.module == "memburst" and a.pressure_targets > a.burst_max_targets:
        p.error("pressure target count exceeds memburst capture limit")
    if not 1 <= a.redis_keys <= 4096 or not 1 <= a.redis_value_bytes <= 1<<20 or a.redis_keys*a.redis_value_bytes > 32<<20:
        p.error("Redis dataset must fit32MiB with bounded key/value sizes")
    if not math.isfinite(a.redis_fork_interval) or a.redis_fork_interval < 0 or (0 < a.redis_fork_interval < 1) or (a.redis_fork_interval and not a.redis):
        p.error("Redis fork interval must be0 or >=1 seconds and requires --redis")
    if not math.isfinite(a.max_clock_error) or a.max_clock_error <= 0:
        p.error("max-clock-error must be finite and positive")
    if bool(a.load_controller_url) != bool(a.load_token_file):
        p.error("external load requires both controller URL and token file")
    count=a.copies*len(languages)+1+int(a.redis)
    if not 1024 <= a.service_port_base <= 65535-count or not 1024 <= a.load_target_base_port <= 65535-count:
        p.error("service and forwarded port ranges must fit nonprivileged TCP ports")
    if a.load_controller_url and (count>64 or math.ceil((a.warmup+a.baseline+a.hold+a.recovery)*a.qps)*(count if a.load_all else len(languages)+a.pressure_targets+2)>250000):
        p.error("external load exceeds controller route/request budget")
    if a.business == "resident":
        if not a.load_controller_url or not a.snapshot_helper or not a.resident_go:p.error("resident KV requires separate load controller, --snapshot-helper and --resident-go")
        if not 256<=a.memory_limit_mib<=4096 or not math.isfinite(a.business_cpus) or not 0<a.business_cpus<=4:p.error("resident business requires256..4096MiB and<=4CPUs")
        if not math.isfinite(a.pressure_tolerance) or not 0<a.pressure_tolerance<=3:p.error("pressure tolerance must be0..3 percentage points")
        try:
            levels=[int(v) for v in a.pressure_levels.split(",")]
            if not levels or len(set(levels))!=len(levels) or not set(levels)<={60,80,90,95}:raise ValueError()
            if 95 in levels and (not a.allow_95 or 90 not in levels or levels.index(95)<levels.index(90)):raise ValueError()
        except ValueError:p.error("pressure levels must beunique60/80/90/95;95requires --allow-95 after90")
        if not 1<=a.snapshot_count<=10 or not math.isfinite(a.snapshot_interval) or a.snapshot_interval<a.capture_timeout or 1+(a.snapshot_count-1)*a.snapshot_interval+a.capture_timeout>=a.hold:p.error("resident snapshot schedule exceeds capture window")
    elif a.business != "fixture":
        if not a.native_root or not a.load_controller_url or not a.snapshot_helper:p.error("native business requires --native-root, --snapshot-helper and separate load controller")
        if not 1<=a.dataset_mib<=256 or not 1<=a.snapshot_count<=10 or not math.isfinite(a.snapshot_interval) or a.snapshot_interval<a.capture_timeout:p.error("native dataset/capture count/interval outside budget")
        if 12+(a.snapshot_count-1)*a.snapshot_interval+a.capture_timeout>=a.hold:p.error("snapshot schedule must fit after wrk2 calibration and before trigger window ends")
        if a.experiment != "pulse":p.error("native business currently requires B/D pulse comparison")
        if min(a.warmup,a.baseline,a.hold,a.recovery)<20 or any(int(v)!=v for v in (a.warmup,a.baseline,a.hold,a.recovery)):p.error("native tool windows must be integer seconds >=20")
        try:
            rates=[int(v) for v in a.rates.split(",")]
            if not rates or len(set(rates))!=len(rates) or not all(1<=r<=50000 and r*max(a.warmup,a.baseline,a.hold,a.recovery)<=1000000 for r in rates):raise ValueError()
        except ValueError:p.error("native rates must be unique integers within rate/request budget")
        if a.slo_p99_ms is not None and (not math.isfinite(a.slo_p99_ms) or a.slo_p99_ms<=0):p.error("SLO must be finite and positive")
    if a.plan:
        import random
        rng = random.Random(a.seed)
        schedule = []
        for repeat in range(a.repeats):
            groups = experiment_groups(a.experiment) if a.business == "fixture" else (["A","B","C"] if a.business=="resident" else ["B","D"])
            rng.shuffle(groups)
            schedule.append(dict(repeat=repeat, groups=groups))
        print(json.dumps(dict(config=vars(a), schedule=schedule), indent=2))
        return 0
    if a.business == "fixture":
        from fault_isolation_framework.adapters.huatuo.performance import campaign, report
    elif a.business == "resident":
        from fault_isolation_framework.adapters.huatuo.resident_performance import campaign, report
    else:
        from fault_isolation_framework.adapters.huatuo.real_business import campaign, report
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
