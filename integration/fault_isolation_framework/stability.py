#!/usr/bin/env python3
# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Opt-in short/72-hour stability campaigns in a dedicated root Linux VM."""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.core.stability import CheckpointEvidence
from fault_isolation_framework.environments.supervisor import supervise
from fault_isolation_framework.core.runner import Runner
from fault_isolation_framework.core.util import require
from fault_isolation_framework.adapters.huatuo.stability.adapter import StabilityAdapter
from fault_isolation_framework.adapters.huatuo.stability.policy import audit_artifacts
from fault_isolation_framework.core.audit import audit


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--module", choices=["memburst", "memory_threshold_snapshot"])
    p.add_argument("--profile", choices=["short", "soak"], default="short")
    p.add_argument("--build")
    p.add_argument("--bpf-dir")
    p.add_argument("--output", required=True)
    p.add_argument("--audit", action="store_true")
    p.add_argument("--cycles", type=int)
    p.add_argument("--duration-seconds", type=float)
    p.add_argument("--churn-per-cycle", type=int)
    p.add_argument("--faults")
    p.add_argument("--fault-every", type=int)
    p.add_argument("--inject-faults", action="store_true")
    p.add_argument(
        "--resource-faults",
        action="store_true",
        help="real Agent EMFILE and test-cgroup OOM; never changes business limits",
    )
    p.add_argument("--require-pid-reuse", action="store_true")
    p.add_argument("--languages", default="go,java,python")
    p.add_argument("--java-home", default="/usr/lib/jvm/java-17-openjdk-amd64")
    p.add_argument("--python", default="/usr/bin/python3")
    p.add_argument(
        "--extra-processes",
        type=int,
        default=0,
        help="additional real small-heap Go processes for ranking scale",
    )
    p.add_argument("--agent-port", type=int, default=19704)
    p.add_argument("--qps", type=int, default=10)
    p.add_argument("--cooldown", type=int, default=8)
    p.add_argument("--phase-timeout", type=float)
    p.add_argument("--campaign-timeout", type=float)
    p.add_argument("--rss-growth-mib", type=int, default=64)
    p.add_argument("--fd-growth", type=int, default=16)
    p.add_argument("--rss-limit-mib", type=int, default=512)
    p.add_argument("--fd-limit", type=int, default=512)
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args()
    if a.audit:
        result = audit(Path(a.output) / "evidence", audit_artifacts)
        print(json.dumps(result, indent=2))
        raise SystemExit(result["status"] != "PASS")
    require(
        a.module and a.build and a.bpf_dir,
        "--module, --build and --bpf-dir are required",
    )
    a.phase_timeout = a.phase_timeout or (180 if a.profile == "short" else 900)
    a.cycles = (
        a.cycles if a.cycles is not None else (2 if a.profile == "short" else 100)
    )
    a.duration_seconds = (
        a.duration_seconds
        if a.duration_seconds is not None
        else (0 if a.profile == "short" else 72 * 3600)
    )
    a.churn_per_cycle = (
        a.churn_per_cycle
        if a.churn_per_cycle is not None
        else (1 if a.profile == "short" else 10)
    )
    a.fault_every = (
        a.fault_every
        if a.fault_every is not None
        else (1 if a.profile == "short" else 10)
    )
    require(
        a.cycles > 0 and a.churn_per_cycle > 0 and a.fault_every > 0 and a.qps > 0,
        "cycles, churn, fault-every and qps must be positive",
    )
    require(0 <= a.extra_processes <= 128, "extra-processes must be in [0,128]")
    require(
        a.rss_growth_mib >= 0
        and a.fd_growth >= 0
        and a.rss_limit_mib > 0
        and a.fd_limit > 0,
        "invalid resource budgets",
    )
    require(
        a.duration_seconds >= 0 and a.phase_timeout > 0 and a.cooldown >= 5,
        "invalid duration, timeout or cooldown",
    )
    require(
        a.profile != "soak"
        or (
            a.duration_seconds >= 72 * 3600
            and a.cycles >= 100
            and a.cycles * a.churn_per_cycle >= 1000
        ),
        "soak requires 72h, >=100 cycles and >=1000 lifecycle iterations",
    )
    languages = a.languages.split(",")
    require(
        len(languages) == len(set(languages))
        and set(languages) <= {"go", "java", "python"}
        and "go" in languages,
        "languages must be unique supported runtimes including go",
    )
    a.faults = a.faults or (
        "efault,short"
        if a.profile == "short"
        else "efault,short,panic,cancel,delay,block,kill_after_read,permission"
    )
    faults = a.faults.split(",")
    require(
        faults
        and set(faults)
        <= {
            "efault",
            "short",
            "panic",
            "cancel",
            "delay",
            "block",
            "kill_after_read",
            "permission",
        },
        "unknown fault",
    )
    require(
        not a.inject_faults or a.cycles // a.fault_every >= len(faults),
        "cycles do not exercise every selected fault",
    )
    require(
        a.fault_every <= a.cycles,
        "fault-every exceeds cycles; lifecycle restart would not run",
    )
    if not a.worker:
        require(
            not Path(a.output).exists(),
            "output directory must be new; failing runs must not be overwritten",
        )
        command = (
            [sys.executable, str(Path(__file__).resolve())]
            + sys.argv[1:]
            + ["--worker"]
        )
        result = supervise(
            command,
            Path(a.output),
            a.campaign_timeout or (a.duration_seconds + a.cycles * 1800 + 300),
            a.phase_timeout,
        )
        print(json.dumps(result, indent=2))
        raise SystemExit(result["status"] != "PASS")
    os.environ["HUATUO_TEST_OWNERSHIP"] = str(
        Path(a.output).resolve() / "ownership.jsonl"
    )
    evidence = CheckpointEvidence(Path(a.output) / "evidence")
    adapter = StabilityAdapter(a, evidence)
    result = Runner(evidence).execute(adapter)
    raise SystemExit(result["status"] != "PASS")


if __name__ == "__main__":
    main()
