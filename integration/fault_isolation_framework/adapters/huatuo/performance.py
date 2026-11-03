# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Plain-Agent performance experiments; no fault overlays or capture retries."""
import hashlib
import json
import math
import os
import platform
import random
import threading
import time
from pathlib import Path

from ...core.documents import read_documents
from ...core.evidence import EvidenceStore
from ...core.performance import experiment_groups, paired_comparisons, summarize_requests, strict_documents
from ...core.util import require, run, wait_for, write_control
from ...environments.docker import DockerEnvironment
from ...environments.linux import ManagedProcess, identity
from ...environments.performance import PerformanceSampler, resource_metrics
from ...workloads.fixtures import launch_services
from ...workloads.http_probe import EXPECTED, request_http
from ...workloads.performance_load import run_load
from .agent import verify_build
from .discovery import Discovery, parse_timestamp
from .stability.adapter import StabilityAdapter


def capture_records(module, documents, target_pids, not_before=None, not_after=None):
    result = []
    for index, document in enumerate(documents):
        if not_before is not None or not_after is not None:
            at = parse_timestamp(document["started_timestamp"]).timestamp()
            if (not_before is not None and at < not_before) or (not_after is not None and at > not_after):
                continue
        data = document.get("tracer_data", {})
        records = data.get("process_snapshots", []) if module == "memburst" else [dict(
            pid=data.get("victim_pid"), language=data.get("language"), snapshot=data.get("snapshot", {}))]
        for record in records:
            if record.get("pid") not in target_pids:
                continue
            snapshot = record.get("snapshot") or {}
            result.append(dict(event_index=index, pid=record["pid"], language=record.get("language"),
                               status=snapshot.get("status"), entries=len(snapshot.get("entries", [])),
                               duration_ms=snapshot.get("duration_ms"), truncated=snapshot.get("output_truncated", False),
                               reason=snapshot.get("status_reason", ""),
                               successful=snapshot.get("status") in (("complete",) if record.get("language") == "go" else ("complete", "partial")) and bool(snapshot.get("entries"))))
    return result


def captures_cover_targets(records, requested):
    return bool(requested) and {r["pid"] for r in records} == set(requested) and all(r["successful"] for r in records)


def select_load_targets(targets, pressured, load_all=False):
    selected = {t["pid"] for t in pressured}
    return [t for t in targets if load_all or t["role"] == "neighbor"
            or t["id"].startswith("target-000-") or t["pid"] in selected]


class PerformanceAdapter(StabilityAdapter):
    def watch_targets(self):
        return [t for t in self.targets if t["role"] == "target"]

    def configuration(self, events, blacklist, invalid=False):
        text = super().configuration(events, blacklist, invalid)
        text = text.replace("ThresholdPercent = 60", "ThresholdPercent = %d" % self.a.threshold_percent)
        text = text.replace("MaxMemoryObjectEntries = 7", "MaxMemoryObjectEntries = %d" % self.a.top_k)
        text = text.replace("RunTracingToolTimeout = 3", "RunTracingToolTimeout = %d" % self.a.capture_timeout)
        if self.tracer_name == "memburst":
            text = text.replace("Interval = 1\n", "Interval = %d\n" % self.a.poll_interval)
        return text

    def prepare(self):
        verify_build(self.build)
        self.environment = DockerEnvironment(self.out)
        self.environment.build_image(self.build/"business-go")
        self.discovery = Discovery(self.environment.driver)
        self.discovery.start()
        self.server, self.api = self.discovery.server, self.environment.api
        self.targets, self.pressured, self.extra_processes = [], [], []
        for copy in range(self.a.copies):
            directory = self.out/("target-%03d" % copy)
            directory.mkdir()
            for target in launch_services(self.environment, directory, self.a.languages.split(","), self.a.java_home, self.a.python):
                target.update(id="target-%03d-%s" % (copy, target["language"]), role="target")
                self.targets.append(target)
                self.discovery.register(target)
        directory = self.out/"neighbor"
        directory.mkdir()
        for target in launch_services(self.environment, directory, ["go"], self.a.java_home, self.a.python, go_heap_mib=1):
            target.update(id="neighbor-go", role="neighbor")
            self.targets.append(target)
        for target in self.targets:
            run("docker", "update", "--memory", "%dm" % self.a.memory_limit_mib,
                "--memory-swap", "%dm" % self.a.memory_limit_mib, target["cid"])
            target["oom_before"] = (target["cgroup"]/"memory.failcnt").read_text().strip()
            target["initial_state"] = json.loads(request_http(target["url"], "/txn?seq=1", True))
            require(target["initial_state"]["total"] == 13, "initial business transaction mismatch")
            self.evidence.register(target["id"]+"-business.log", "business_log")
        selected = set(self.a.pressure_languages.split(","))
        self.pressured = [t for t in self.targets if t["role"] == "target" and t["language"] in selected][:self.a.pressure_targets]
        require(len(self.pressured) == self.a.pressure_targets, "not enough selected pressure targets")
        self.measurement_targets = select_load_targets(self.targets, self.pressured, self.a.load_all)
        if self.tracer_name == "memburst" and not any(t["language"] == "go" for t in self.pressured):
            # Anonymous pressure requires a real Go driver in the existing fixture.
            self.driver = next(t for t in self.targets if t["role"] == "target" and t["language"] == "go")
        else:
            self.driver = None
        for index in range(self.a.extra_processes):
            process = ManagedProcess()
            name = "ranking-%04d.log" % index
            self.evidence.register(name, "ranking_process_log")
            process.start([str(self.build/"business-go"), "1"], self.out/name, dict(os.environ))
            self.extra_processes.append(process)
            wait_for("ranking process ready", lambda n=name: '"url"' in (self.out/n).read_text(), timeout=20)
        manifest = json.loads((self.build/"build.json").read_text())
        manifest.update(performance_evaluated=True, claim="validation fixture; not production benchmark",
                        kernel=os.uname().release, machine=platform.machine(), cgroup="v1",
                        cpu_count=os.cpu_count(), load_generator="co-located stdlib fixed-arrival",
                        java=run(self.a.java_home+"/bin/java", "-version").stderr,
                        python=run(self.a.python, "--version").stdout,
                        targets=[{k:v for k,v in t.items() if k not in ("ctl", "cgroup")} for t in self.targets],
                        binaries={name:hashlib.sha256((self.build/name).read_bytes()).hexdigest() for name in ("agent", "business-go")},
                        bpf={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(self.a.bpf_dir).glob("*.o")})
        self.evidence.register("environment.json", "environment", format="json")
        (self.out/"environment.json").write_text(json.dumps(manifest, indent=2)+"\n")

    def cleanup(self):
        errors = []
        try:
            self.stop_agent(kill=True)
        except Exception as exc:
            errors.append(repr(exc))
        for process in self.extra_processes:
            try:
                process.stop(kill=True)
            except Exception as exc:
                errors.append(repr(exc))
        if hasattr(self, "environment"):
            for target in self.targets:
                try:
                    log = run("docker", "logs", target["cid"])
                    (self.out/(target["id"]+"-business.log")).write_text(log.stdout+log.stderr)
                except Exception as exc:
                    errors.append(repr(exc))
            try:
                self.environment.cleanup([])
            except Exception as exc:
                errors.append(repr(exc))
        if hasattr(self, "discovery"):
            self.discovery.cleanup()
        require(not errors, "performance cleanup failed: "+"; ".join(errors))


def drive_pressure(owner, args, group, start, pressure, stop):
    targets = owner.pressured + ([owner.driver] if owner.driver else [])
    applied = []
    try:
        if stop.wait(max(0, start+args.warmup+args.baseline-time.monotonic())):
            return
        pressure["started"], pressure["epoch_started"] = time.monotonic(), time.time()
        if args.experiment == "pulse":
            for target in targets:
                if stop.is_set():
                    break
                command = dict(target=target["id"], mib=args.pressure_mib, time=time.monotonic(), epoch=time.time())
                write_control(target["ctl"]/"target_mb", str(args.pressure_mib))
                applied.append(target)
                pressure["commands"].append(command)
        until, seen = start+args.warmup+args.baseline+args.hold, 0
        while time.monotonic() < until and not stop.is_set():
            if group != "A" and owner.event_path.exists():
                documents = read_documents(owner.event_path)
                if len(documents) > seen:
                    pressure["events"].append(dict(time=time.monotonic(), count=len(documents)))
                    seen = len(documents)
            stop.wait(.05)
    except Exception as exc:
        pressure["errors"].append(repr(exc))
    finally:
        for target in applied:
            try:
                write_control(target["ctl"]/"target_mb", "0")
            except Exception as exc:
                pressure["errors"].append(repr(exc))
        pressure["released"] = time.monotonic()


def execute_trial(args, directory, group, repeat):
    evidence = EvidenceStore(directory)
    owner = PerformanceAdapter(args, evidence)
    sampler, pressure_thread = None, None
    outcome = dict(group=group, repeat=repeat, valid=False, errors=[], metrics={})
    pressure = dict(commands=[], events=[], errors=[])
    control_stop = threading.Event()
    try:
        owner.prepare()
        if group != "A":
            owner.start_agent(plain=True, disabled=group == "B")
        sampler = PerformanceSampler(owner, evidence.output/"resources.jsonl", args.sample_interval)
        evidence.register("resources.jsonl", "performance_resources", format="jsonl")
        evidence.register("requests.jsonl", "performance_requests", format="jsonl")
        evidence.register("pressure.json", "performance_pressure", format="json")
        duration = args.warmup+args.baseline+args.hold+args.recovery
        start = time.monotonic()+.5
        scheduled_epoch = time.time()+.5
        sampler.start()
        pressure_thread = threading.Thread(target=drive_pressure, args=(owner, args, group, start, pressure, control_stop), daemon=True)
        pressure_thread.start()
        targets = [dict(id=t["id"], url=t["url"]) for t in owner.measurement_targets]
        rows = run_load(targets, evidence.output/"requests.jsonl", args.qps, duration,
                        args.workers, args.pending, expected=EXPECTED, start_at=scheduled_epoch, start_monotonic=start)
        pressure_thread.join(10)
        require(not pressure_thread.is_alive(), "pressure controller did not stop")
        sampler.close()
        measured_start, measured_end = start+args.warmup, start+duration
        resources = resource_metrics(sampler.rows, measured_start, measured_end)
        outcome["metrics"] = {key:resources[key] for key in ("cpu_seconds", "sampled_agent_tree_rss_peak_bytes")}
        outcome.update(resources=resources, windows={}, load={})
        for target_id, counters in resources["business"].items():
            for key, value in counters.items():
                outcome["metrics"][target_id+"."+key] = value
        windows = dict(measured=(measured_start, measured_end),
                       baseline=(measured_start, measured_start+args.baseline),
                       trigger=(measured_start+args.baseline, measured_end-args.recovery),
                       recovery=(measured_end-args.recovery, measured_end))
        for name, (begin, end) in windows.items():
            outcome["windows"][name] = dict(begin=begin, end=end, targets={})
            for target in targets:
                chosen = [r for r in rows if r["target"] == target["id"] and begin <= r["scheduled"] < end]
                expected_count = sum(1 for n in range(math.ceil(duration*args.qps)) if begin <= start+n/args.qps < end)
                stats = summarize_requests(chosen, expected_count, end-begin, args.max_dispatch_lag)
                outcome["windows"][name]["targets"][target["id"]] = stats
                if name == "measured":
                    outcome["load"][target["id"]] = stats
                    outcome["metrics"][target["id"]+".rps"] = stats["success_rps"]
                    outcome["metrics"][target["id"]+".p99_ms"] = stats["latency_ms"]["p99"]
                    if not stats["valid_load"] or stats["missing"] or stats["errors"]:
                        outcome["errors"].append("invalid load or business errors: "+target["id"])
        require(not pressure["errors"], "pressure controller failed: "+str(pressure["errors"]))
        require(resources["samples"] >= 2 and not resources["errors"], "incomplete/error resource samples")
        for target in owner.targets:
            require(identity(target["pid"]) == target["identity"], "business process changed")
            require((target["cgroup"]/"memory.failcnt").read_text().strip() == target["oom_before"], "business memory allocation hit limit")
            require(request_http(target["url"], "/work") == EXPECTED, "business checksum mismatch")
            state = json.loads(request_http(target["url"], "/txn?seq=2", True))
            require(state["seq"] == 2 and state["total"] == 39 and state["ticks"] > target["initial_state"]["ticks"], "business state/progress mismatch")
        require(all(p.process.poll() is None for p in owner.extra_processes), "ranking scale disappeared")
        if group != "A":
            require(owner.agent.poll() is None, "Agent exited before event finalization")
            owner.stop_agent()
        documents = strict_documents(owner.event_path) if group != "A" else []
        if group == "D":
            require("epoch_started" in pressure, "pressure did not start")
            require(all(parse_timestamp(d["started_timestamp"]).timestamp() >= pressure["epoch_started"] for d in documents), "unexpected pre-pulse capture invalidates experiment")
        records = capture_records(args.module, documents, {t["pid"] for t in owner.pressured},
                                  not_before=pressure.get("epoch_started") if group == "D" else None,
                                  not_after=scheduled_epoch+duration if group == "D" else None)
        all_records = capture_records(args.module, documents, {t["pid"] for t in owner.targets})
        neighbor_pids = {t["pid"] for t in owner.targets if t["role"] == "neighbor"}
        neighbor_selected = any(r["pid"] in neighbor_pids for r in all_records)
        outcome.update(captures=records, all_business_captures=all_records, neighbor_selected=neighbor_selected, persisted_events=len(documents),
                       selected_pids=sorted(set(r["pid"] for r in records)),
                       requested_target_pids=[t["pid"] for t in owner.pressured],
                       event_bytes=owner.event_path.stat().st_size if group != "A" and owner.event_path.exists() else 0,
                       observed_process_count=sum(p.name.isdigit() for p in Path("/proc").iterdir()))
        if group != "A" and owner.event_path.exists():
            evidence.register(str(owner.event_path.relative_to(evidence.output)), "performance_events", format="json_documents")
        if args.experiment == "pulse":
            for target in owner.pressured:
                peaks = [int(r["cgroups"][target["id"]]["memory.usage_in_bytes"]) for r in sampler.rows if target["id"] in r.get("cgroups", {})]
                require(max(peaks, default=0) >= args.pressure_mib*.85*(1<<20), "requested pressure was not observed")
        if group == "D":
            require(not neighbor_selected, "neighbor was selected for collection; cannot claim uncollected-neighbor impact")
            require(captures_cover_targets(records, {t["pid"] for t in owner.pressured}), "missing or failed requested-target capture; never score incomplete collection as cheap success")
        else:
            require(not documents, "unexpected capture in non-trigger control")
        outcome["valid"] = not outcome["errors"]
    except Exception as exc:
        outcome["errors"].append(repr(exc))
    finally:
        control_stop.set()
        if pressure_thread and pressure_thread.is_alive():
            pressure_thread.join(5)
            if pressure_thread.is_alive():
                outcome["errors"].append("pressure controller failed to stop")
        if sampler and not sampler.stream.closed:
            try:
                sampler.close()
            except Exception as exc:
                outcome["errors"].append(repr(exc))
        try:
            owner.cleanup()
        except Exception as exc:
            outcome["errors"].append(repr(exc))
        outcome["valid"] = outcome["valid"] and not outcome["errors"]
        (evidence.output/"pressure.json").write_text(json.dumps(pressure, indent=2)+"\n")
        evidence.save(outcome)
    return outcome


def campaign(args, output):
    output = Path(output)
    trials = []
    rng = random.Random(args.seed)
    for repeat in range(args.repeats):
        groups = experiment_groups(args.experiment)
        rng.shuffle(groups)
        for group in groups:
            name = "trial-%02d-%s" % (repeat, group)
            write_control(output/"progress.json", json.dumps(dict(phase=name, started=time.monotonic(), idle_budget=args.phase_timeout)))
            trial = execute_trial(args, output/name, group, repeat)
            trial["directory"] = name
            trials.append(trial)
            write_control(output/"results.json", json.dumps(dict(config=vars(args), trials=trials), indent=2)+"\n")
    return trials


def report(output):
    output = Path(output)
    data = json.loads((output/"results.json").read_text())
    trials, config = data["trials"], data["config"]
    enabled = "C" if config["experiment"] == "idle" else "D"
    comparisons = [paired_comparisons(trials, enabled, "B"), paired_comparisons(trials, enabled, "A")]
    supervisor_path = output/"supervisor.json"
    supervisor = json.loads(supervisor_path.read_text()) if supervisor_path.exists() else {"reason": "missing supervisor"}
    campaign_errors = bool(supervisor.get("returncode") or supervisor.get("reason") or supervisor.get("cleanup_errors"))
    complete = len(trials) == config["repeats"]*3 and all(
        sorted(t["group"] for t in trials if t["repeat"] == repeat) == sorted(experiment_groups(config["experiment"]))
        for repeat in range(config["repeats"]))
    status = "VALIDATION_PASS" if not campaign_errors and complete and all(t["valid"] for t in trials) else "INVALID_OR_FAILED"
    summary = dict(status=status, performance_acceptance="NOT_EVALUATED", comparisons=comparisons,
                   valid_trials=sum(t["valid"] for t in trials), total_trials=len(trials), supervisor=supervisor)
    (output/"analysis.json").write_text(json.dumps(summary, indent=2)+"\n")
    text = ["# Memory snapshot performance validation", "", "Status: "+status,
            "", "Performance acceptance: NOT_EVALUATED. Co-located validation fixture; no production SLO claim.",
            "", "Module: `%s`; experiment: `%s`; repeats: %d." % (config["module"], config["experiment"], config["repeats"]),
            "", "| Trial | Valid | Captures | Errors |", "|---|---|---:|---|"]
    for t in trials:
        text.append("| %s | %s | %d | %s |" % (t["directory"], t["valid"], len(t.get("captures", [])), "; ".join(t["errors"]).replace("|", "/")))
    text += ["", "## Paired absolute deltas", "", "Only valid pairs; p99 needs >=1000 requests per target/window.", "", "| Comparison | Metric | Median delta | Min | Max | Pairs |", "|---|---|---:|---:|---:|---:|"]
    for comparison in comparisons:
        for key, value in comparison["absolute_delta"].items():
            text.append("| %s−%s | %s | %.6g | %.6g | %.6g | %d |" % (comparison["enabled"], comparison["baseline"], key, value["median"], value["min"], value["max"], value["n"]))
    text += ["", "CPU is Agent self plus waited-child delta; child CPU is attributed at reap. Live/unreaped children at window boundaries are excluded; sampled-tree CPU is separate.",
             "RSS is a sampled simultaneous sum, not unique physical memory or an exact peak.",
             "Raw per-target latency, pressure commands, events, host PSI and cgroup observations are retained per trial.",
             "Failed captures and invalid load runs remain in the report and are excluded from paired conclusions."]
    (output/"REPORT.md").write_text("\n".join(text)+"\n")
    return summary
