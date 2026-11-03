# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Repeated real-Agent campaigns reuse the fault-isolation runner and canaries."""
import json
import os
import signal
import time
from pathlib import Path
from ....core.models import Scenario, OperationResult
from ....core.stability import coverage_errors, resource_errors
from ....core.util import write_control, require, run, wait_for
from ....environments.linux import identity, ManagedProcess
from ....environments.resources import ResourceMonitor, resource_sample_interval
from ....workloads.http_probe import request_http
from ....core.documents import read_documents
from ..discovery import PodFixture
from ..memsnapshot.adapter import MemsnapshotAdapter, BLACKLIST
from ..memsnapshot.assertions import validate_fault
from .trigger import StabilityTrigger, burst_anon_floor
from .policy import audit_artifacts
from .resource_faults import resource_fault
from . import reliability
from .diagnostics import capture_failure
from ..memsnapshot.worker import worker_enabled, containment


class StabilityAdapter(MemsnapshotAdapter):
    requires_audit_policy = True

    def __init__(self, args, evidence):
        super().__init__(args, evidence)
        self.tracer_name = args.module
        self.adapter_id = "huatuo.stability." + args.module
        self.trigger = StabilityTrigger(self)
        self.cycles = []
        self.started = None
        self.monitor = None
        self.counts = dict(
            captures=0,
            cgroup_replacements=0,
            limit_changes=0,
            observed_pid_reuse=0,
            agent_replacements=0,
        )
        self.seen_pids = {}
        self.agent_transition = False
        self.warmed_agents = set()
        self.warmed_languages = {}
        self.extra_processes = []

    def start_agent(self, **kwargs):
        if self.tracer_name == "memburst":
            self.trigger.release_all()
            time.sleep(1)
        self.agent_transition = True
        try:
            return super().start_agent(**kwargs)
        finally:
            self.agent_transition = False
            self.counts["agent_replacements"] = max(0, self.number - 1)

    def stop_agent(self, kill=False):
        if (
            self.monitor
            and not self.monitor.stream.closed
            and self.agent
            and self.agent.poll() is None
        ):
            self.monitor.record(settled=True)
        self.agent_transition = True
        try:
            return super().stop_agent(kill)
        finally:
            self.agent_transition = False

    def prepare(self):
        super().prepare()
        for probe in self.probes:
            probe.retain_history = False
        require(
            any(t["language"] == "go" for t in self.targets),
            "campaign needs the Go anonymous-pressure driver",
        )
        for index in range(self.a.extra_processes):
            process = ManagedProcess()
            name = "ranking-process-%04d.log" % index
            self.evidence.register(name, "business_log")
            process.start(
                [str(self.build / "business-go"), "1"],
                self.out / name,
                dict(os.environ),
            )
            self.extra_processes.append(process)
            wait_for(
                "ranking helper ready",
                lambda n=name: '"url"' in (self.out / n).read_text(),
                timeout=15,
            )
        self.started = time.monotonic()
        self.observe_workers = worker_enabled(self)
        self.monitor = ResourceMonitor(
            self, interval=resource_sample_interval(self.a.profile, self.observe_workers)
        )
        self.monitor.start()
        self.evidence.register("campaign.json", "campaign", format="json")
        self.evidence.register("cycles.jsonl", "cycles", format="jsonl")

    def blacklist(self):
        return (
            [
                "sched-blame",
                "xfs",
                "io_health",
                "iocost",
                "blk_throtl",
                "net_conntrack",
                "netdev_rdma_stat",
                "mthreads_xid",
            ]
            + [n for n in BLACKLIST if n != self.tracer_name]
            + (["memory_threshold_snapshot"] if self.tracer_name == "memburst" else [])
        )

    def configuration(self, events, blacklist, invalid=False):
        text = super().configuration(events, blacklist, invalid)
        text = text.replace(
            "IntervalTracing = 1", "IntervalTracing = %d" % self.a.cooldown
        )
        if self.tracer_name == "memburst":
            meminfo = {
                line.split(":", 1)[0]: int(line.split()[1])
                for line in Path("/proc/meminfo").read_text().splitlines()
            }
            floor = burst_anon_floor(
                meminfo["MemTotal"], meminfo["Active(anon)"] + meminfo["Inactive(anon)"]
            )
            text += """\n[AutoTracing.MemoryBurst]
DeltaMemoryBurst = 1
DeltaAnonThreshold = %d
Interval = 1
SlidingWindowLength = 2
IntervalTracing = %d
DumpProcessMaxNum = 10
""" % (
                floor,
                self.a.cooldown,
            )
        return text

    def names(self, cycle):
        names = [(t, "capture") for t in self.targets]
        names += [(self.targets[0], "cooldown"), (self.targets[0], "lifecycle")]
        if self.tracer_name == "memory_threshold_snapshot":
            names += [(self.targets[0], "limit-change")]
        if self.a.inject_faults and cycle % self.a.fault_every == 0:
            for t in self.targets:
                names += [(t, "fault"), (t, "recovery")]
            names += [
                (self.targets[0], "storage-full"),
                (self.targets[0], "storage-recovery"),
            ]
        names += (
            [(self.targets[0], "restart"), (self.targets[0], "restart-recovery")]
            if cycle % self.a.fault_every == 0
            else []
        )
        if self.a.resource_faults and cycle % self.a.fault_every == 0:
            for mode in ("agent-fd", "agent-oom"):
                names += [
                    (self.targets[0], mode),
                    (self.targets[0], mode + "-recovery"),
                ]
        names += [(self.targets[0], "settled")]
        return names

    def plan(self):
        return (
            ["cycle-0000/%s/agent-off" % t["language"] for t in self.targets]
            + ["cycle-0000/%s/warmup" % t["language"] for t in self.targets]
            + [
                "cycle-0000/%s/%s" % (self.targets[0]["language"], name)
                for name, _ in self.extra_checks()
            ]
            + [
                "cycle-%04d/%s/%s" % (cycle, t["language"], name)
                for cycle in range(1, self.a.cycles + 1)
                for t, name in self.names(cycle)
            ]
        )

    def wrap(self, cycle, target, name, operation, expected=False):
        phase = "cycle-%04d/%s/%s" % (cycle, target["language"], name)

        def execute():
            self.case_name = phase
            point = dict(phase=phase, started=time.monotonic(), idle_budget=0)
            if name == "steady":
                point["idle_budget"] = (
                    self.a.steady_seconds
                    + self.a.steady_rounds * 90
                    + self.a.phase_timeout
                )
            if name == "settled":
                point["idle_budget"] = (
                    self.a.duration_seconds / self.a.cycles + self.a.phase_timeout
                )
            temporary = Path(self.a.output) / "progress.tmp"
            temporary.write_text(json.dumps(point))
            temporary.replace(Path(self.a.output) / "progress.json")
            detail = operation() or {}
            require(
                not reliability.contract_errors(detail.get("check"), detail),
                "reliability check contract failed",
            )
            detail["module"] = self.tracer_name
            artifacts = (
                ["agent-%d.log" % self.number, "bamai-%d.conf" % self.number]
                if self.number
                else []
            )
            if detail.get("witness"):
                artifacts.append(detail["witness"])
            if detail.get("event_file"):
                artifacts.append(str(Path(detail["event_file"]).relative_to(self.out)))
            if detail.get("worker_witness"):
                artifacts.append(detail["worker_witness"])
                capture = detail.get("failed_worker_capture") or detail.get("recovery")
                if capture and capture.get("event_file"):
                    relative = str(Path(capture["event_file"]).relative_to(self.out))
                    if relative not in artifacts:
                        artifacts.append(relative)
            return OperationResult(detail, detail.get("fault_hits", 0), artifacts)

        return Scenario(phase, target["language"], execute, expected, minimum_seconds=1)

    def capture(self, target, not_before=None):
        # Single-target checks must not inherit another target's high pressure.
        # Before a fresh Agent this also prevents an untracked startup capture.
        self.trigger.release_all()
        if self.agent is None:
            self.start_agent(plain=True)
        kwargs = {"not_before": not_before} if not_before is not None else {}
        try:
            result = self.trigger.capture(target, normal=True, **kwargs)
        except Exception as error:
            try:
                capture_failure(self, error)
            except Exception as diagnostic_error:
                print("capture diagnostics unavailable: " + repr(diagnostic_error), flush=True)
            raise
        result["target_language"] = target["language"]
        self.counts["captures"] += 1
        agent_id = tuple(identity(self.agent.pid))
        self.warmed_languages.setdefault(agent_id, set()).add(target["language"])
        all_languages = {t["language"] for t in self.targets}
        if (
            agent_id not in self.warmed_agents
            and self.warmed_languages[agent_id] == all_languages
        ):
            self.trigger.release_all()
            self.monitor.record(settled=True, baseline=True)
            self.warmed_agents.add(agent_id)
        return result

    def cooldown(self, target):
        return reliability.cooldown(self, target)

    def extra_checks(self):
        selected = getattr(self.a, "checks", "").split(",")
        checks = []
        if "steady" in selected:
            checks.append(("steady", lambda: reliability.steady(self)))
        for mode in ("efault", "delay", "block"):
            if "isolation-" + mode in selected:
                checks.append(
                    (
                        "isolation-" + mode,
                        lambda m=mode: reliability.isolation(self, self.targets[0], m),
                    )
                )
        if "target-exit" in selected:
            checks.append(("target-exit", lambda: reliability.target_exit(self)))
        return checks

    def limit_change(self, target):
        original = int((target["cgroup"] / "memory.limit_in_bytes").read_text())
        captured = []
        try:
            for _ in range(self.a.churn_per_cycle):
                self.trigger.release_all()
                (target["cgroup"] / "memory.limit_in_bytes").write_text(
                    str(700 * 1024 * 1024)
                )
                captured.append(self.capture(target))
                (target["cgroup"] / "memory.limit_in_bytes").write_text(str(original))
                self.counts["limit_changes"] += 1
        finally:
            (target["cgroup"] / "memory.limit_in_bytes").write_text(str(original))
        return dict(changes=len(captured), captures=captured)

    def lifecycle(self, cycle):
        rows = []
        self.trigger.release_all()
        for index in range(self.a.churn_per_cycle):
            ctl = self.out / ("churn-%04d-%04d" % (cycle, index))
            ctl.mkdir()
            write_control(ctl / "target_mb", "0")
            window_started = time.time()
            target = self.environment.launch(
                [
                    "--network",
                    "host",
                    "--memory",
                    "768m",
                    "--memory-swap",
                    "768m",
                    "-v",
                    str(ctl) + ":/control:ro",
                ],
                ["/business-go"],
            )
            target.update(language="go", ctl=ctl)
            old = self.seen_pids.get(target["pid"])
            reused = old is not None and old != target["identity"]
            self.counts["observed_pid_reuse"] += int(reused)
            self.seen_pids[target["pid"]] = target["identity"]
            self.discovery.register(target)
            try:
                if self.tracer_name != "memburst":
                    wait_for(
                        "replacement cgroup registered",
                        lambda: self.trigger.watch_ready(target),
                        timeout=45,
                    )
                result = self.capture(target)
                rows.append(
                    dict(
                        pid=target["pid"],
                        identity=target["identity"],
                        cid=target["cid"],
                        cgroup=str(target["cgroup"]),
                        capture=result,
                        observed_pid_reuse=reused,
                        window_started=window_started,
                        window_finished=time.time(),
                    )
                )
                name = ctl.name + ".log"
                self.evidence.register(name, "business_log")
                (self.out / name).write_text(
                    run("docker", "logs", target["cid"]).stdout
                )
            finally:
                PodFixture.containers.pop(target["cid"], None)
                run("docker", "rm", "-f", target["cid"])
                self.environment.containers.remove(target["cid"])
            wait_for(
                "replacement cgroup removed",
                lambda: not target["cgroup"].exists(),
                timeout=20,
            )
            self.counts["cgroup_replacements"] += 1
        recovered = self.capture(self.targets[0])
        finished = time.time()
        for row in rows:
            row["window_finished"] = finished
        return dict(replacements=rows, post_delete_capture=recovered)

    def inject(self, target, action):
        self.trigger.release_all()
        self.clearfault()
        # Clear syscall-wide irreversible constraints by using a fresh Agent.
        self.stop_agent()
        self.setfault(target, "mark" if action == "permission" else action)
        self.start_agent(permission=action == "permission")
        if action in ("block", "kill_after_read"):
            self.trigger.pressure(target)
            marker = (
                "MEMSNAP_READ_COMPLETED id="
                if action == "kill_after_read"
                else "MEMSNAP_FAULT id="
            ) + self.case_name
            wait_for(
                "blocked read reached",
                lambda: marker in self.logpath.read_text(),
                timeout=40,
            )
            worker_detail = containment(self, target) if worker_enabled(self) else {}
            time.sleep(0 if worker_detail else 3)
            metrics = request_http(
                "http://127.0.0.1:%d" % self.a.agent_port, "/metrics"
            )
            require(metrics, "blocked Agent HTTP unavailable")
            metrics_name = "blocked-http-%d.txt" % self.number
            self.evidence.register(metrics_name, "agent_metrics")
            (self.out / metrics_name).write_bytes(metrics)
            if worker_detail:
                worker_detail.update(worker_detail["failed_worker_capture"])
                return dict(worker_detail, action=action, target_pid=target["pid"], witness=metrics_name,
                            agent_http_responsive=True, fault_hits=self.hits())
            require(
                not read_documents(self.event_path),
                "blocked capture unexpectedly persisted",
            )
            hits, pid = self.hits(), self.agent.pid
            self.stop_agent(kill=True)
            require(
                self.last_agent_exit == -signal.SIGKILL,
                "blocked Agent SIGKILL not confirmed",
            )
            return dict(
                action=action,
                target_pid=target["pid"],
                killed_agent_pid=pid,
                exit_signal="SIGKILL",
                witness=metrics_name,
                agent_http_responsive=True,
                fault_hits=hits,
            )
        result = self.trigger.capture(target)
        errors = validate_fault(action, result)
        require(not errors, "; ".join(errors))
        result.update(
            action="mark" if action == "permission" else action,
            fault_mode=action,
            target_pid=target["pid"],
            fault_hits=self.hits(),
        )
        require(result["fault_hits"] > 0, "fault injection was not reached")
        return result

    def recover(self, target):
        old = identity(self.agent.pid) if self.agent else None
        restart = (
            self.a.faults.split(",")[
                (self.current_cycle // self.a.fault_every - 1)
                % len(self.a.faults.split(","))
            ]
            == "permission"
        )
        self.clearfault()
        if restart:
            self.stop_agent()
        result = self.capture(target)
        require(
            old is None or restart or identity(self.agent.pid) == old,
            "same-Agent recovery replaced the Agent",
        )
        result["recovery_same_agent"] = old is not None and not restart
        return result

    def storage_full(self, target):
        self.trigger.release_all()
        self.stop_agent()
        self.clearfault()
        self.start_agent(storage_full=True, plain=True)
        self.trigger.pressure(target)
        wait_for(
            "real ENOSPC from event writer",
            lambda: "no space left on device" in self.logpath.read_text(),
            timeout=45,
        )
        return dict(storage_failure="ENOSPC")

    def fresh(self, target, kill=False):
        self.trigger.release_all()
        self.stop_agent(kill=kill)
        require(
            self.last_agent_exit == (-signal.SIGKILL if kill else 0),
            "Agent exit signal mismatch",
        )
        self.start_agent(plain=True)
        return self.capture(target)

    def settled(self, cycle, cycle_started):
        self.trigger.release_all()
        remaining = self.a.duration_seconds / self.a.cycles - (
            time.monotonic() - cycle_started
        )
        if remaining > 0:
            time.sleep(remaining)
        self.monitor.record(settled=True)
        require(
            not any(r.get("error") for r in self.monitor.rows),
            "resource observer reported failure",
        )
        row = dict(
            cycle=cycle,
            status="PASS",
            elapsed_seconds=time.monotonic() - self.started,
            counts=dict(self.counts),
            agent=identity(self.agent.pid),
        )
        self.cycles.append(row)
        with (self.out / "cycles.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        return row

    def agent_off(self, target):
        self.trigger.pressure(target)
        time.sleep(3)
        self.trigger.release_all()
        return dict(agent_enabled=False)

    def scenarios(self):
        for target in self.targets:
            yield self.wrap(0, target, "agent-off", lambda t=target: self.agent_off(t))
        for target in self.targets:
            yield self.wrap(0, target, "warmup", lambda t=target: self.capture(t))
        for name, operation in self.extra_checks():
            yield self.wrap(0, self.targets[0], name, operation)
        for cycle in range(1, self.a.cycles + 1):
            started = time.monotonic()
            self.current_cycle = cycle
            action = self.a.faults.split(",")[
                (cycle // self.a.fault_every - 1) % len(self.a.faults.split(","))
            ]
            for target, name in self.names(cycle):
                operations = {
                    "capture": lambda t=target: self.capture(t),
                    "cooldown": lambda t=target: self.cooldown(t),
                    "lifecycle": lambda c=cycle: self.lifecycle(c),
                    "limit-change": lambda t=target: self.limit_change(t),
                    "fault": lambda t=target, m=action: self.inject(t, m),
                    "recovery": lambda t=target: self.recover(t),
                    "storage-full": lambda t=target: self.storage_full(t),
                    "storage-recovery": lambda t=target: self.fresh(t),
                    "restart": lambda t=target, c=cycle: self.fresh(t, kill=c % 2 == 0),
                    "restart-recovery": lambda t=target: self.capture(t),
                    "agent-fd": lambda: resource_fault(self, "agent-fd"),
                    "agent-oom": lambda: resource_fault(self, "agent-oom"),
                    "agent-fd-recovery": lambda t=target: self.capture(t),
                    "agent-oom-recovery": lambda t=target: self.capture(t),
                    "settled": lambda c=cycle, at=started: self.settled(c, at),
                }
                yield self.wrap(cycle, target, name, operations[name], name == "fault")

    def quiesce(self):
        finalizing = dict(phase="finalizing", started=time.monotonic(), idle_budget=0)
        point = Path(self.a.output) / "progress.tmp"
        point.write_text(json.dumps(finalizing))
        point.replace(Path(self.a.output) / "progress.json")
        try:
            if self.monitor:
                self.monitor.record(settled=True)
                self.monitor.close()
        finally:
            super().quiesce()

    def verify_final(self):
        super().verify_final()
        for process in self.extra_processes:
            require(
                process.process is not None and process.process.poll() is None,
                "ranking helper exited",
            )
        elapsed = time.monotonic() - self.started
        issues = coverage_errors(
            self.a.cycles, self.a.duration_seconds, self.cycles, elapsed
        )
        if self.a.require_pid_reuse and self.counts["observed_pid_reuse"] == 0:
            issues.append("actual PID reuse was required but not observed")
        if self.monitor:
            if not any(row.get("baseline") for row in self.monitor.rows):
                issues.append("no fully warmed Agent growth baseline")
            issues += resource_errors(
                self.monitor.rows,
                self.a.rss_growth_mib * 1024 * 1024,
                self.a.fd_growth,
                self.a.rss_limit_mib * 1024 * 1024,
                self.a.fd_limit,
                watch_growth=self.a.watch_growth, thread_growth=self.a.thread_growth,
            )
        record = dict(
            status="FAIL" if issues else "PASS",
            profile=self.a.profile,
            module=self.tracer_name,
            minimum_seconds=self.a.duration_seconds,
            elapsed_seconds=elapsed,
            planned_cycles=self.a.cycles,
            completed_cycles=len(self.cycles),
            counts=self.counts,
            extra_processes=self.a.extra_processes,
            errors=issues,
            resource_limits=dict(
                rss_growth=self.a.rss_growth_mib * 1024 * 1024,
                fd_growth=self.a.fd_growth,
                rss_limit=self.a.rss_limit_mib * 1024 * 1024,
                fd_limit=self.a.fd_limit,
                watch_growth=self.a.watch_growth, thread_growth=self.a.thread_growth,
            ),
            performance_evaluated=False,
            long_soak_verified=self.a.profile == "soak"
            and elapsed >= 72 * 3600
            and not issues,
            pid_reuse_verified=self.counts["observed_pid_reuse"] > 0,
            unsupported=["cgroup-v2", "forced-blocked-syscall-cancellation"]
            + ([] if self.a.resource_faults else ["Agent-OOM", "Agent-FD-exhaustion"]),
        )
        (self.out / "campaign.json").write_text(json.dumps(record, indent=2) + "\n")
        require(not issues, "; ".join(issues))

    def cleanup(self):
        errors = []
        for process in self.extra_processes:
            try:
                process.stop()
            except Exception as exc:
                errors.append(repr(exc))
        try:
            super().cleanup()
        finally:
            require(not errors, "ranking helper cleanup failed: " + str(errors))

    def audit_artifacts(self, output, summary, manifest):
        return audit_artifacts(output, summary, manifest)
