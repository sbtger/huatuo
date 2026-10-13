# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import hashlib, json, os, sys
from pathlib import Path
from ....core.models import OperationResult, Scenario
from ....core.util import require, run, wait_for
from ....environments.docker import DockerEnvironment
from ....environments.linux import ManagedProcess, identity
from ....workloads.fixtures import launch_services
from ....workloads.http_probe import Traffic, request_http
from ..agent import command as agent_command
from ..discovery import Discovery
from .trigger import SnapshotTrigger
from .faults import FaultScenarios
from .policy import audit_artifacts

TRACER = "memory_threshold_snapshot"
BLACKLIST = """arp ascend_npu cpu_stat cpu_util cpuidle cpusys diskio dload dropwatch hungtask irqtracing iolatency iotracing loadavg memburst memory_buddyinfo memory_events memory_free memory_others memory_reclaim memory_reclaim_events memory_vmstat metax_gpu mthreads_gpu mountpoint_perm net_rx_latency netdev netdev_bonding_lacp netdev_dcb netdev_events netdev_hw netdev_qdisc netdev_rdma_link netdev_txqueue_timeout netstat memory_oom_kill ras runqlat sched_tick sockstat softirq softlockup tcp_memory tcp_retransmit""".split()
FAULTS = [
    "permission",
    "efault",
    "short",
    "panic",
    "cancel",
    "delay",
    "block",
    "kill_after_read",
    "restart",
    "storage_full",
    "invalid_config",
]


class MemsnapshotAdapter:
    def __init__(self, a, evidence):
        self.a = a
        self.evidence = evidence
        self.out = evidence.output
        self.build = Path(a.build).resolve()
        self.targets = []
        self.probes = []
        self.agent = None
        self.number = 0
        self.server = None
        self.case_name = ""
        self.last_capture = 0.0
        self.faultfile = self.out / "fault.json"
        self.faultfile.write_text("{}")
        self.process = ManagedProcess()
        self.trigger = SnapshotTrigger(self)
        self.fault_scenarios = FaultScenarios(self)

    tracer_name = TRACER
    adapter_id = "huatuo.memsnapshot"
    requires_audit_policy = True

    def prepare(self):
        self.environment = DockerEnvironment(self.out)
        self.environment.build_image(self.build / "business-go")
        self.discovery = Discovery(self.environment.driver)
        self.discovery.start()
        self.server = self.discovery.server
        self.api = self.environment.api
        self.targets = launch_services(
            self.environment,
            self.out,
            self.a.languages.split(","),
            self.a.java_home,
            self.a.python,
        )
        for target in self.targets:
            self.discovery.register(target)
            target["oom_before"] = (
                (target["cgroup"] / "memory.failcnt").read_text().strip()
            )
            self.evidence.register(
                target["language"] + "-requests.jsonl",
                "requests",
                target_id=target["language"],
                format="jsonl",
            )
            self.evidence.register(target["language"] + "-business.log", "business_log")
            probe = Traffic(target, self.out, self.a.qps)
            self.probes.append(probe)
            probe.start()
        manifest = json.loads((self.build / "build.json").read_text())
        root = Path(__file__).resolve().parents[3]
        manifest.update(
            adapter_id=self.adapter_id,
            kernel=os.uname().release,
            cgroup="v1",
            java=run(self.a.java_home + "/bin/java", "-version").stderr,
            python=run(self.a.python, "--version").stdout,
            qps_per_language=self.a.qps,
            targets=[
                {k: v for k, v in t.items() if k not in ("ctl", "cgroup")}
                for t in self.targets
            ],
            performance_evaluated=False,
            bpf_sha256={
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path(self.a.bpf_dir).glob("*.o")
            },
            source_sha256={
                str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in root.rglob("*")
                if p.suffix in (".py", ".go", ".java", ".c")
            },
            command_line=list(sys.argv),
        )
        (self.out / "environment.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        self.evidence.register("environment.json", "environment", format="json")

    def plan(self):
        phases = ["agent-off", "blacklist", "plain-agent", "instrumented-control"]
        for fault in self.a.faults.split(","):
            phases.extend([fault, fault + "-recovery"])
        return [t["language"] + "/" + phase for t in self.targets for phase in phases]

    def scenarios(self):
        return self.fault_scenarios.scenarios()

    def scenario(self, target, name, operation, expected=False):
        phase = target["language"] + "/" + name

        def execute():
            self.case_name = phase
            detail = operation() or {}
            hits = detail.get("fault_hits", self.hits()) if expected else 0
            artifacts = []
            if self.number:
                artifacts = [
                    "agent-%d.log" % self.number,
                    "bamai-%d.conf" % self.number,
                ]
            if detail.get("event_file"):
                artifacts.append(str(Path(detail["event_file"]).relative_to(self.out)))
            return OperationResult(detail=detail, fault_hits=hits, evidence=artifacts)

        return Scenario(phase, target["language"], execute, expect_fault=expected)

    def quiesce(self):
        self.stop_agent()

    def verify_final(self):
        for target in self.targets:
            require(
                self.trigger.oom(target) == target["oom_before"],
                "business hit its memory limit",
            )
            require(identity(target["pid"]) == target["identity"], "business restarted")

    def audit_artifacts(self, output, summary, manifest):
        return audit_artifacts(output, summary, manifest)

    def cleanup(self):
        try:
            self.stop_agent(kill=True)
        finally:
            try:
                if hasattr(self, "environment"):
                    self.environment.cleanup(self.targets)
            finally:
                if hasattr(self, "discovery"):
                    self.discovery.cleanup()

    def start_agent(
        self,
        plain=False,
        permission=False,
        storage_full=False,
        invalid=False,
        disabled=False,
    ):
        require(self.agent is None, "Agent already running")
        self.number += 1
        events = self.out / ("events-%d" % self.number)
        events.mkdir()
        self.event_path = events / TRACER
        if storage_full:
            self.event_path.symlink_to("/dev/full")
        blacklist = BLACKLIST + ([TRACER] if disabled else [])
        conf = self.out / ("bamai-%d.conf" % self.number)
        self.evidence.register(conf.name, "agent_config")
        conf.write_text(
            """BlackList = %s
[HTTPServer]
ListenAddress = "127.0.0.1:%d"
[HTTPServer.Auth]
BearerToken = "memsnapshot-business-test"
[Pod]
KubeletReadOnlyPort = %d
KubeletAuthorizedPort = 0
DockerAPIVersion = "%s"
[AutoTracing.MemoryThresholdSnapshot]
ThresholdPercent = %d
IntervalTracing = 1
RunTracingToolTimeout = 3
MaxMemoryObjectEntries = 7
[Storage.LocalFile]
Path = "%s"
"""
            % (
                json.dumps(blacklist),
                self.a.agent_port,
                self.server.server_port,
                self.api,
                101 if invalid else 60,
                events,
            )
        )
        logfile = self.out / ("agent-%d.log" % self.number)
        self.evidence.register(logfile.name, "agent_log")
        self.logpath = logfile
        binary = self.build / ("agent" if plain else "agent-fault")
        cmd = agent_command(binary, conf, self.out, self.a.bpf_dir)
        if permission:
            cmd = [str(self.build / "deny-readv")] + cmd
        self.agent = self.process.start(
            cmd,
            logfile,
            {**os.environ, "HUATUO_MEMSNAP_FAULT_FILE": str(self.faultfile)},
        )
        if invalid:
            # Configuration may reject startup or disable this tracer. Both must be explicit.
            wait_for(
                "invalid threshold rejection",
                lambda: (
                    "threshold percent must be in [1, 100]" in logfile.read_text()
                ),
                timeout=20,
            )
            return
        wait_for(
            "Agent metrics",
            lambda: self.agent.poll() is None
            and request_http("http://127.0.0.1:%d" % self.a.agent_port, "/metrics"),
            timeout=45,
        )
        metrics = request_http(
            "http://127.0.0.1:%d" % self.a.agent_port, "/metrics"
        ).decode()
        self.evidence.register("metrics-%d.txt" % self.number, "agent_metrics")
        (self.out / ("metrics-%d.txt" % self.number)).write_text(metrics)
        require(
            ('tracing="' + TRACER + '"' in metrics) != disabled,
            "tracing status disagrees with configured switch",
        )
        if not disabled:
            for t in self.targets:
                wait_for(
                    "registered threshold watch " + t["language"],
                    lambda t=t: self.trigger.watch_ready(t),
                    timeout=35,
                )

    def stop_agent(self, kill=False):
        if self.agent:
            try:
                self.last_agent_exit = self.process.stop(kill)
            finally:
                self.agent = None

    def setfault(self, t, action):
        tmp = self.faultfile.with_suffix(".tmp")
        tmp.write_text(json.dumps(dict(pid=t["pid"], action=action, id=self.case_name)))
        tmp.replace(self.faultfile)

    def clearfault(self):
        self.faultfile.write_text("{}")

    def hits(self):
        return self.logpath.read_text().count(
            "MEMSNAP_FAULT id=" + self.case_name + " "
        )
