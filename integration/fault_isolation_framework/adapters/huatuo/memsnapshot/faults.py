# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import signal, time
from ....core.util import require, wait_for
from ....core.documents import read_documents
from ....workloads.http_probe import request_http
from .assertions import validate_fault


class FaultScenarios:
    def __init__(self, owner):
        self.owner = owner

    def fault(self, t, mode):
        self.owner.stop_agent()
        self.owner.trigger.release(t)
        self.owner.clearfault()
        injected = mode in (
            "efault",
            "short",
            "panic",
            "cancel",
            "delay",
            "block",
            "kill_after_read",
            "permission",
        )
        action = "mark" if mode == "permission" else mode

        def operation():
            self.owner.setfault(t, action if injected else "mark")
            self.owner.start_agent(
                permission=mode == "permission",
                storage_full=mode == "storage_full",
                invalid=mode == "invalid_config",
            )
            if mode == "invalid_config":
                return dict(rejection_log=str(self.owner.logpath))
            if mode == "restart":
                self.owner.stop_agent()
                require(
                    self.owner.last_agent_exit == 0,
                    "normal restart had an abnormal Agent exit",
                )
                self.owner.start_agent()
                return self.owner.trigger.capture(t, normal=True)
            if mode == "storage_full":
                (t["ctl"] / "target_mb").write_text("500")
                wait_for(
                    "storage ENOSPC",
                    lambda: "no space left on device" in self.owner.logpath.read_text(),
                    timeout=45,
                )
                return dict(storage_failure="ENOSPC", log=str(self.owner.logpath))
            if mode in ("block", "kill_after_read"):
                (t["ctl"] / "target_mb").write_text("500")
                marker = (
                    "MEMSNAP_READ_COMPLETED id=" + self.owner.case_name
                    if mode == "kill_after_read"
                    else "MEMSNAP_FAULT id=" + self.owner.case_name + " "
                )
                wait_for(
                    "capture fault marker",
                    lambda: marker in self.owner.logpath.read_text(),
                    timeout=45,
                )
                time.sleep(3)
                require(
                    self.owner.agent.poll() is None,
                    "Agent exited before the requested kill",
                )
                require(
                    request_http(
                        "http://127.0.0.1:%d" % self.owner.a.agent_port, "/metrics"
                    ),
                    "Agent HTTP stopped responding during collector stall",
                )
                require(
                    not read_documents(self.owner.event_path),
                    "blocked capture unexpectedly persisted",
                )
                pid = self.owner.agent.pid
                hits = self.owner.hits()
                self.owner.stop_agent(kill=True)
                require(
                    self.owner.last_agent_exit == -signal.SIGKILL,
                    "Agent did not exit from SIGKILL",
                )
                return dict(
                    killed_agent_pid=pid,
                    fault_hits=hits,
                    agent_http_responsive=True,
                    exit_signal="SIGKILL",
                )
            result = self.owner.trigger.capture(t)
            faults = validate_fault(mode, result)
            require(not faults, "; ".join(faults) + ": " + result["reason"])
            if mode == "permission":
                require(
                    "operation not permitted" in self.owner.logpath.read_text(),
                    "seccomp permission rejection not witnessed",
                )
            return result

        yield self.owner.scenario(t, mode, operation, expected=injected)
        oldpid = self.owner.agent.pid if self.owner.agent else None
        self.owner.clearfault()
        self.owner.trigger.release(t)
        # Restart is mandatory for irreversible seccomp, killed Agent and full storage.
        restart = mode in (
            "permission",
            "block",
            "kill_after_read",
            "storage_full",
            "invalid_config",
        )

        def recovery():
            if restart:
                self.owner.stop_agent()
                self.owner.start_agent()
            result = self.owner.trigger.capture(t, normal=True)
            result["recovery_same_agent"] = not restart
            result["previous_agent_pid"] = oldpid
            if not restart:
                require(
                    self.owner.agent.pid == oldpid,
                    "recovery unexpectedly replaced Agent",
                )
            return result

        yield self.owner.scenario(t, mode + "-recovery", recovery)
        self.owner.trigger.release(t)

    def scenarios(self):
        for t in self.owner.targets:
            self.owner.stop_agent()
            yield self.owner.scenario(t, "agent-off", lambda: dict(agent_enabled=False))

            def disabled(t=t):
                self.owner.trigger.release(t)
                self.owner.start_agent(disabled=True)
                (t["ctl"] / "target_mb").write_text("500")
                time.sleep(3)
                require(
                    self.owner.agent.poll() is None,
                    "blacklisted Agent exited during observation",
                )
                metrics = request_http(
                    "http://127.0.0.1:%d" % self.owner.a.agent_port, "/metrics"
                ).decode()
                require(
                    'tracing="' + self.owner.tracer_name + '"' not in metrics,
                    "blacklisted tracer became enabled",
                )
                require(
                    not read_documents(self.owner.event_path),
                    "blacklisted feature persisted a capture",
                )
                return dict(snapshot_enabled=False, agent_http_responsive=True)

            yield self.owner.scenario(t, "blacklist", disabled)
            self.owner.trigger.release(t)

            def baseline(t=t):
                self.owner.stop_agent()
                self.owner.start_agent(plain=True)
                return self.owner.trigger.capture(t, normal=True)

            yield self.owner.scenario(t, "plain-agent", baseline)
            self.owner.trigger.release(t)

            def control(t=t):
                self.owner.stop_agent()
                require(
                    self.owner.last_agent_exit == 0,
                    "normal restart had an abnormal Agent exit",
                )
                self.owner.start_agent()
                return self.owner.trigger.capture(t, normal=True)

            yield self.owner.scenario(t, "instrumented-control", control)
            self.owner.trigger.release(t)
            for mode in self.owner.a.faults.split(","):
                yield from self.fault(t, mode)
