# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Real, test-owned Agent resource failures; business cgroups remain unchanged."""
import json
import os
import signal
import sys
import time
import uuid
from ..agent import command
from ....environments.supervisor import own
from ....core.util import require, wait_for
from ....environments.linux import cgroup_mount


def resource_fault(owner, mode):
    owner.trigger.release_all()
    owner.stop_agent()
    owner.clearfault()
    owner.number += 1
    owner.counts["agent_replacements"] = owner.number - 1
    events = owner.out / ("events-%d" % owner.number)
    events.mkdir()
    owner.event_path = events / owner.tracer_name
    conf = owner.out / ("bamai-%d.conf" % owner.number)
    owner.evidence.register(conf.name, "agent_config")
    conf.write_text(owner.configuration(events, owner.blacklist()))
    owner.logpath = owner.out / ("agent-%d.log" % owner.number)
    owner.evidence.register(owner.logpath.name, "agent_log")
    cmd = command(owner.build / "agent", conf, owner.out, owner.a.bpf_dir)
    scope = None
    scope_created = False
    before = None
    owner.agent_transition = True
    try:
        if mode == "agent-oom":
            scope = cgroup_mount("1") / ("huatuo-stability-" + uuid.uuid4().hex[:12])
            scope.mkdir()
            scope_created = True
            own("cgroup", str(scope))
            (scope / "memory.limit_in_bytes").write_text(str(1024 * 1024))
            control = scope / "memory.oom_control"
            before = int(
                dict(line.split() for line in control.read_text().splitlines())[
                    "oom_kill"
                ]
            )
            script = (
                'import os,sys; print("STABILITY_AGENT_OOM",flush=True); '
                'open(sys.argv[1],"w").write(str(os.getpid())); '
                "os.execv(sys.argv[2],sys.argv[2:])"
            )
            wrapped = [sys.executable, "-c", script, str(scope / "cgroup.procs")] + cmd
        else:
            script = (
                'import os,resource,sys; print("STABILITY_AGENT_FD_LIMIT=16",flush=True); '
                "resource.setrlimit(resource.RLIMIT_NOFILE,(16,16)); "
                "os.execv(sys.argv[1],sys.argv[1:])"
            )
            wrapped = [sys.executable, "-c", script] + cmd
        owner.agent = owner.process.start(wrapped, owner.logpath, dict(os.environ))
        pid = owner.agent.pid
        if mode == "agent-oom":
            wait_for(
                "Agent killed by test cgroup OOM",
                lambda: owner.agent.poll() is not None,
                timeout=30,
            )
            after = int(
                dict(line.split() for line in control.read_text().splitlines())[
                    "oom_kill"
                ]
            )
            exitcode = owner.agent.returncode
            require(
                exitcode == -signal.SIGKILL and after > before,
                "Agent OOM not witnessed by kernel counter and SIGKILL",
            )
            result = dict(
                resource_fault=mode,
                target_pid=pid,
                exitcode=exitcode,
                oom_kill_before=before,
                oom_kill_after=after,
            )
        else:
            wait_for(
                "Agent real EMFILE",
                lambda: "too many open files" in owner.logpath.read_text().lower(),
                timeout=30,
            )
            result = dict(
                resource_fault=mode, target_pid=pid, rlimit_nofile=16, error="EMFILE"
            )
        name = "resource-fault-%d.json" % owner.number
        owner.evidence.register(name, "resource_fault", format="json")
        (owner.out / name).write_text(json.dumps(result, indent=2) + "\n")
        result["witness"] = name
        return result
    finally:
        try:
            owner.stop_agent(kill=True)
        finally:
            if scope_created:
                wait_for(
                    "OOM cgroup empty",
                    lambda: not (scope / "cgroup.procs").read_text().strip(),
                    timeout=10,
                )
                scope.rmdir()
            owner.agent_transition = False
