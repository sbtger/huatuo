# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Own only the containers/image created by this run."""
import json, os, shutil, uuid
from pathlib import Path
from ..core.util import Failure, require, run, wait_for
from .linux import cgroup_mount, identity


class DockerEnvironment:
    def __init__(self, output):
        require(os.geteuid() == 0, "run on an isolated VM as root")
        require(
            run("docker", "info", "--format", "{{.CgroupVersion}}").stdout.strip()
            == "1",
            "this environment requires cgroup v1",
        )
        self.output = Path(output)
        self.mount = cgroup_mount("1")
        self.api = run(
            "docker", "version", "--format", "{{.Server.APIVersion}}"
        ).stdout.strip()
        self.driver = run(
            "docker", "info", "--format", "{{.CgroupDriver}}"
        ).stdout.strip()
        self.containers = []
        self.image = ""

    def build_image(self, binary):
        work = self.output / "image"
        work.mkdir()
        shutil.copy2(binary, work / "business-go")
        (work / "Dockerfile").write_text(
            "FROM scratch\nCOPY business-go /business-go\n"
        )
        self.image = "huatuo-fault-isolation:" + uuid.uuid4().hex[:12]
        run("docker", "build", "-q", "-t", self.image, str(work), timeout=120)

    def launch(self, args, command):
        cid = run(
            *(
                [
                    "docker",
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    "fault-isolation-" + uuid.uuid4().hex[:8],
                ]
                + args
                + [self.image]
                + command
            )
        ).stdout.strip()
        self.containers.append(cid)
        ready = wait_for(
            "business readiness",
            lambda: next(
                (
                    json.loads(line)
                    for line in run("docker", "logs", cid).stdout.splitlines()
                    if line.startswith("{")
                ),
                None,
            ),
            timeout=30,
        )
        pid = int(run("docker", "inspect", "-f", "{{.State.Pid}}", cid).stdout.strip())
        cgroup = next(
            line.split(":", 2)[2]
            for line in Path("/proc/%d/cgroup" % pid).read_text().splitlines()
            if "memory" in line.split(":")[1].split(",")
        )
        return dict(
            ready,
            cid=cid,
            pid=pid,
            cgroup=self.mount / cgroup.lstrip("/"),
            identity=identity(pid),
        )

    def cleanup(self, targets):
        errors = []
        for target in targets:
            try:
                logs = run("docker", "logs", target["cid"], check=False)
                (self.output / (target["language"] + "-business.log")).write_text(
                    logs.stdout + logs.stderr
                )
                if logs.returncode:
                    errors.append("business log collection failed: " + target["cid"])
            except Exception as exc:
                errors.append("business log collection failed: " + repr(exc))
        commands = [["docker", "rm", "-f", cid] for cid in self.containers]
        if self.image:
            commands.append(["docker", "rmi", self.image])
        for command in commands:
            try:
                result = run(*command, check=False)
                if result.returncode:
                    errors.append(
                        " ".join(command)
                        + ": exit=%d: " % result.returncode
                        + result.stderr[-800:]
                    )
            except Exception as exc:
                errors.append(" ".join(command) + ": " + repr(exc))
        if errors:
            raise Failure("resource cleanup failed: " + "; ".join(errors))
