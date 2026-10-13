# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import os, signal, subprocess
from pathlib import Path
from ..core.util import Failure, require


def identity(pid):
    fields = Path("/proc/%d/stat" % pid).read_text().rsplit(") ", 1)[1].split()
    require(fields[0] not in ("Z", "X"), "business is dead or zombie")
    return [pid, int(fields[19])]


def cgroup_mount(mode):
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        fields = right.split()
        if mode == "2" and fields[0] == "cgroup2":
            return Path(left.split()[4])
        if mode == "1" and fields[0] == "cgroup" and "memory" in fields[2].split(","):
            return Path(left.split()[4])
    raise Failure(f"memory cgroup mount for mode {mode} is unavailable")


class ManagedProcess:
    def __init__(self):
        self.process = None
        self.stream = None

    def start(self, command, logfile, env):
        require(self.process is None, "process is already managed")
        self.stream = Path(logfile).open("w")
        try:
            self.process = subprocess.Popen(
                command,
                stdout=self.stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env=env,
            )
        except Exception:
            self.stream.close()
            self.stream = None
            raise
        return self.process

    def stop(self, kill=False):
        if self.process is None:
            return None
        process = self.process
        timed_out = False
        try:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL if kill else signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            returncode = process.returncode
        finally:
            self.stream.close()
            self.stream = None
            self.process = None
        require(kill or not timed_out, "managed process graceful shutdown timed out")
        return returncode
