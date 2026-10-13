# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Launch the example services using generic Docker resource ownership."""
from pathlib import Path
from ..core.util import require, run
from .http_probe import EXPECTED, request_http


def launch_services(environment, output, languages, java_home, python):
    output = Path(output)
    targets = []
    workloads = Path(__file__).parent / "services"
    run(
        java_home + "/bin/javac",
        "-d",
        str(output / "java"),
        str(workloads / "SnapshotBusiness.java"),
    )
    for language in languages:
        ctl = output / (language + "-control")
        ctl.mkdir()
        (ctl / "target_mb").write_text("0")
        args = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--network",
            "host",
            "--memory",
            "768m",
            "--memory-swap",
            "768m",
            "-v",
            str(ctl) + ":/control:ro",
            "-v",
            str(workloads) + ":/fixture:ro",
            "-v",
            str(output / "java") + ":/classes:ro",
        ]
        if language != "go":
            for root in ("/usr", "/lib", "/lib64"):
                args += ["-v", root + ":" + root + ":ro"]
        if language == "java":
            config = (
                Path(java_home + "/conf/security/java.security").resolve().parent.parent
            )
            args += ["-v", str(config) + ":" + str(config) + ":ro"]
        cmd = {
            "go": ["/business-go"],
            "java": [
                java_home + "/bin/java",
                "-Xms64m",
                "-Xmx128m",
                "-XX:+UseG1GC",
                "-XX:MaxDirectMemorySize=600m",
                "-cp",
                "/classes",
                "SnapshotBusiness",
            ],
            "python": [python, "/fixture/python_service.py"],
        }[language]
        t = environment.launch(args[4:], cmd)
        t.update(language=language, ctl=ctl)
        targets.append(t)
        require(
            request_http(t["url"], "/work") == EXPECTED,
            language + " fixture work contract failed before Agent start",
        )
    return targets
