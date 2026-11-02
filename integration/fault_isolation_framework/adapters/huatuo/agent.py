# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""HuaTuo daemon command construction; feature config belongs to the adapter."""
from pathlib import Path


def command(binary, config, output, bpf_dir, region="fault-isolation"):
    return [
        str(binary),
        "--config-dir",
        str(output),
        "--config",
        Path(config).name,
        "--region",
        region,
        "--bpf-dir",
        str(Path(bpf_dir).resolve()),
        "--tools-bin-dir",
        str(output),
        "--log-debug",
    ]


def verify_build(directory):
    import hashlib
    import json
    from ...core.util import require

    directory = Path(directory)
    manifest = json.loads((directory / "build.json").read_text())
    require(bool(manifest.get("sha256")), "build manifest has no binary hashes")
    for name, expected in manifest["sha256"].items():
        require(
            Path(name).name == name, "build manifest contains an invalid binary path"
        )
        require(
            hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected,
            "build hash mismatch: " + name,
        )
    return manifest
