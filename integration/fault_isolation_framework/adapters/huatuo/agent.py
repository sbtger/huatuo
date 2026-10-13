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
