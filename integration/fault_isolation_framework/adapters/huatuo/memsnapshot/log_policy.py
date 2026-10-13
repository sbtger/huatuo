# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Only explicitly witnessed faults permit expected Agent warning/error lines."""
import re


def unexpected_logs(text, storage_full=False, invalid_config=False):
    rejected = []
    panic_pids = set(
        re.findall(
            r"^MEMSNAP_FAULT id=\S+ action=panic pid=(\d+) stage=provider$", text, re.M
        )
    )
    for line in text.splitlines():
        if not re.search(
            r'level="?(?:warn|warning|error|panic|fatal)"?|^panic:|^fatal error:', line
        ):
            continue
        pid = re.search(r'\bpid="(\d+)"', line)
        if (
            'msg="runtime snapshot panicked"' in line
            and 'panic="test-only runtime snapshot panic"' in line
            and pid
            and pid.group(1) in panic_pids
        ):
            continue
        if (
            storage_full
            and "no space left on device" in line
            and "memory_threshold_snapshot" in line
        ):
            continue
        if invalid_config and "threshold percent must be in [1, 100], got 101" in line:
            continue
        rejected.append(line)
    return rejected
