# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fault_isolation_framework.core.util import Failure, require, run, wait_for
from fault_isolation_framework.core.documents import read_documents
from fault_isolation_framework.environments.linux import cgroup_mount
from fault_isolation_framework.adapters.huatuo.discovery import (
    PodFixture,
    parse_timestamp,
)


def path_matches_container(path, container_id):
    return Path(path).name in (container_id, f"docker-{container_id}.scope")
