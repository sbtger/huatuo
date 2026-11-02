# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Worker lifecycle evidence and explicit metadata loss on terminated captures."""
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from ....core.documents import read_documents
from ....core.util import require, wait_for
from ....environments.linux import identity

WORKER = "huatuo-memsnapshot-worker"


def publish_worker(owner, plain):
    source = owner.build/(WORKER if plain else WORKER+"-fault")
    if not source.exists():
        require(not (owner.build/WORKER).exists(), "fault worker binary missing from new build")
        return None
    temporary = owner.out/(".worker-"+uuid.uuid4().hex)
    try:
        shutil.copy2(source, temporary)
        temporary.chmod(0o755)
        os.replace(temporary, owner.out/WORKER)
    finally:
        if temporary.exists():
            temporary.unlink()
    owner.evidence.register(WORKER, "worker_executable", format="binary")
    return dict(binary=source.name, sha256=hashlib.sha256(source.read_bytes()).hexdigest())


def worker_enabled(owner):
    return (owner.build/WORKER).exists()


def capture_metadata_errors(record, language):
    snapshot = record.get("snapshot") or {}
    terminated = snapshot.get("status") == "failed" and snapshot.get("status_reason", "").startswith("memory snapshot worker")
    errors = []
    if record.get("language") != language and not (terminated and record.get("language") == "unknown"):
        errors.append("runtime differs from selected process")
    memory = record.get("process_memory")
    if not memory and not terminated:
        errors.append("process RSS fallback missing")
    elif memory and memory.get("rss_bytes", 0) <= 0:
        errors.append("process RSS fallback invalid")
    return errors


def worker_log_entries(text, kind, target_pid=None):
    entries = []
    for line in text.splitlines():
        if 'msg="memory snapshot worker '+kind+'"' not in line:
            continue
        fields = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if target_pid is not None and fields.get("target_pid") != str(target_pid):
            continue
        if all(fields.get(k, "").isdigit() for k in ("worker_pid", "worker_start_ticks", "request_id")):
            entries.append(dict(pid=int(fields["worker_pid"]), start_ticks=int(fields["worker_start_ticks"]),
                                request_id=int(fields["request_id"]), line=line))
    return entries


def original_worker_gone(ident):
    try:
        return identity(ident[0]) != ident
    except (OSError, RuntimeError):
        return True


def failed_capture(owner, target):
    for index, document in enumerate(read_documents(owner.event_path)):
        data = document.get("tracer_data", {})
        records = data.get("process_snapshots", []) if owner.tracer_name == "memburst" else [dict(data, pid=data.get("victim_pid"))]
        for record in records:
            snapshot = record.get("snapshot") or {}
            if record.get("pid") == target["pid"] and snapshot.get("status") == "failed" and "memory snapshot worker deadline" in snapshot.get("status_reason", ""):
                return dict(status="failed", reason=snapshot["status_reason"], entries=len(snapshot.get("entries", [])),
                            event_file=str(owner.event_path), event_index=index, target_pid=target["pid"],
                            target_language=target["language"], agent_pid=owner.agent.pid)
    return None


def reaped_worker(owner, target):
    before = identity(owner.agent.pid)
    started = wait_for("worker process identity", lambda: next(iter(worker_log_entries(owner.logpath.read_text(), "started", target["pid"])), None), timeout=10)
    ident = [started["pid"], started["start_ticks"]]
    require(ident[1] > 0, "worker start-time identity missing")
    reaped = wait_for("blocked worker reaped", lambda: next((r for r in worker_log_entries(owner.logpath.read_text(), "reaped", target["pid"])
                        if (r["pid"], r["start_ticks"], r["request_id"]) == (started["pid"], started["start_ticks"], started["request_id"])), None), timeout=12)
    wait_for("blocked worker lifetime gone", lambda: original_worker_gone(ident), timeout=3)
    reaped_ns = time.monotonic_ns()
    fault_config = json.loads(owner.faultfile.read_text())
    witness_name = "worker-%d-%d-%d.json" % (owner.number, ident[0], started["request_id"])
    owner.evidence.register(witness_name, "worker_lifetime", format="json")
    (owner.out/witness_name).write_text(json.dumps(dict(worker_identity=ident, request_id=started["request_id"],
        fault_config=fault_config, gone=True, reaped_ns=reaped_ns, agent=before), indent=2)+"\n")
    require(identity(owner.agent.pid) == before, "worker failure replaced Agent")
    return dict(worker_isolation=True, worker_witness=witness_name, worker_identity=ident, worker_request_id=started["request_id"],
                worker_started_log=started["line"], worker_reaped_log=reaped["line"],
                worker_reaped_ns=reaped_ns, worker_gone=True,
                agent_before=before, agent_after=identity(owner.agent.pid))


def containment(owner, target):
    result = reaped_worker(owner, target)
    capture = wait_for("failed worker event persisted", lambda: failed_capture(owner, target), timeout=12)
    capture["not_before_epoch"] = json.loads(owner.faultfile.read_text())["requested_epoch"]
    owner.evidence.expect_document(str(owner.event_path.relative_to(owner.out)))
    result["failed_worker_capture"] = capture
    # Direct fault triggers bypass capture(), but still start the Agent cooldown.
    owner.last_capture = time.monotonic()
    return result


def worker_contract_errors(detail, logs=None):
    errors = []
    ident = detail.get("worker_identity", [])
    if len(ident) != 2 or min(ident, default=0) <= 0 or not detail.get("worker_gone"):
        errors.append("worker lifetime was not observed gone")
    if ident and ident[0] in (detail.get("agent_before", [None])[0], detail.get("fault_pid"), detail.get("target_pid")):
        errors.append("worker identity overlaps Agent or business")
    request = detail.get("worker_request_id")
    for kind in ("started", "reaped"):
        line = detail.get("worker_"+kind+"_log", "")
        records = worker_log_entries(line, kind, detail.get("fault_pid", detail.get("target_pid")))
        if not any([r["pid"], r["start_ticks"]] == ident and r["request_id"] == request for r in records):
            errors.append("worker identity/reap log mismatch")
        if logs is not None and (not line or line not in logs):
            errors.append("raw worker lifecycle log missing")
    capture = detail.get("failed_worker_capture", {})
    if not detail.get("target_exit_cancelled") and (capture.get("status") != "failed" or "memory snapshot worker" not in capture.get("reason", "")):
        errors.append("terminated worker has no explicit failed event")
    if detail.get("healthy_started_ns") is not None and not (
        0 < detail.get("read_active_ns", 0) <= detail.get("worker_reaped_ns", 0) <= detail["healthy_started_ns"]
    ):
        errors.append("healthy capture did not follow worker termination")
    return errors


def audit_worker_capture(output, detail, evidence):
    """Bind the claimed failed result to its raw file, Agent and pressure request."""
    from ..discovery import parse_timestamp
    import json
    errors = []
    try:
        capture = detail["failed_worker_capture"]
        original = Path(capture["event_file"])
        relative = str(Path(original.parent.name)/original.name)
        require(relative in evidence, "worker event missing from phase evidence")
        witness = worker_witness(output, detail, evidence)
        requested = witness["fault_config"]["requested_epoch"]
        require(requested == capture["not_before_epoch"] and requested > 0, "worker pressure request differs from witness")
        target = detail.get("fault_pid", detail.get("target_pid"))
        require(capture["target_pid"] == target == witness["fault_config"]["pid"], "worker failure target differs from request")
        require(capture["agent_pid"] == detail["agent_before"][0], "worker failure came from another Agent")
        log_name = "agent-"+original.parent.name[len("events-"):]+".log"
        require(log_name in evidence, "worker event belongs to another Agent log")
        metadata = json.loads((output/log_name.replace(".log", ".json")).read_text())
        require(metadata["pid"] == capture["agent_pid"], "worker event Agent metadata mismatch")
        documents = read_documents(output/relative)
        index = capture["event_index"]
        require(0 <= index < len(documents), "worker failed raw event index missing")
        document = documents[index]
        require(parse_timestamp(document["started_timestamp"]).timestamp() >= requested, "stale worker failure predates pressure request")
        data = document["tracer_data"]
        records = data.get("process_snapshots", []) if original.name == "memburst" else [dict(data, pid=data.get("victim_pid"))]
        record = next((r for r in records if r.get("pid") == target), None)
        require(record is not None, "worker failed raw target missing")
        snapshot = record["snapshot"]
        require(snapshot["status"] == capture["status"] == "failed" and snapshot.get("status_reason", "") == capture["reason"]
                and len(snapshot.get("entries", [])) == capture["entries"], "raw worker failed snapshot differs from claim")
    except Exception as exc:
        errors.append("worker failed-event audit: "+str(exc))
    return errors


def worker_witness(output, detail, evidence):
    name = detail["worker_witness"]
    require(name in evidence, "worker lifetime witness missing from phase evidence")
    path = output/name
    require(output.resolve() in path.resolve().parents, "worker witness outside evidence")
    witness = json.loads(path.read_text())
    require(witness["worker_identity"] == detail["worker_identity"]
            and witness["request_id"] == detail["worker_request_id"]
            and witness["gone"] is True and witness["reaped_ns"] == detail["worker_reaped_ns"]
            and witness["agent"] == detail["agent_before"], "worker lifetime witness differs from claim")
    require(witness["fault_config"]["pid"] == detail.get("fault_pid",detail.get("target_pid")), "worker witness target differs")
    return witness
