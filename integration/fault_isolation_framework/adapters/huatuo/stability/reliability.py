# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Optional live reliability checks and their independently replayable contracts."""
import json
import re
import time
from pathlib import Path
from ....core.util import write_control, require, wait_for, run
from ....core.documents import read_documents
from ....environments.linux import identity
from ..discovery import PodFixture, parse_timestamp
from ..memsnapshot.worker import worker_enabled, containment, worker_contract_errors, audit_worker_capture, reaped_worker, worker_witness


def contract_errors(name, d):
    errors = []
    if name == "steady":
        if (
            d.get("rounds", 0) < d.get("minimum_rounds", 20)
            or d.get("elapsed_seconds", 0) < d.get("minimum_seconds", 1800)
            or len({tuple(i) for i in d.get("identities", [])}) != 1
            or d.get("agent_binary") != "agent"
            or len(d.get("round_results", [])) != d.get("rounds")
        ):
            errors.append(
                "steady observation lacks duration, rounds or same shipping Agent"
            )
        expected = set(d.get("languages", []))
        for index, row in enumerate(d.get("round_results", [])):
            if (
                not expected
                or row.get("round") != index + 1
                or row.get("agent") != d.get("identities", [None])[0]
                or len(row.get("captures", [])) != len(expected)
                or {c.get("target_language") for c in row.get("captures", [])}
                != expected
                or any(
                    c.get("agent_pid") != row["agent"][0]
                    for c in row.get("captures", [])
                )
            ):
                errors.append("steady round lacks same-Agent all-runtime captures")
    elif name == "cooldown":
        rows = d.get("observations", [])
        if (
            len(rows) < 3
            or d.get("observed_seconds", 0) < 3
            or (rows and (rows[0]["at"] > d.get("observation_started", d.get("cooldown_deadline", 0) - d.get("observed_seconds", 0)) + 1
                or rows[-1]["at"] < d.get("cooldown_deadline", 0) - 0.5))
            or any(b["at"] - a["at"] > 1 or b["at"] < a["at"] for a, b in zip(rows, rows[1:]))
            or any(
                r["events"] != d.get("initial_event_count")
                or r["at"] > d.get("cooldown_deadline", 0)
                for r in rows
            )
            or not d.get("post_expiry_capture", {}).get("normal_attempts")
        ):
            errors.append(
                "cooldown lacks complete negative observation or positive control"
            )
    elif name == "isolation":
        healthy = [d.get("healthy_capture", {})] + d.get("additional_healthy_captures", [])
        if (
            d.get("fault_pid") == d.get("healthy_pid")
            or not d.get("fault_active")
            or not d.get("marker")
            or len({c.get("target_pid") for c in healthy}) != len(healthy)
            or ("expected_healthy_pids" in d and {c.get("target_pid") for c in healthy} != set(d["expected_healthy_pids"]))
            or d.get("agent_before") != d.get("agent_after")
            or not d.get("healthy_capture", {}).get("normal_attempts")
            or 1 + len(d.get("additional_healthy_captures", [])) != d.get("required_healthy_targets", 1)
            or any(not c.get("normal_attempts") for c in d.get("additional_healthy_captures", []))
        ):
            errors.append(
                "cross-target isolation lacks reached fault and same-Agent healthy capture"
            )
        if d.get("worker_isolation"):
            errors += worker_contract_errors(d)
        elif d.get("mode") in ("delay", "block"):
            begin, end = d.get("read_active_ns", 0), d.get("read_end_ns", 0)
            first, last = d.get("healthy_started_ns", 0), d.get("healthy_finished_ns", 0)
            if not (0 < begin <= first <= last and (not end or end >= last)):
                errors.append("healthy capture did not complete during an active fault read")
    elif name == "target-exit":
        if (
            not d.get("target_gone")
            or ("err=no such process" not in d.get("read_result", "") and not (d.get("target_exit_cancelled") and d.get("worker_isolation") and "capture process memory: context canceled" in d.get("cancellation_log", "")))
            or d.get("agent_before") != d.get("agent_after")
            or not d.get("recovery", {}).get("normal_attempts")
        ):
            errors.append("target exit lacks actual ESRCH/canceled worker and same-Agent recovery")
        if d.get("target_exit_cancelled"):
            errors += worker_contract_errors(d)
    return errors


def selected_check_errors(command, cases):
    def argument(name, default):
        for index, token in enumerate(command):
            if token == name:
                return command[index + 1]
            if token.startswith(name + "="):
                return token.split("=", 1)[1]
        return default
    selected = set(argument("--checks", "").split(",")) - {""}
    errors = []
    for check in selected:
        matching = [c for c in cases if c["name"].endswith("/" + check)]
        if len(matching) != 1:
            errors.append("selected reliability check missing or duplicated: " + check)
            continue
        d = matching[0]["detail"]
        expected = "isolation" if check.startswith("isolation-") else check
        if d.get("check") != expected or (expected == "isolation" and d.get("mode") != check[len("isolation-"):]):
            errors.append("executed reliability check differs from selected mode")
        if check == "steady" and (
            d.get("minimum_rounds") != int(argument("--steady-rounds", "20"))
            or d.get("minimum_seconds") != float(argument("--steady-seconds", "1800"))):
            errors.append("steady quota differs from requested command line")
    return errors


def audit_check(output, case):
    d = case["detail"]
    errors = contract_errors(d.get("check"), d)
    logs = "\n".join(
        (output / n).read_text() for n in case["evidence"] if n.endswith(".log")
    )
    if d.get("check") in ("isolation", "target-exit"):
        if d.get("marker", "missing") not in logs:
            errors.append("raw fault marker missing for reliability check")
    if d.get("check") == "target-exit" and not d.get("target_exit_cancelled") and d.get("read_result", "missing") not in logs:
        errors.append("raw target-exit syscall result missing")
    if d.get("worker_isolation"):
        errors += worker_contract_errors(d, logs)
        if d.get("target_exit_cancelled"):
            try:
                worker_witness(output,d,case["evidence"])
                line=d.get("cancellation_log", "")
                require(line and line in logs and d["exit_window"]["cid"] in line, "raw cgroup cancellation missing")
            except Exception as exc:
                errors.append("worker cancellation witness: "+str(exc))
        else:
            errors += audit_worker_capture(output, d, case["evidence"])
    if d.get("check") == "isolation":
        environment = json.loads((output / "environment.json").read_text())
        expected = {t["pid"] for t in environment["targets"] if t["pid"] != d["fault_pid"]}
        witness = json.loads((output / d["witness"]).read_text())
        if (witness.get("fault_pid") != d["fault_pid"]
            or witness.get("healthy_started_ns") != d.get("healthy_started_ns")
            or witness.get("healthy_finished_ns") != d.get("healthy_finished_ns")
            or witness.get("fault_config_before", {}).get("pid") != d["fault_pid"]
            or witness.get("fault_config_after") != witness.get("fault_config_before")):
            errors.append("raw isolation attempt differs from active fault claim")
        if set(d.get("expected_healthy_pids", [])) != expected:
            errors.append("isolation omitted a selected healthy business target")
    if d.get("check") == "isolation" and d.get("mode") in ("delay", "block"):
        begin, end = read_window(logs, case["name"], d["fault_pid"])
        if (begin, end) != (d.get("read_active_ns"), d.get("read_end_ns")):
            errors.append("isolation raw read interval differs from claim")
    if d.get("check") == "target-exit":
        for name in case["evidence"]:
            if Path(name).name != d["module"]:
                continue
            for doc in read_documents(output / name):
                data = doc.get("tracer_data", {})
                records = data.get("process_snapshots", []) if d["module"] == "memburst" else [data]
                for record in records:
                    pid = record.get("pid", record.get("victim_pid"))
                    if pid == d["target_pid"] and record.get("snapshot", {}).get("status") not in (None, "failed"):
                        errors.append("dead target has a successful raw snapshot")
    if d.get("check") == "steady":
        raw = [
            json.loads(line)
            for line in (output / d["witness"]).read_text().splitlines()
        ]
        if raw != d["round_results"]:
            errors.append("raw steady rounds differ from summary")
        ident = d["identities"][0]
        metadata = [json.loads(p.read_text()) for p in output.glob("agent-*.json")]
        if not any(
            m.get("pid") == ident[0] and m.get("binary") == "agent" for m in metadata
        ):
            errors.append("steady shipping binary has no raw process witness")
    return errors


def steady(owner):
    owner.stop_agent()
    owner.clearfault()
    owner.start_agent(plain=True)
    started = time.monotonic()
    ident = identity(owner.agent.pid)
    rows, identities = [], [ident]
    path = owner.out / "steady-rounds.jsonl"
    owner.evidence.register(path.name, "steady_rounds", format="jsonl")
    with path.open("w") as stream:
        for index in range(owner.a.steady_rounds):
            captures = [owner.capture(t) for t in owner.targets]
            current = identity(owner.agent.pid)
            require(current == ident, "steady Agent identity changed")
            identities.append(current)
            row = dict(
                round=index + 1,
                agent=current,
                captures=captures,
                elapsed_seconds=time.monotonic() - started,
            )
            rows.append(row)
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            owner.trigger.release_all()
            until = (
                started + owner.a.steady_seconds * (index + 1) / owner.a.steady_rounds
            )
            while time.monotonic() < until:
                time.sleep(min(1, until - time.monotonic()))
            print(
                "[STEADY] round=%d/%d pid=%d elapsed=%.1fs"
                % (
                    index + 1,
                    owner.a.steady_rounds,
                    ident[0],
                    time.monotonic() - started,
                ),
                flush=True,
            )
    owner.monitor.record(settled=True)
    return dict(
        check="steady",
        rounds=len(rows),
        minimum_rounds=owner.a.steady_rounds,
        elapsed_seconds=time.monotonic() - started,
        minimum_seconds=owner.a.steady_seconds,
        identities=identities,
        languages=[t["language"] for t in owner.targets],
        agent_binary="agent",
        round_results=rows,
        witness=path.name,
    )


def cooldown_boundary(module, document, interval, wall_now, monotonic_now):
    # memburst starts cooldown at enqueue, before the asynchronous snapshot.
    field = "started_timestamp" if module == "memburst" else "uploaded_timestamp"
    return monotonic_now + parse_timestamp(document[field]).timestamp() + interval - wall_now - 0.2


def cooldown(owner, target):
    result = owner.capture(target)
    before = len(read_documents(owner.event_path))
    document = read_documents(owner.event_path)[result["event_index"]]
    deadline = cooldown_boundary(owner.tracer_name, document, owner.a.cooldown, time.time(), time.monotonic())
    owner.trigger.release_all()
    owner.trigger.pressure(target)
    started = time.monotonic()
    require(deadline - started >= 3, "cooldown pressure consumed observation window")
    rows = []
    while time.monotonic() < deadline:
        count = len(read_documents(owner.event_path))
        rows.append(dict(at=time.monotonic(), events=count))
        require(count == before, "cooldown persisted an extra event")
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    observed = time.monotonic() - started
    owner.trigger.release_all()
    recovered = owner.capture(target)
    return dict(
        check="cooldown",
        initial_capture=result,
        initial_event_count=before,
        observations=rows,
        observed_seconds=observed,
        observation_started=started,
        cooldown_deadline=deadline,
        post_expiry_capture=recovered,
    )


def read_window(logs, case, pid):
    def timestamp(kind):
        match = re.search(r"MEMSNAP_READ_%s id=%s pid=%d at=(\d+)" % (kind, re.escape(case), pid), logs)
        return int(match.group(1)) if match else 0
    return timestamp("ACTIVE"), timestamp("END")


def isolation(owner, target, mode):
    owner.trigger.release_all()
    owner.stop_agent()
    owner.setfault(target, mode)
    if mode == "delay":
        spec = json.loads(owner.faultfile.read_text())
        spec["delay_ms"] = 30000
        owner.faultfile.write_text(json.dumps(spec))
    owner.start_agent()
    before = identity(owner.agent.pid)
    owner.last_capture = 0.0
    owner.trigger.pressure(target)
    marker = "MEMSNAP_FAULT id=%s action=%s pid=%d stage=read" % (
        owner.case_name,
        mode,
        target["pid"],
    )
    wait_for(
        "isolation fault reached",
        lambda: marker in owner.logpath.read_text(),
        timeout=40,
    )
    # Respect intentional node cooldown before requesting another target. A
    # delayed/blocked read remains active beyond this wait; EFAULT tests scope.
    worker_detail = containment(owner, target) if worker_enabled(owner) and mode in ("delay", "block") else {}
    # Cooldown starts at completion for threshold, not at the first blocked read.
    time.sleep(owner.a.cooldown + 0.5)
    healthy_targets = [t for t in owner.targets if t["pid"] != target["pid"]]
    healthy = healthy_targets[0]
    witness_name = owner.case_name.replace("/", "_") + "-attempt.json"
    witness_path = owner.out / witness_name
    owner.evidence.register(witness_name, "fault_attempt", format="json")
    attempt = dict(fault_pid=target["pid"], mode=mode,
                   fault_config_before=json.loads(owner.faultfile.read_text()),
                   agent_before=before, expected_healthy_pids=[t["pid"] for t in healthy_targets])
    # This is a capture-isolation assertion, separate from business isolation.
    # Keep the fault installed while another target requests a real capture.
    try:
        healthy_started = time.monotonic_ns()
        attempt["healthy_started_ns"] = healthy_started
        witness_path.write_text(json.dumps(attempt, indent=2) + "\n")
        results = [owner.capture(t, not_before=time.time()) for t in healthy_targets]
        result = results[0]
        healthy_finished = time.monotonic_ns()
        attempt["healthy_finished_ns"] = healthy_finished
        read_begin, read_end = read_window(owner.logpath.read_text(), owner.case_name, target["pid"])
        active = json.loads(owner.faultfile.read_text())
        return dict(
            worker_detail,
            check="isolation",
            witness=witness_name,
            mode=mode,
            fault_pid=target["pid"],
            healthy_pid=healthy["pid"],
            agent_before=before,
            agent_after=identity(owner.agent.pid),
            marker=marker,
            fault_active=active.get("pid") == target["pid"]
            and active.get("action") == mode,
            healthy_capture=result,
            additional_healthy_captures=results[1:],
            required_healthy_targets=len(healthy_targets),
            expected_healthy_pids=[t["pid"] for t in healthy_targets],
            healthy_started_ns=healthy_started, healthy_finished_ns=healthy_finished,
            read_active_ns=read_begin, read_end_ns=read_end,
        )
    except Exception as exc:
        attempt["error"] = repr(exc)
        raise
    finally:
        attempt["attempt_finished_ns"] = time.monotonic_ns()
        attempt["read_active_ns"], attempt["read_end_ns"] = read_window(owner.logpath.read_text(), owner.case_name, target["pid"])
        attempt["fault_config_after"] = json.loads(owner.faultfile.read_text())
        witness_path.write_text(json.dumps(attempt, indent=2) + "\n")
        owner.clearfault()
        if mode == "block" and not worker_enabled(owner):
            owner.stop_agent(kill=True)


def target_exit(owner):
    owner.trigger.release_all()
    owner.stop_agent()
    ctl = owner.out / "exit-target"
    ctl.mkdir()
    write_control(ctl / "target_mb", "0")
    started = time.time()
    target = owner.environment.launch(
        [
            "--network",
            "host",
            "--memory",
            "768m",
            "--memory-swap",
            "768m",
            "-v",
            str(ctl) + ":/control:ro",
        ],
        ["/business-go"],
    )
    target.update(language="go", ctl=ctl)
    owner.discovery.register(target)
    owner.setfault(target, "pause")
    owner.start_agent()
    if owner.tracer_name == "memory_threshold_snapshot":
        wait_for(
            "exit target cgroup watched",
            lambda: owner.trigger.watch_ready(target),
            timeout=45,
        )
    ident = identity(owner.agent.pid)
    marker = "MEMSNAP_FAULT id=%s action=pause pid=%d stage=read" % (
        owner.case_name,
        target["pid"],
    )
    removed = False
    try:
        owner.trigger.pressure(target)
        wait_for(
            "target paused before read",
            lambda: marker in owner.logpath.read_text(),
            timeout=40,
        )
        PodFixture.containers.pop(target["cid"], None)
        run("docker", "rm", "-f", target["cid"])
        owner.environment.containers.remove(target["cid"])
        removed = True
        wait_for(
            "exit target process reaped",
            lambda: not Path("/proc/%d" % target["pid"]).exists(),
            timeout=10,
        )
        worker_detail = {}
        if worker_enabled(owner) and owner.tracer_name == "memory_threshold_snapshot":
            cancellation = wait_for("retired cgroup canceled collection", lambda: next((line for line in owner.logpath.read_text().splitlines()
                if target["cid"] in line and "capture process memory: context canceled" in line), None), timeout=10)
            worker_detail = reaped_worker(owner, target)
            worker_detail.update(target_exit_cancelled=True, cancellation_log=cancellation)
            line = "not attempted: collector canceled before paused syscall resumed"
            owner.clearfault()
        else:
            owner.clearfault()
            prefix = "MEMSNAP_READ_RESULT id=" + owner.case_name
            line = wait_for(
                "actual read after target exit",
                lambda: next(
                    (
                        line
                        for line in owner.logpath.read_text().splitlines()
                        if line.startswith(prefix)
                    ),
                    None,
                ),
                timeout=30,
            )
            require("err=no such process" in line, "target exit did not cause real ESRCH")
        # A failed non-persisted attempt may still consume the node cooldown.
        owner.last_capture = time.monotonic()
        recovered = owner.capture(owner.targets[0])
        return dict(
            worker_detail,
            check="target-exit",
            target_pid=target["pid"],
            target_gone=True,
            read_result=line,
            marker=marker,
            agent_before=ident,
            agent_after=identity(owner.agent.pid),
            recovery=recovered,
            exit_window=dict(
                cid=target["cid"],
                window_started=started,
                window_finished=time.time(),
                target_pid=target["pid"],
            ),
        )
    finally:
        owner.clearfault()
        if not removed:
            PodFixture.containers.pop(target["cid"], None)
            run("docker", "rm", "-f", target["cid"])
            owner.environment.containers.remove(target["cid"])
