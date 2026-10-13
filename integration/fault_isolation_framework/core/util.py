# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
import json, subprocess, time


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def run(*args, timeout=60, check=True, **kwargs):
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
        **kwargs,
    )
    if check and result.returncode:
        raise Failure(
            f"{' '.join(map(str, args))}: exit={result.returncode}: "
            f"{result.stderr[-1600:]}"
        )
    return result


def wait_for(description, predicate, timeout=30, period=0.25):
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            last_error = str(exc)
        time.sleep(period)
    raise Failure(f"timeout waiting for {description}; last error: {last_error}")
