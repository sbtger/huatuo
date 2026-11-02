# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Bounded campaign gates and checkpoint evidence; no environment dependencies."""
import json
from pathlib import Path

from .evidence import EvidenceStore


def coverage_errors(cycles, minimum_seconds, rows, elapsed):
    errors = []
    if [r.get("cycle") for r in rows] != list(range(1, cycles + 1)):
        errors.append("cycle coverage is incomplete or duplicated")
    if any(r.get("status") != "PASS" for r in rows):
        errors.append("one or more cycles failed")
    if elapsed < minimum_seconds:
        errors.append("minimum observation duration not reached")
    return errors


def resource_errors(rows, rss_growth, fd_growth, rss_limit, fd_limit):
    errors = []
    groups = {}
    if not rows:
        return ["resource observation is empty"]
    times = [r["time"] for r in rows if "time" in r]
    if any(b < a or b - a > 10 for a, b in zip(times, times[1:])):
        errors.append("resource sample timeline has a gap or reversal")
    for row in rows:
        if row.get("error"):
            errors.append("resource observer: " + row["error"])
        if not row.get("agent"):
            continue
        groups.setdefault(tuple(row["agent"]), []).append(row)
        if row["rss_bytes"] > rss_limit or row["fds"] > fd_limit:
            errors.append("Agent exceeded absolute resource budget")
    if not groups:
        errors.append("no live Agent resource observation")
    for agent, samples in groups.items():
        if any("baseline" in row for row in samples) and not any(
            row.get("baseline") for row in samples
        ):
            continue
        # Compare settled checkpoints, not peak snapshots against cold startup.
        settled = [s for s in samples if s.get("settled", True)]
        if len(settled) < 2:
            if any(s.get("baseline") for s in samples):
                errors.append("warmed Agent has no growth endpoint: " + str(agent))
            continue
        if settled[-1]["rss_bytes"] - settled[0]["rss_bytes"] > rss_growth:
            errors.append("Agent RSS grew beyond budget: " + str(agent))
        if settled[-1]["fds"] - settled[0]["fds"] > fd_growth:
            errors.append("Agent FD count grew beyond budget: " + str(agent))
    return sorted(set(errors))


class CheckpointEvidence(EvidenceStore):
    def save(self, summary):
        if summary["status"] != "INCOMPLETE":
            return super().save(summary)
        # Hash the final streams once, rather than re-reading hours of traffic
        # after every phase. Partial checkpoints never claim audit success.
        temporary = self.output / "summary.tmp"
        temporary.write_text(json.dumps(summary, indent=2) + "\n")
        temporary.replace(self.output / "summary.json")
