# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Offline performance analysis; failed trials never become cheap successes."""
import math
import statistics


def percentile(values, p):
    # Require at least ten expected observations in the upper tail.
    minimum = 1 if p <= 50 else math.ceil(10 / (1 - p / 100))
    if len(values) < minimum:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(p / 100 * len(ordered)) - 1)]


def distribution(values):
    return dict(n=len(values), p50=percentile(values, 50),
                p95=percentile(values, 95), p99=percentile(values, 99),
                max=max(values) if values else None)


def summarize_requests(rows, scheduled, duration, max_lag=.1):
    success = [r for r in rows if r["ok"]]
    sent = [r for r in rows if r.get("sent") is not None]
    missing = max(0, scheduled - len(rows))
    errors = sum(not r["ok"] for r in rows)
    lag = [r.get("dispatch_lag", 0) for r in rows]
    return dict(scheduled=scheduled, recorded=len(rows), missing=missing,
                sent=len(sent), success=len(success), errors=errors,
                success_rps=len(success)/duration,
                valid_load=not missing and not any(r.get("load_invalid") for r in rows)
                           and max(lag, default=0) <= max_lag,
                latency_ms=distribution([(r["ended"]-r["scheduled"])*1000 for r in success]),
                send_delay_ms=distribution([(r["sent"]-r["scheduled"])*1000 for r in sent]),
                service_ms=distribution([(r["ended"]-r["sent"])*1000 for r in sent]),
                error_reasons=sorted(set(r.get("error", "") for r in rows if not r["ok"])))


def paired_comparisons(trials, enabled, baseline):
    pairs = []
    repeats = sorted(set(t["repeat"] for t in trials))
    for repeat in repeats:
        by_group = {t["group"]: t for t in trials if t["repeat"] == repeat}
        a, b = by_group.get(enabled), by_group.get(baseline)
        if not a or not b or not a["valid"] or not b["valid"]:
            continue
        delta = {}
        for key in a["metrics"].keys() & b["metrics"].keys():
            av, bv = a["metrics"][key], b["metrics"][key]
            if av is not None and bv is not None:
                delta[key] = dict(absolute=av-bv, percent=100*(av-bv)/bv if bv else None)
        pairs.append(dict(repeat=repeat, delta=delta))
    keys = set().union(*(p["delta"].keys() for p in pairs))
    summary = {}
    for key in sorted(keys):
        values = [p["delta"][key]["absolute"] for p in pairs if key in p["delta"]]
        summary[key] = dict(median=statistics.median(values), min=min(values), max=max(values), n=len(values))
    return dict(enabled=enabled, baseline=baseline, valid_pairs=len(pairs),
                excluded_repeats=len(repeats)-len(pairs), pairs=pairs, absolute_delta=summary)


def experiment_groups(experiment):
    if experiment == "idle":
        return ["A", "B", "C"]
    if experiment == "pulse":
        return ["A", "B", "D"]
    raise ValueError("unknown performance experiment")


def highest_tested_rate(rows, slo_p99_ms, max_error_rate):
    accepted = [r["qps"] for r in rows if r["valid"] and r["p99_ms"] is not None
                and r["p99_ms"] <= slo_p99_ms and r["error_rate"] <= max_error_rate]
    return max(accepted) if accepted else None


def strict_documents(path):
    """Only use after the writer stops; a truncated final event is invalid."""
    import json
    raw = path.read_text() if path.exists() else ""
    decoder, result, offset = json.JSONDecoder(), [], 0
    while offset < len(raw):
        if raw[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(raw, offset)
        if not isinstance(value, dict):
            raise ValueError("event must be an object")
        result.append(value)
    return result


def arrival_errors(rows,target_ids,qps,duration,start=None):
    """Check every planned arrival once; malformed timing cannot score as fast."""
    count=math.ceil(qps*duration);seen={key:[] for key in target_ids};errors=set()
    def finite(value):
        try:return isinstance(value,(int,float)) and not isinstance(value,bool) and math.isfinite(value)
        except OverflowError:return False
    for row in rows:
        key=row.get('target');ordinal=row.get('ordinal')
        if key not in seen:errors.add('unknown load target');continue
        if not isinstance(ordinal,int) or isinstance(ordinal,bool):errors.add('invalid arrival ordinal');continue
        seen[key].append(ordinal)
        if not isinstance(row.get('ok'),bool):errors.add('invalid response verdict')
        if not all(finite(row.get(k)) for k in ('scheduled','ended','dispatch_lag')):
            errors.add('nonfinite/missing request timing');continue
        if row['dispatch_lag'] < -1e-6 or row['ended'] < row['scheduled']-1e-6:errors.add('request timeline reversed')
        if row.get('sent') is not None and (not finite(row['sent']) or not row['scheduled']-1e-6 <= row['sent'] <= row['ended']):
            errors.add('invalid send/end ordering')
        if start is not None and abs(row['scheduled']-(start+ordinal/qps))>1e-4:errors.add('scheduled arrival differs from planned ordinal')
    for key,ordinals in seen.items():
        if sorted(ordinals)!=list(range(count)):errors.add('missing/duplicate/extra arrivals: '+key)
    return sorted(errors)
