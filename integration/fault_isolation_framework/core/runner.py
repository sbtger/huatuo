# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Execute feature scenarios while independent business probes remain active."""
import json
import time
import traceback
from .audit import audit
from .models import OperationResult
from .util import require


class Runner:
    def __init__(self, evidence):
        self.evidence = evidence
        self.results = []
        self.errors = []
        self.plan = []

    def summary(self, adapter, complete=False):
        totals = {p.target_id: p.totals() for p in adapter.probes}
        return dict(
            schema_version=2,
            adapter_id=adapter.adapter_id,
            adapter_policy_required=getattr(adapter, "requires_audit_policy", False),
            status="PASS"
            if complete
            and self.results
            and not self.errors
            and all(c["status"] == "PASS" for c in self.results)
            else "FAIL"
            if self.errors or any(c["status"] == "FAIL" for c in self.results)
            else "INCOMPLETE",
            cases=self.results,
            case_count=len(self.results),
            planned_cases=self.plan,
            total_business_requests={k: v["requests"] for k, v in totals.items()},
            total_business_transactions={
                k: v["transactions"] for k, v in totals.items()
            },
            errors=self.errors,
            performance_evaluated=False,
            all_exception_paths_proven=False,
        )

    def observe(self, scenario, adapter):
        print("[RUN] " + scenario.name, flush=True)
        begun = []
        observations = {}
        error = ""
        operation_failed = False
        result = OperationResult()
        started = time.monotonic()
        try:
            require(
                scenario.target_id in {p.target_id for p in adapter.probes},
                "scenario target has no business probe",
            )
            for probe in adapter.probes:
                begun.append((probe, probe.begin(scenario.name)))
            returned = scenario.operation()
            require(
                isinstance(returned, OperationResult),
                "scenario must return OperationResult",
            )
            result = returned
            if scenario.expect_fault:
                require(result.fault_hits > 0, "fault was not reached")
                require(bool(result.evidence), "fault witness has no raw evidence")
            for name in result.evidence:
                require(
                    name in self.evidence.artifacts,
                    "unregistered scenario evidence: " + name,
                )
        except Exception as exc:
            operation_failed = True
            error = repr(exc)
            traceback.print_exc()
        time.sleep(max(0, scenario.minimum_seconds - (time.monotonic() - started)))
        for probe, (before, at) in begun:
            try:
                observations[probe.target_id] = probe.finish(
                    scenario.name,
                    before,
                    at,
                    result.fault_hits,
                    scenario.expect_fault and probe.target_id == scenario.target_id,
                )
            except Exception as exc:
                observations[probe.target_id] = {"assertion_errors": [str(exc)]}
        failures = [
            e
            for observation in observations.values()
            for e in observation["assertion_errors"]
        ]
        require(
            len(observations) == len(adapter.probes),
            "business observation is incomplete",
        )
        phase = dict(
            name=scenario.name,
            target_id=scenario.target_id,
            expect_fault=scenario.expect_fault,
            status="FAIL" if operation_failed or failures else "PASS",
            detail=result.detail,
            error=error,
            business=observations,
            fault_hits=result.fault_hits,
            evidence=result.evidence,
        )
        self.results.append(phase)
        self.evidence.save(self.summary(adapter))
        print(
            "["
            + phase["status"]
            + "] "
            + scenario.name
            + " "
            + error
            + " "
            + str(failures),
            flush=True,
        )
        require(phase["status"] == "PASS", "case failed: " + scenario.name)

    def execute(self, adapter):
        complete = False
        try:
            adapter.prepare()
            self.plan = adapter.plan()
            require(
                self.plan and len(set(self.plan)) == len(self.plan),
                "scenario plan must be nonempty and unique",
            )
            require(
                adapter.probes
                and len({p.target_id for p in adapter.probes}) == len(adapter.probes),
                "business probes must be nonempty and unique",
            )
            for scenario in adapter.scenarios():
                index = len(self.results)
                require(
                    index < len(self.plan) and scenario.name == self.plan[index],
                    "scenario order differs from declared plan",
                )
                self.observe(scenario, adapter)
            require(
                len(self.results) == len(self.plan),
                "not all planned scenarios executed",
            )
            complete = True
        except Exception as exc:
            self.errors.append(str(exc))
            traceback.print_exc()
        finally:
            try:
                try:
                    adapter.quiesce()
                except Exception as exc:
                    self.errors.append(str(exc))
                for probe in adapter.probes:
                    try:
                        probe.close()
                    except Exception as exc:
                        self.errors.append(str(exc))
                try:
                    adapter.verify_final()
                except Exception as exc:
                    self.errors.append(str(exc))
                for probe in adapter.probes:
                    try:
                        if any(r["ok"] is not True for r in probe.records()):
                            self.errors.append(
                                "business errors occurred between phases: "
                                + probe.target_id
                            )
                    except Exception as exc:
                        self.errors.append(
                            "final business records failed: " + repr(exc)
                        )
            finally:
                try:
                    adapter.cleanup()
                except Exception as exc:
                    self.errors.append("cleanup failed: " + repr(exc))
        summary = self.summary(adapter, complete)
        self.evidence.save(summary)
        result = audit(self.evidence.output, adapter.audit_artifacts)
        if result["status"] != "PASS":
            summary["status"] = "FAIL"
            summary["errors"].append("evidence/log audit failed; inspect audit.json")
            self.evidence.save(summary)
        return summary
