# Copyright 2026 The HuaTuo Authors. Licensed under the Apache License, Version 2.0.
"""Feature-neutral contracts. The adapters own trigger and result semantics."""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Protocol, Iterable


@dataclass
class OperationResult:
    detail: Dict = field(default_factory=dict)
    fault_hits: int = 0
    evidence: List[str] = field(default_factory=list)


@dataclass
class Scenario:
    name: str
    target_id: str
    operation: Callable[[], OperationResult]
    expect_fault: bool = False
    minimum_seconds: float = 3.0


class BusinessProbe(Protocol):
    target_id: str

    def begin(self, name: str):
        ...

    def finish(self, name, before, started, hits, expected) -> Dict:
        ...

    def close(self) -> None:
        ...

    def totals(self) -> Dict:
        ...

    def records(self) -> List[Dict]:
        ...


class FeatureAdapter(Protocol):
    adapter_id: str
    probes: List[BusinessProbe]

    def prepare(self) -> None:
        ...

    def plan(self) -> List[str]:
        ...

    def scenarios(self) -> Iterable[Scenario]:
        ...

    def quiesce(self) -> None:
        ...

    def verify_final(self) -> None:
        ...

    def audit_artifacts(self, output, summary, manifest) -> Dict:
        ...

    def cleanup(self) -> None:
        ...
